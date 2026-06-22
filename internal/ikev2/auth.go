package ikev2

// IKE_AUTH handler — EAP-AKA per RFC 7296 §2.16 and 3GPP TS 24.302 §8.2.3.
//
// Exchange sequence (ePDG as responder, UE as initiator):
//   Round 1  UE→ePDG: IDi, IDr, [CP], SA, TSi, TSr  (no AUTH, no EAP)
//            ePDG→UE: IDr, [CERT], EAP-Challenge
//   Round N  UE→ePDG: EAP-Response  (one or more times)
//            ePDG→UE: EAP-Request or EAP-Success
//   Final    UE→ePDG: AUTH
//            ePDG→UE: AUTH, SAr2, TSi, TSr, [CP-reply]

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/pco"
	"vectorcore-epdg/internal/pgwdiscovery"
	"vectorcore-epdg/internal/s2b"
	"vectorcore-epdg/internal/session"
	"vectorcore-epdg/internal/swm"
	"vectorcore-epdg/internal/xfrm"

	"github.com/free5gc/ike/message"
)

const (
	// X.509 Certificate – Signature (RFC 7296 §3.6).
	certEncodingX509 uint8 = 4
	// AUTH method: Shared Key Message Integrity Code (MSK-based, RFC 7296 §3.8).
	authMethodSharedKey uint8 = 2
	// "Key Pad for IKEv2" literal per RFC 7296 §2.15.
	ikeV2KeyPad = "Key Pad for IKEv2"

	authTimeout = 10 * time.Second

	// notifyIKEv2MultipleBearerPDNConnectivity (TS 24.302 §8.1.2.3/§8.2.9.9):
	// a private status Notify a UE includes in its IKE_AUTH request to
	// indicate it supports per-bearer CHILD_SA negotiation for dedicated EPS
	// bearers (TS 24.302 §7.2.7/§7.4.6). Both UE and ePDG support for this
	// are explicitly optional ("may support") — this ePDG does not
	// implement the mechanism (see docs/audit-report.md finding #5) and
	// falls back to the spec-defined single-CHILD_SA behavior regardless.
	// Detected and logged only, to inform whether implementing the full
	// mechanism is worth the effort for this deployment's UE fleet.
	notifyIKEv2MultipleBearerPDNConnectivity uint16 = 42011
)

// rawPayload implements message.IKEPayload for pre-encoded payload bytes.
// Used to relay raw EAP packets (free5gc/ike does not support EAP-AKA type 23).
type rawPayload struct {
	typ  message.IkePayloadType
	data []byte
}

func (p *rawPayload) Type() message.IkePayloadType { return p.typ }
func (p *rawPayload) Marshal() ([]byte, error)     { return p.data, nil }
func (p *rawPayload) Unmarshal(b []byte) error     { p.data = append(p.data[:0], b...); return nil }

// authPayloads holds inner payloads parsed from an IKE_AUTH request.
type authPayloads struct {
	idi      *message.IdentificationInitiator
	idr      *message.IdentificationResponder
	auth     *message.Authentication
	sa       *message.SecurityAssociation
	tsi      *message.TrafficSelectorInitiator
	tsr      *message.TrafficSelectorResponder
	cp       *message.Configuration
	eapRaw   []byte // raw EAP packet bytes (nil if no EAP payload)
	notifies []*message.Notification
}

// ────────────────────────────────────────────────────────────────────────────
// Top-level dispatcher
// ────────────────────────────────────────────────────────────────────────────

func (s *Server) handleIKEAuth(conn *net.UDPConn, remote *net.UDPAddr, pkt []byte, hdr *message.IKEHeader, natt bool) {
	if hdr.Flags&message.InitiatorBitCheck == 0 || hdr.Flags&message.ResponseBitCheck != 0 {
		s.log.Debug("IKE_AUTH: bad flags", "flags", hdr.Flags, "remote", remote)
		return
	}

	sa := s.lookupSA(hdr.InitiatorSPI)
	if sa == nil {
		s.log.Warn("IKE_AUTH: unknown SPI", "spi_i", hdr.InitiatorSPI, "remote", remote)
		return
	}

	sa.mu.Lock()
	defer sa.mu.Unlock()

	if sa.state != ikeStateAuth {
		s.log.Warn("IKE_AUTH: SA not in auth state", "state", sa.state, "remote", remote)
		return
	}
	sa.remoteAddr = remote
	sa.lastSeen = time.Now()

	innerType, plain, err := decryptSK(sa.saKey, pkt)
	if err != nil {
		s.log.Warn("IKE_AUTH: decrypt failed", "err", err, "remote", remote)
		return
	}

	payloads, err := parseAuthPayloads(innerType, plain)
	if err != nil {
		s.log.Warn("IKE_AUTH: parse failed", "err", err, "remote", remote)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
		return
	}

	// MOBIKE (RFC 4555 §2.1): detect USE_MOBIKE in any IKE_AUTH round.
	if !sa.mobikeEnabled {
		for _, n := range payloads.notifies {
			if n.NotifyMessageType == message.MOBIKE_SUPPORTED {
				sa.mobikeEnabled = true
				break
			}
		}
	}

	switch {
	case sa.eapRound == 0:
		s.handleAuthRound1(conn, remote, sa, hdr, payloads, natt)
	case payloads.auth != nil:
		s.handleAuthFinal(conn, remote, sa, hdr, payloads, natt)
	default:
		s.handleAuthEAP(conn, remote, sa, hdr, payloads, natt)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Round 1: IDi, IDr, SA, TS, CP  →  IDr, [CERT], EAP-challenge
// ────────────────────────────────────────────────────────────────────────────

func (s *Server) handleAuthRound1(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, hdr *message.IKEHeader, pl *authPayloads, natt bool) {
	if pl.idi == nil {
		s.log.Warn("IKE_AUTH round1: missing IDi", "remote", remote)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
		return
	}

	// Extract NAI/IMSI from IDi.
	nai, imsi, err := extractNAI(pl.idi)
	if err != nil {
		s.log.Warn("IKE_AUTH round1: IDi parse failed", "err", err, "remote", remote)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	}

	// Extract APN from IDr (UE tells us which APN it wants).
	requestedAPN := ""
	if pl.idr != nil {
		requestedAPN = extractAPN(pl.idr)
	}
	apn := requestedAPN
	if apn == "" {
		if s.fullCfg != nil {
			apn = s.fullCfg.APN.Default
		}
		if apn == "" {
			apn = "ims"
		}
	}
	if requestedAPN != "" {
		s.log.Info("IKE_AUTH round1: UE requested APN", "imsi", imsi, "apn", requestedAPN, "remote", remote)
	} else {
		s.log.Info("IKE_AUTH round1: UE did not request an APN, using default", "imsi", imsi, "default_apn", apn, "remote", remote)
	}

	// Observe (do not act on) IKEv2 multiple bearer PDN connectivity support.
	// Both sides are optional per TS 24.302 §7.2.7.1/§7.4.6.1; this ePDG does
	// not implement the per-bearer CHILD_SA mechanism (finding #5), so this
	// is purely informational — it does not change how the request is
	// handled, and not finding it is not a spec violation.
	for _, n := range pl.notifies {
		if n.NotifyMessageType == notifyIKEv2MultipleBearerPDNConnectivity {
			s.log.Info("IKE_AUTH round1: UE supports IKEv2 multiple bearer PDN connectivity (not implemented by this ePDG)",
				"imsi", imsi, "remote", remote)
			break
		}
	}

	// Save IDi bytes for AUTH computation: [IDType | 0 | 0 | 0 | IDData].
	sa.idiAuthBytes = buildIDAuthBytes(pl.idi.IDType, pl.idi.IDData)
	sa.imsi = imsi
	sa.nai = nai
	sa.apn = apn

	// Save CHILD SA negotiation state from first IKE_AUTH.
	if pl.sa != nil {
		prop, propNum, peerSPI, err2 := selectAndExtractESP(pl.sa)
		if err2 != nil {
			s.log.Warn("IKE_AUTH round1: no acceptable ESP proposal", "err", err2, "remote", remote)
			s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.NO_PROPOSAL_CHOSEN, natt)
			return
		}
		sa.espProp = prop
		sa.espPropNum = propNum
		sa.peerESPSPI = peerSPI
	}

	// Check whether UE requested an IP address via CFG_REQUEST.
	// A non-zero INTERNAL_IP4_ADDRESS value signals VoLTE→VoWiFi handover:
	// the UE is asking the PGW to preserve its existing PDN connection.
	if pl.cp != nil && pl.cp.ConfigurationType == message.CFG_REQUEST {
		for _, attr := range pl.cp.ConfigurationAttribute {
			if attr.Type == message.INTERNAL_IP4_ADDRESS {
				sa.cpWantsIP = true
				if len(attr.Value) == 4 {
					if ip := net.IP(attr.Value).To4(); ip != nil && !ip.Equal(net.IPv4zero) {
						sa.handoverIP = ip
					}
				}
			}
		}
	}
	if sa.handoverIP != nil {
		s.log.Info("IKE_AUTH round1: VoLTE→VoWiFi handover detected",
			"imsi", imsi, "requested_paa", sa.handoverIP)
	}

	// Create or retrieve session in the session manager.
	if s.sessions != nil {
		sessID := fmt.Sprintf("%016x-%016x", sa.spiI, sa.spiR)
		sess := s.sessions.GetOrCreate(sessID)
		sess.Lock()
		sess.IMSI = imsi
		sess.NAI = nai
		sess.APN = apn
		sess.IkeSPII = sa.spiI
		sess.IkeSPIR = sa.spiR
		_ = sess.Transition(session.StateEAPAuthenticating)
		sess.Unlock()
		sa.sessionID = sessID
	}

	// Build initial EAP payload: EAP-Response/Identity with the UE's NAI.
	// If the UE already included an EAP payload in round 1, use its identifier;
	// otherwise synthesize an EAP-Identity-Response from the NAI.
	var eapToSend []byte
	var eapIdentifier byte
	if len(pl.eapRaw) >= 2 {
		eapIdentifier = pl.eapRaw[1]
		eapToSend = pl.eapRaw
	} else {
		idResp, err2 := swm.IdentityResponse(0, nai)
		if err2 != nil {
			s.log.Error("IKE_AUTH round1: build EAP identity failed", "err", err2)
			s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
			return
		}
		eapIdentifier = 0
		eapToSend = idResp
	}
	_ = eapIdentifier // identifier is inside the EAP packet bytes

	// Forward to SWm.
	if s.swm == nil {
		s.log.Error("IKE_AUTH round1: SWm client not configured")
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()

	result, err := s.swm.ExchangeEAP(ctx, swm.EAPRequest{
		IMSI:       imsi,
		NAI:        nai,
		APN:        apn,
		EAPPayload: eapToSend,
	})
	if err != nil {
		s.log.Error("IKE_AUTH round1: SWm error", "err", err, "imsi", imsi, "remote", remote)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	}

	sa.swmSessionID = result.SessionID
	sa.eapRound = 1
	if s.sessions != nil {
		if sess := s.sessions.Get(sa.sessionID); sess != nil {
			sess.Lock()
			sess.SWMSessionID = result.SessionID
			sess.Unlock()
		}
	}

	s.log.Info("IKE_AUTH round1: SWm response",
		"imsi", imsi, "nai", nai, "apn", apn,
		"eap_state", result.State, "remote", remote)

	switch result.State {
	case swm.EAPStateFailure:
		s.log.Warn("IKE_AUTH round1: SWm EAP failure", "reason", result.Reason, "imsi", imsi)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	case swm.EAPStateSuccess:
		sa.msk = result.MSK
		// TS 23.003 §19.3.4/19.3.5: when the UE authenticated with a pseudonym
		// or fast re-authentication identity, sa.imsi was never known locally —
		// the AAA-resolved Permanent User Identity is now the only IMSI we have.
		if result.PermanentIdentity != "" {
			sa.imsi = result.PermanentIdentity
		}
		if s.sessions != nil {
			if sess := s.sessions.Get(sa.sessionID); sess != nil {
				sess.Lock()
				sess.MSK = result.MSK
				if result.PermanentIdentity != "" {
					sess.IMSI = result.PermanentIdentity
				}
				_ = sess.Transition(session.StateEAPAuthenticated)
				sess.Unlock()
			}
		}
	}

	// Build response: IDr, [CERT], EAP.
	s.sendEAPResponse(conn, remote, sa, hdr.MessageID, result.EAPPayload, true, natt)
	// Cache so we can retransmit if the UE doesn't receive our challenge (RFC 7296 §2.1).
	sa.eapChallengeMsgID = hdr.MessageID
	sa.eapChallengePayload = result.EAPPayload
}

// ────────────────────────────────────────────────────────────────────────────
// EAP continuation rounds
// ────────────────────────────────────────────────────────────────────────────

func (s *Server) handleAuthEAP(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, hdr *message.IKEHeader, pl *authPayloads, natt bool) {
	if len(pl.eapRaw) == 0 {
		// UE is retransmitting its round1 IKE_AUTH (our EAP challenge was lost).
		// RFC 7296 §2.1: retransmit the cached response.
		if hdr.MessageID == sa.eapChallengeMsgID && sa.eapChallengePayload != nil {
			s.log.Debug("IKE_AUTH EAP: retransmitting EAP challenge", "imsi", sa.imsi, "msg_id", hdr.MessageID, "remote", remote)
			s.sendEAPResponse(conn, remote, sa, hdr.MessageID, sa.eapChallengePayload, true, natt)
		} else {
			s.log.Warn("IKE_AUTH EAP round: no EAP payload",
				"round", sa.eapRound,
				"msg_id", hdr.MessageID,
				"cached_msg_id", sa.eapChallengeMsgID,
				"cached_payload_len", len(sa.eapChallengePayload),
				"remote", remote)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
	defer cancel()

	result, err := s.swm.ExchangeEAP(ctx, swm.EAPRequest{
		SessionID:  sa.swmSessionID,
		IMSI:       sa.imsi,
		NAI:        sa.nai,
		APN:        sa.apn,
		EAPPayload: pl.eapRaw,
	})
	if err != nil {
		s.log.Error("IKE_AUTH EAP: SWm error", "err", err, "round", sa.eapRound, "imsi", sa.imsi)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	}

	sa.eapRound++
	sa.eapChallengePayload = nil // EAP response received; cached challenge no longer needed
	s.log.Info("IKE_AUTH EAP: round complete",
		"round", sa.eapRound, "eap_state", result.State,
		"msk_present", len(result.MSK) == 64, "imsi", sa.imsi, "remote", remote)

	switch result.State {
	case swm.EAPStateFailure:
		s.log.Warn("IKE_AUTH EAP: authentication failed", "reason", result.Reason, "imsi", sa.imsi)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	case swm.EAPStateSuccess:
		sa.msk = result.MSK
		// TS 23.003 §19.3.4/19.3.5: when the UE authenticated with a pseudonym
		// or fast re-authentication identity, sa.imsi was never known locally —
		// the AAA-resolved Permanent User Identity is now the only IMSI we have.
		if result.PermanentIdentity != "" {
			sa.imsi = result.PermanentIdentity
		}
		if s.sessions != nil {
			sess := s.sessions.Get(sa.sessionID)
			if sess != nil {
				sess.Lock()
				sess.MSK = result.MSK
				if result.PermanentIdentity != "" {
					sess.IMSI = result.PermanentIdentity
				}
				if result.APNProfile != nil && result.APNProfile.AMBRPresent {
					sess.APNProfile = &session.APNProfile{
						APN:          result.APNProfile.APN,
						AMBRUplink:   uint64(result.APNProfile.AMBRUplink),
						AMBRDownlink: uint64(result.APNProfile.AMBRDownlink),
					}
				}
				_ = sess.Transition(session.StateEAPAuthenticated)
				sess.Unlock()
			}
		}
	}

	// Send the EAP payload (challenge or success) to the UE.
	s.sendEAPResponse(conn, remote, sa, hdr.MessageID, result.EAPPayload, false, natt)
}

// ────────────────────────────────────────────────────────────────────────────
// Final round: AUTH payload verification + CHILD SA response
// ────────────────────────────────────────────────────────────────────────────

func (s *Server) handleAuthFinal(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, hdr *message.IKEHeader, pl *authPayloads, natt bool) {
	if len(sa.msk) != 64 {
		s.log.Warn("IKE_AUTH final: MSK not available", "imsi", sa.imsi, "remote", remote)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	}
	if pl.auth == nil {
		s.log.Warn("IKE_AUTH final: missing AUTH payload", "remote", remote)
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	}

	// Verify the UE's AUTH payload.
	// <InitiatorSignedOctets> = initReqRaw | nonceR | prf(SK_pi, IDi_bytes)
	macedIDI := prfMAC(sa.saKey.prf, sa.saKey.SK_pi, sa.idiAuthBytes)
	initiatorSigned := concat(sa.initReqRaw, sa.nonceR, macedIDI)
	expectedAuth := computeEAPAUTH(sa.saKey.prf, sa.msk, initiatorSigned)

	if !constEqual(expectedAuth, pl.auth.AuthenticationData) {
		s.log.Warn("IKE_AUTH final: AUTH verification failed",
			"imsi", sa.imsi, "remote", remote,
			"expected_len", len(expectedAuth), "got_len", len(pl.auth.AuthenticationData))
		s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
		return
	}

	s.log.Info("IKE_AUTH final: UE AUTH verified", "imsi", sa.imsi, "remote", remote)

	// TS 23.402 §8.2.2: a re-attach without a handover indication is an implicit
	// detach of any existing active session for this IMSI+APN.  We wait until after
	// AUTH verification so we never tear down a valid session on an unverified claim.
	if sa.handoverIP == nil && s.sessions != nil {
		if oldSess, ok := s.sessions.FindSingleActiveByIMSIAPN(sa.imsi, sa.apn); ok {
			oldSess.RLock()
			oldSpiI := oldSess.IkeSPII
			oldSess.RUnlock()
			if oldIKESA := s.lookupSA(oldSpiI); oldIKESA != nil {
				oldIKESA.mu.Lock()
				oldIKESA.state = ikeStateDeleting
				s.fullTeardown(oldIKESA, "implicit_detach")
				oldIKESA.mu.Unlock()
				s.log.Info("IKE_AUTH final: implicitly detached existing session",
					"imsi", sa.imsi, "old_session_id", oldSess.ID)
			}
		}
	}

	// S2b CreateSession to obtain the UE's PAA.
	var paa net.IP
	var s2bResult *s2b.CreateSessionResult
	if s.s2b != nil {
		var ambrUL, ambrDL uint64
		if s.sessions != nil {
			if sess := s.sessions.Get(sa.sessionID); sess != nil {
				sess.RLock()
				if sess.APNProfile != nil {
					ambrUL = sess.APNProfile.AMBRUplink
					ambrDL = sess.APNProfile.AMBRDownlink
				}
				sess.RUnlock()
			}
		}

		// Resolve PGW-C address per 3GPP TS 29.303 (DNS) or static config.
		var pgwControlIP net.IP
		if s.fullCfg != nil {
			dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 3*time.Second)
			pgwControlIP = pgwdiscovery.Discover(dnsCtx, s.log, pgwdiscovery.Config{
				DNSEnabled:        s.fullCfg.PGWDiscovery.DNSEnabled,
				AllowS5S8Fallback: s.fullCfg.PGWDiscovery.AllowS5S8Fallback,
				StaticPGWC:        s.fullCfg.GTP.PGWGTPC,
				MCC:               s.fullCfg.EPDG.MCC,
				MNC:               s.fullCfg.EPDG.MNC,
			}, sa.apn)
			dnsCancel()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r, err := s.s2b.CreateSession(ctx, s2b.CreateSessionRequest{
			IMSI:         sa.imsi,
			APN:          sa.apn,
			AMBRUplink:   ambrUL,
			AMBRDownlink: ambrDL,
			Handover:     sa.handoverIP != nil,
			PGWControlIP: pgwControlIP,
		})
		cancel()
		if err != nil {
			s.log.Error("IKE_AUTH final: S2b CreateSession failed",
				"err", err, "imsi", sa.imsi, "apn", sa.apn)
			s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
			return
		}
		s2bResult = r
		paa = r.PAA
		s.log.Info("IKE_AUTH final: S2b session created",
			"imsi", sa.imsi, "paa", paa,
			"pgw_ctrl_teid", r.PGWControlTEID, "pgw_user_teid", r.PGWUserTEID,
			"handover", sa.handoverIP != nil)
		if sa.handoverIP != nil && !paa.Equal(sa.handoverIP) {
			s.log.Warn("IKE_AUTH final: handover PAA mismatch — PGW assigned different address",
				"imsi", sa.imsi, "requested", sa.handoverIP, "assigned", paa)
		}

		// Update session state.
		if s.sessions != nil {
			sess := s.sessions.Get(sa.sessionID)
			if sess != nil {
				sess.Lock()
				_ = sess.Transition(session.StateS2BCreateSessionSent)
				sess.S2B = &session.S2BContext{
					PAA:              paa.String(),
					PGWControlTEID:   r.PGWControlTEID,
					PGWControlIP:     r.PGWControlIP,
					PGWUserTEID:      r.PGWUserTEID,
					PGWUserIP:        r.PGWUserIP,
					LocalControlTEID: r.LocalControlTEID,
					LocalUserTEID:    r.LocalUserTEID,
					EBI:              r.EBI,
					PGWRecovery:      r.PGWRecovery,
				}
				_ = sess.Transition(session.StateS2BAccepted)
				sess.Unlock()
			}
		}
	}

	// Generate ePDG's inbound ESP SPI.
	var spiBytes [4]byte
	if _, err := rand.Read(spiBytes[:]); err != nil {
		s.log.Error("IKE_AUTH final: SPI gen failed", "err", err)
		return
	}
	sa.localESPSPI = binary.BigEndian.Uint32(spiBytes[:])
	sa.state = ikeStateEstablished

	// Install CHILD SA in kernel XFRM — happens here so the SA is ready before
	// we tell the UE the IKE_AUTH completed.
	if sa.espProp != nil && sa.localIP != nil {
		encrIn, integIn, encrOut, integOut := deriveChildSAKeys(sa.saKey, sa.nonceI, sa.nonceR,
			sa.espProp.encr.KeyLen(), sa.espProp.integKeyLen())
		encrName, integName, integTrunc := childAlgNames(sa.espProp)

		var remoteTS *net.IPNet
		if paa4 := paa.To4(); paa4 != nil {
			remoteTS = &net.IPNet{IP: paa4, Mask: net.CIDRMask(32, 32)}
		} else {
			remoteTS = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		}
		_, localTS, _ := net.ParseCIDR("0.0.0.0/0")

		xfrmParams := xfrm.ChildSAParams{
			LocalIP:      sa.localIP,
			RemoteIP:     remote.IP,
			InboundSPI:   sa.localESPSPI,
			OutboundSPI:  sa.peerESPSPI,
			EncKeyIn:     encrIn,
			IntKeyIn:     integIn,
			EncKeyOut:    encrOut,
			IntKeyOut:    integOut,
			EncAlgName:   encrName,
			IntAlgName:   integName,
			IntTruncBits: integTrunc,
			NATT:         sa.natT,
			NATTSrcPort:  nattPort,
			NATTDstPort:  remote.Port,
			LocalTS:      localTS,
			RemoteTS:     remoteTS,
			IfID:         xfrm.IfID,
		}
		if err := xfrm.InstallChildSA(xfrmParams); err != nil {
			s.log.Error("IKE_AUTH final: XFRM install failed",
				"err", err, "imsi", sa.imsi, "remote", remote)
			s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
			return
		}
		s.log.Info("IKE_AUTH final: XFRM installed",
			"inbound_spi", fmt.Sprintf("%08x", sa.localESPSPI),
			"outbound_spi", fmt.Sprintf("%08x", sa.peerESPSPI),
			"encr", encrName, "encr_bits", sa.espProp.encr.keyBits,
			"integ", integName, "pfs", sa.espProp.dhID(),
			"paa", paa, "natt", sa.natT)

		if s.sessions != nil {
			if sess := s.sessions.Get(sa.sessionID); sess != nil {
				sess.Lock()
				sess.ESPInboundSPI = sa.localESPSPI
				sess.ESPOutboundSPI = sa.peerESPSPI
				sess.OuterIP = sa.remoteAddr.String()
				_ = sess.Transition(session.StateGTPUInstalling)
				sess.Unlock()
			}
		}

		// GTP-U bearer installation.
		if s.gtpuMgr != nil && s.sessions != nil {
			if sess := s.sessions.Get(sa.sessionID); sess != nil {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
				// AddSession takes sess and locks internally for its own field
				// accesses (including writing sess.Datapath) — do not hold
				// sess.Lock() across this call.
				if err := s.gtpuMgr.AddSession(ctx2, sess); err != nil {
					cancel2()
					s.log.Error("IKE_AUTH final: GTP-U AddSession failed",
						"err", err, "imsi", sa.imsi, "paa", paa)
					s.sendAuthNotify(conn, remote, sa, hdr.MessageID, message.AUTHENTICATION_FAILED, natt)
					return
				}
				cancel2()
				sess.Lock()
				_ = sess.Transition(session.StateDatapathInstalling)
				_ = sess.Transition(session.StateActive)
				ebi := uint8(0)
				if sess.S2B != nil {
					ebi = sess.S2B.EBI
				}
				sess.Unlock()
				s.log.Info("IKE_AUTH final: GTP-U session installed, session Active",
					"imsi", sa.imsi, "paa", paa, "ebi", ebi)
			}
		}
	}

	// Build our IDr payload bytes for AUTH computation.
	epdgID := s.epdgIdentity()
	idrBytes := buildIDAuthBytes(message.ID_FQDN, []byte(epdgID))

	// Compute ePDG's AUTH payload.
	// <ResponderSignedOctets> = initRespRaw | nonceI | prf(SK_pr, IDr_bytes)
	macedIDR := prfMAC(sa.saKey.prf, sa.saKey.SK_pr, idrBytes)
	responderSigned := concat(sa.initRespRaw, sa.nonceI, macedIDR)
	ourAUTH := computeEAPAUTH(sa.saKey.prf, sa.msk, responderSigned)

	// Build response: IDr, AUTH, SAr2, TSi, TSr, [CP-reply].
	var inner message.IKEPayloadContainer

	// TS 24.302 §7.4.1.1: the ePDG shall include the APN (default or
	// UE-provided — sa.apn already resolved either way) in the "IDr"
	// payload of the final IKE_AUTH response, ID Type ID_FQDN. This is
	// separate from the round-1 IDr (the ePDG's own identity, used for the
	// signature AUTH computation above) — RFC 7296's responder identity for
	// AUTH purposes was already committed to in round 1 and is unaffected
	// by this payload.
	inner.BuildIdentificationResponder(message.ID_FQDN, []byte(sa.apn))

	inner.BuildAuthentication(authMethodSharedKey, ourAUTH)

	if sa.espProp != nil {
		buildESPSAResponse(&inner, sa.espProp, sa.espPropNum, sa.localESPSPI)
	}

	buildTSResponse(&inner, paa)

	if sa.cpWantsIP && paa != nil {
		cp := inner.BuildConfiguration(message.CFG_REPLY)
		cp.ConfigurationAttribute.BuildConfigurationAttribute(
			message.INTERNAL_IP4_ADDRESS, paa.To4())
		if s2bResult != nil {
			// PGW returns DNS and P-CSCF in APCO for IMS APNs; fall back to PCO.
			pcoData := s2bResult.ResponseAPCO
			if pcoData == nil {
				pcoData = s2bResult.ResponsePCO
			}
			if s.fullCfg != nil {
				appendDNSFromPCO(cp, pcoData, s.fullCfg.PCO)
				appendPCSCFFromPCO(cp, pcoData, s.fullCfg.PCO)
			}
		}
	}

	// Echo MOBIKE_SUPPORTED if the UE negotiated it (RFC 4555 §2.1).
	if sa.mobikeEnabled {
		inner.BuildNotification(message.TypeNone, message.MOBIKE_SUPPORTED, nil, nil)
	}

	if err := s.sendEncryptedResponse(conn, remote, sa, message.IKE_AUTH, hdr.MessageID, inner, natt); err != nil {
		s.log.Error("IKE_AUTH final: send failed", "err", err, "remote", remote)
		return
	}

	s.log.Info("IKE_AUTH complete",
		"imsi", sa.imsi, "apn", sa.apn, "paa", paa,
		"esp_spi_local", fmt.Sprintf("%08x", sa.localESPSPI),
		"esp_spi_peer", fmt.Sprintf("%08x", sa.peerESPSPI),
		"remote", remote)
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers: sending responses
// ────────────────────────────────────────────────────────────────────────────

// sendEAPResponse sends IDr, [CERT], AUTH, and the given EAP payload.
// includeID is true for the first response (round 1); false for subsequent EAP rounds.
//
// TS 33.402 §8.2.2 step 6 requires the ePDG to send its identity, a certificate,
// and the AUTH parameter (protecting the IKE_SA_INIT exchange with a public-key
// signature) together with the first EAP challenge — before EAP, and therefore
// the EAP MSK, exist. The MSK-based AUTH built in handleAuthFinal is a separate,
// later value that authenticates the exchange to the UE after EAP succeeds.
func (s *Server) sendEAPResponse(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, msgID uint32, eapPayload []byte, includeID bool, natt bool) {
	var inner message.IKEPayloadContainer

	if includeID {
		epdgID := s.epdgIdentity()
		inner.BuildIdentificationResponder(message.ID_FQDN, []byte(epdgID))
		if len(s.certDER) > 0 {
			inner.BuildCertificate(certEncodingX509, s.certDER)
		}

		idrBytes := buildIDAuthBytes(message.ID_FQDN, []byte(epdgID))
		macedIDR := prfMAC(sa.saKey.prf, sa.saKey.SK_pr, idrBytes)
		responderSigned := concat(sa.initRespRaw, sa.nonceI, macedIDR)
		sig, err := s.computeCertAUTH(responderSigned)
		if err != nil {
			s.log.Error("IKE_AUTH: signature AUTH failed", "err", err, "remote", remote)
			s.sendAuthNotify(conn, remote, sa, msgID, message.AUTHENTICATION_FAILED, natt)
			return
		}
		inner.BuildAuthentication(message.RSADigitalSignature, sig)
	}

	inner = append(inner, &rawPayload{typ: message.TypeEAP, data: eapPayload})

	if err := s.sendEncryptedResponse(conn, remote, sa, message.IKE_AUTH, msgID, inner, natt); err != nil {
		s.log.Error("IKE_AUTH: send EAP response failed", "err", err, "remote", remote)
	}
}

// computeCertAUTH signs the responder-signed octets (RFC 7296 §2.15) with the
// ePDG's certificate private key, using AUTH Method 1 "RSA Digital Signature"
// (RFC 7296 §3.8): PKCS#1 v1.5 padding over a SHA-1 digest. This legacy method
// (rather than the RFC 7427 generic signature method) is chosen for broad UE
// interoperability, matching the base RFC 7296 profile TS 33.402 references.
func (s *Server) computeCertAUTH(signedOctets []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("no ePDG private key configured")
	}
	digest := sha1.Sum(signedOctets)
	return rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA1, digest[:])
}

// sendAuthNotify sends an AUTHENTICATION_FAILED (or other) notify in an encrypted IKE_AUTH response.
func (s *Server) sendAuthNotify(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, msgID uint32, notifyType uint16, natt bool) {
	var inner message.IKEPayloadContainer
	inner.BuildNotification(message.TypeNone, notifyType, nil, nil)
	if err := s.sendEncryptedResponse(conn, remote, sa, message.IKE_AUTH, msgID, inner, natt); err != nil {
		s.log.Debug("IKE_AUTH: send notify failed", "err", err, "notify", notifyType)
	}
}

// sendEncryptedResponse encrypts inner payloads and sends the IKE response.
func (s *Server) sendEncryptedResponse(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, exchType uint8, msgID uint32, payloads message.IKEPayloadContainer, natt bool) error {
	var plain []byte
	var firstType uint8

	if len(payloads) > 0 {
		encoded, err := payloads.Encode()
		if err != nil {
			return fmt.Errorf("encode inner: %w", err)
		}
		plain = encoded
		firstType = uint8(payloads[0].Type())
	}

	return s.sendEncryptedRaw(conn, remote, sa, exchType, msgID, firstType, plain, natt)
}

// sendEncryptedRaw encrypts raw inner bytes (may be nil for DPD empty response) and sends the IKE message.
func (s *Server) sendEncryptedRaw(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, exchType uint8, msgID uint32, innerNextPayload uint8, plain []byte, natt bool) error {
	// Compute total message length to fill in the IKE header.
	totalLen, err := encryptedSKMessageLen(sa.saKey, len(plain))
	if err != nil {
		return fmt.Errorf("compute message length: %w", err)
	}

	hdrBytes := buildIKEHeaderBytes(sa.spiI, sa.spiR, exchType, msgID, totalLen)

	out, err := encryptSK(sa.saKey, innerNextPayload, plain, hdrBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	s.send(conn, remote, out, natt)
	return nil
}

// buildIKEHeaderBytes constructs the 28-byte IKE header for an encrypted response.
func buildIKEHeaderBytes(spiI, spiR uint64, exchType uint8, msgID uint32, totalLen int) []byte {
	hdr := make([]byte, message.IKE_HEADER_LEN)
	binary.BigEndian.PutUint64(hdr[0:], spiI)
	binary.BigEndian.PutUint64(hdr[8:], spiR)
	hdr[16] = uint8(message.TypeSK) // NextPayload = SK
	hdr[17] = (2 << 4) | 0          // MajorVersion=2, MinorVersion=0
	hdr[18] = exchType
	hdr[19] = message.ResponseBitCheck // Response flag, no Initiator flag
	binary.BigEndian.PutUint32(hdr[20:], msgID)
	binary.BigEndian.PutUint32(hdr[24:], uint32(totalLen))
	return hdr
}

// buildIKERequestHeaderBytes constructs the 28-byte IKE header for an ePDG-initiated
// request (e.g. DPD probe). The ePDG is the IKE responder, so neither the Initiator
// nor the Response flag is set (flags = 0x00).
func buildIKERequestHeaderBytes(spiI, spiR uint64, exchType uint8, msgID uint32, totalLen int) []byte {
	hdr := make([]byte, message.IKE_HEADER_LEN)
	binary.BigEndian.PutUint64(hdr[0:], spiI)
	binary.BigEndian.PutUint64(hdr[8:], spiR)
	hdr[16] = uint8(message.TypeSK) // NextPayload = SK
	hdr[17] = (2 << 4) | 0          // MajorVersion=2, MinorVersion=0
	hdr[18] = exchType
	hdr[19] = 0x00 // no Response, no Initiator — ePDG is IKE responder sending a request
	binary.BigEndian.PutUint32(hdr[20:], msgID)
	binary.BigEndian.PutUint32(hdr[24:], uint32(totalLen))
	return hdr
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers: payload parsing
// ────────────────────────────────────────────────────────────────────────────

// parseAuthPayloads manually walks the inner payload chain from a decrypted IKE_AUTH.
// It does not use free5gc's IKEPayloadContainer.Decode because that parser rejects
// EAP-AKA type 23 ("EAP type[23] is not supported").
func parseAuthPayloads(firstType uint8, plain []byte) (*authPayloads, error) {
	result := &authPayloads{}
	curType := firstType
	off := 0

	for curType != 0 && off < len(plain) {
		if off+4 > len(plain) {
			return nil, fmt.Errorf("truncated payload at offset %d", off)
		}
		nextType := plain[off]
		payloadLen := int(binary.BigEndian.Uint16(plain[off+2 : off+4]))
		if payloadLen < 4 || off+payloadLen > len(plain) {
			return nil, fmt.Errorf("invalid payload length %d at offset %d", payloadLen, off)
		}
		body := plain[off+4 : off+payloadLen]

		switch message.IkePayloadType(curType) {
		case message.TypeIDi:
			pl := &message.IdentificationInitiator{}
			if err := safePayloadUnmarshal("IDi", func() error { return pl.Unmarshal(body) }); err != nil {
				return nil, fmt.Errorf("IDi: %w", err)
			}
			result.idi = pl
		case message.TypeIDr:
			pl := &message.IdentificationResponder{}
			if err := safePayloadUnmarshal("IDr", func() error { return pl.Unmarshal(body) }); err != nil {
				return nil, fmt.Errorf("IDr: %w", err)
			}
			result.idr = pl
		case message.TypeAUTH:
			pl := &message.Authentication{}
			if err := safePayloadUnmarshal("AUTH", func() error { return pl.Unmarshal(body) }); err != nil {
				return nil, fmt.Errorf("AUTH: %w", err)
			}
			result.auth = pl
		case message.TypeSA:
			pl := &message.SecurityAssociation{}
			if err := safePayloadUnmarshal("SA", func() error { return pl.Unmarshal(body) }); err != nil {
				return nil, fmt.Errorf("SA: %w", err)
			}
			result.sa = pl
		case message.TypeTSi:
			pl := &message.TrafficSelectorInitiator{}
			if err := safePayloadUnmarshal("TSi", func() error { return pl.Unmarshal(body) }); err != nil {
				return nil, fmt.Errorf("TSi: %w", err)
			}
			result.tsi = pl
		case message.TypeTSr:
			pl := &message.TrafficSelectorResponder{}
			if err := safePayloadUnmarshal("TSr", func() error { return pl.Unmarshal(body) }); err != nil {
				return nil, fmt.Errorf("TSr: %w", err)
			}
			result.tsr = pl
		case message.TypeCP:
			pl := &message.Configuration{}
			if err := safePayloadUnmarshal("CP", func() error { return pl.Unmarshal(body) }); err != nil {
				return nil, fmt.Errorf("CP: %w", err)
			}
			result.cp = pl
		case message.TypeEAP:
			// Store raw EAP bytes to pass directly to SWm without re-parsing.
			result.eapRaw = make([]byte, len(body))
			copy(result.eapRaw, body)
		case message.TypeN:
			// Notification payload bodies contain Protocol ID (1 byte),
			// SPI Size (1 byte), and Notify Message Type (2 bytes) before
			// any SPI or notification data. free5gc/ike v1.2.1 slices these
			// fields without checking the minimum body length.
			if len(body) < 4 {
				return nil, fmt.Errorf("notification payload too short: %d", len(body))
			}
			if spiSize := int(body[1]); spiSize > len(body)-4 {
				return nil, fmt.Errorf("notification SPI size %d exceeds body length %d", spiSize, len(body))
			}
			pl := &message.Notification{}
			if err := safePayloadUnmarshal("notification", func() error { return pl.Unmarshal(body) }); err != nil {
				return nil, fmt.Errorf("notification: %w", err)
			}
			result.notifies = append(result.notifies, pl)
		}

		off += payloadLen
		curType = nextType
	}
	return result, nil
}

// safePayloadUnmarshal prevents malformed peer input from turning bounds-check
// defects in the third-party IKE payload decoder into a process-wide panic.
func safePayloadUnmarshal(name string, unmarshal func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%s payload decoder panic: %v", name, recovered)
		}
	}()
	return unmarshal()
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers: identity and APN extraction
// ────────────────────────────────────────────────────────────────────────────

// extractNAI parses the IDi payload into the NAI the AAA server will route
// and resolve on, and opportunistically a local IMSI when the identity is
// syntactically a permanent root NAI.
//
// TS 33.402 §8.2.2 step 2 / §8.2.3 step 2 explicitly allow IDi to carry an
// IMSI, an EAP-AKA pseudonym, or a fast re-authentication identity — the ePDG
// must accept all of them and forward the NAI to AAA as opaque
// routing/authentication data (TS 23.003 §19.3). A pseudonym or fast
// re-authentication identity's "digits" are an AAA-assigned opaque value,
// not an IMSI (TS 23.003 §19.3.4/19.3.5 examples show this directly: the
// pseudonym/fast-reauth value differs from the real IMSI) — they must never
// be parsed as one. Only the AAA server can resolve those to a real IMSI
// (returned in the DEA's Permanent User Identity; see swm.EAPResult.PermanentIdentity).
//
// Errors are returned only for a genuinely unusable identity (empty or an
// unsupported IDi type) — never merely because the identity isn't a
// permanent root NAI, since rejecting it there is exactly the bug this
// fixes (audit finding #6).
func extractNAI(idi *message.IdentificationInitiator) (nai, imsi string, err error) {
	if len(idi.IDData) == 0 {
		return "", "", fmt.Errorf("empty IDi data")
	}
	raw := string(idi.IDData)

	// Handle FQDN and RFC822 (email-format) identity types.
	switch idi.IDType {
	case message.ID_FQDN, message.ID_RFC822_ADDR, message.ID_KEY_ID:
		// All treated as NAI text.
	default:
		return "", "", fmt.Errorf("unsupported IDi type %d", idi.IDType)
	}

	nai = raw
	imsi = permanentIMSIFromNAI(raw)
	return nai, imsi, nil
}

// permanentIMSIFromNAI returns the IMSI when local (the NAI's username part)
// is a TS 23.003 §19.3.2 permanent root NAI — prefix "0" (EAP-AKA) or "6"
// (EAP-AKA'), followed by a 6-15 digit IMSI — and "" otherwise (pseudonym,
// fast re-authentication, decorated, or any other identity form: TS 23.003
// §19.3.4/19.3.5 use prefixes "2"/"7" and "4"/"8" for those, with opaque
// AAA-assigned digits that must not be mistaken for an IMSI).
func permanentIMSIFromNAI(raw string) string {
	local := raw
	if idx := strings.IndexByte(raw, '@'); idx >= 0 {
		local = raw[:idx]
	}
	if len(local) == 0 || (local[0] != '0' && local[0] != '6') {
		return ""
	}
	digits := local[1:]
	if len(digits) < 6 || len(digits) > 15 {
		return ""
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return digits
}

// extractAPN returns the first label of the IDr FQDN as the APN label.
// IDr FQDN example: "ims.epdg.epc.mnc435.mcc311.3gppnetwork.org" → "ims"
func extractAPN(idr *message.IdentificationResponder) string {
	if len(idr.IDData) == 0 {
		return ""
	}
	fqdn := string(idr.IDData)
	if idx := strings.IndexByte(fqdn, '.'); idx > 0 {
		return fqdn[:idx]
	}
	return fqdn
}

// epdgIdentity returns the ePDG's FQDN identity for IDr and AUTH computation.
func (s *Server) epdgIdentity() string {
	if s.fullCfg != nil && s.fullCfg.EPDG.Name != "" {
		return s.fullCfg.EPDG.Name
	}
	return "epdg"
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers: AUTH computation (RFC 7296 §2.15)
// ────────────────────────────────────────────────────────────────────────────

// computeEAPAUTH computes the MSK-based AUTH value per RFC 7296 §2.15:
//
//	auth_key = prf(MSK, "Key Pad for IKEv2")
//	AUTH     = prf(auth_key, signedOctets)
func computeEAPAUTH(prf *prfAlg, msk, signedOctets []byte) []byte {
	authKey := prfMAC(prf, msk, []byte(ikeV2KeyPad))
	return prfMAC(prf, authKey, signedOctets)
}

// prfMAC computes prf(key, data) and returns the full output.
func prfMAC(prf *prfAlg, key, data []byte) []byte {
	h := prf.New(key)
	h.Write(data)
	return h.Sum(nil)
}

// buildIDAuthBytes returns [IDType | 0x00 | 0x00 | 0x00 | IDData] for AUTH computation.
func buildIDAuthBytes(idType uint8, idData []byte) []byte {
	b := make([]byte, 4+len(idData))
	b[0] = idType
	// b[1..3] = 0 (reserved)
	copy(b[4:], idData)
	return b
}

// concat joins byte slices without allocation reuse.
func concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// constEqual compares two byte slices in constant time.
func constEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers: CHILD SA payload construction
// ────────────────────────────────────────────────────────────────────────────

// selectAndExtractESP selects an ESP proposal from SAi2 and returns the UE's SPI.
func selectAndExtractESP(sa *message.SecurityAssociation) (*childProposal, uint8, uint32, error) {
	prop, propNum, err := selectESPProposal(sa)
	if err != nil {
		return nil, 0, 0, err
	}
	for _, p := range sa.Proposals {
		if p.ProposalNumber == propNum && len(p.SPI) == 4 {
			return prop, propNum, binary.BigEndian.Uint32(p.SPI), nil
		}
	}
	return prop, propNum, 0, nil
}

// buildESPSAResponse adds the SAr2 payload with the negotiated ESP transforms.
func buildESPSAResponse(container *message.IKEPayloadContainer, prop *childProposal, propNum uint8, localSPI uint32) {
	spiBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(spiBytes, localSPI)

	sa := container.BuildSecurityAssociation()
	p := sa.Proposals.BuildProposal(propNum, message.TypeESP, spiBytes)

	keyBits := uint16(prop.encr.keyBits)
	attrType := uint16(message.AttributeTypeKeyLength)
	p.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, prop.encr.id, &attrType, &keyBits, nil)
	if prop.integ != nil {
		p.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, prop.integ.id, nil, nil, nil)
	}
	if prop.dh != nil {
		p.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, prop.dh.TransformID(), nil, nil, nil)
	}
	p.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_DISABLE, nil, nil, nil)
}

// buildTSResponse adds TSi and TSr payloads.
// TSi is narrowed to paa/32 when available; otherwise 0.0.0.0/0.
// TSr is always 0.0.0.0/0 (ePDG accepts all inbound).
func buildTSResponse(container *message.IKEPayloadContainer, paa net.IP) {
	var tsStart, tsEnd []byte
	if paa4 := paa.To4(); paa4 != nil {
		tsStart = []byte(paa4)
		tsEnd = []byte(paa4)
	} else {
		tsStart = []byte{0, 0, 0, 0}
		tsEnd = []byte{255, 255, 255, 255}
	}

	tsi := container.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(
		message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535, tsStart, tsEnd)

	tsr := container.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(
		message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535,
		[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers: certificate loading
// ────────────────────────────────────────────────────────────────────────────

// pemToDER decodes the first PEM block from pemBytes and returns DER bytes.
func pemToDER(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return block.Bytes, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers: PCO / DNS / P-CSCF extraction
// ────────────────────────────────────────────────────────────────────────────

// IKEv2 CFG attribute types for P-CSCF addresses (RFC 7651; not defined in free5gc/ike).
const (
	internalIP4PCSCF = uint16(20) // P_CSCF_IP4_ADDRESS (RFC 7651 §3)
	internalIP6PCSCF = uint16(21) // P_CSCF_IP6_ADDRESS (RFC 7651 §3)
)

func appendDNSFromPCO(cp *message.Configuration, decoded *pco.Decoded, cfg config.PCOConfig) {
	if decoded == nil {
		return
	}
	if cfg.RequestDNSv4 {
		for _, ip := range decoded.DNSv4 {
			if ip4 := ip.To4(); ip4 != nil {
				cp.ConfigurationAttribute.BuildConfigurationAttribute(message.INTERNAL_IP4_DNS, ip4)
			}
		}
	}
	if cfg.RequestDNSv6 {
		for _, ip := range decoded.DNSv6 {
			if ip16 := ip.To16(); ip16 != nil {
				cp.ConfigurationAttribute.BuildConfigurationAttribute(message.INTERNAL_IP6_DNS, ip16)
			}
		}
	}
}

func appendPCSCFFromPCO(cp *message.Configuration, decoded *pco.Decoded, cfg config.PCOConfig) {
	if decoded == nil {
		return
	}
	if cfg.RequestPCSCFv4 {
		for _, ip := range decoded.PCSCFv4 {
			if ip4 := ip.To4(); ip4 != nil {
				cp.ConfigurationAttribute.BuildConfigurationAttribute(internalIP4PCSCF, ip4)
			}
		}
	}
	if cfg.RequestPCSCFv6 {
		for _, ip := range decoded.PCSCFv6 {
			if ip16 := ip.To16(); ip16 != nil {
				cp.ConfigurationAttribute.BuildConfigurationAttribute(internalIP6PCSCF, ip16)
			}
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers: CHILD SA key derivation (RFC 7296 §2.17)
// ────────────────────────────────────────────────────────────────────────────

// deriveChildSAKeys derives CHILD SA keying material from SK_d per RFC 7296 §2.17.
// KEYMAT = prf+(SK_d, Ni | Nr)
// Returns SK_ei, SK_ai, SK_er, SK_ar in that order.
func deriveChildSAKeys(saKey *ikeSAKey, nonceI, nonceR []byte, encrKeyLen, integKeyLen int) (encrIn, integIn, encrOut, integOut []byte) {
	seed := append(nonceI, nonceR...)
	h := saKey.prf.New(saKey.SK_d)
	keymat := prfPlus(h, seed, 2*(encrKeyLen+integKeyLen))
	off := 0
	take := func(n int) []byte {
		b := make([]byte, n)
		copy(b, keymat[off:off+n])
		off += n
		return b
	}
	return take(encrKeyLen), take(integKeyLen), take(encrKeyLen), take(integKeyLen)
}

// childAlgNames maps a childProposal's algorithm IDs to Linux kernel crypto
// names. For AEAD ciphers (prop.integ == nil) integName is "" — the kernel
// XFRM layer (internal/xfrm) uses an empty IntAlgName as the signal to build
// an Aead transform instead of separate Crypt+Auth ones.
func childAlgNames(prop *childProposal) (encrName, integName string, integTruncBits int) {
	if prop.encr.IsAEAD() {
		encrName = "rfc4106(gcm(aes))"
		return encrName, "", 0
	}
	// All other currently supported encryption algorithms are AES-CBC variants.
	encrName = "cbc(aes)"

	switch prop.integ.id {
	case message.AUTH_HMAC_SHA1_96:
		integName, integTruncBits = "hmac(sha1)", 96
	case message.AUTH_HMAC_SHA2_256_128:
		integName, integTruncBits = "hmac(sha256)", 128
	case authHmacSha2512_256:
		integName, integTruncBits = "hmac(sha512)", 256
	default:
		integName, integTruncBits = "hmac(sha256)", 128
	}
	return
}
