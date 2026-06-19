package ikev2

// CREATE_CHILD_SA handler — RFC 7296 §2.8 (CHILD SA rekey) and §2.18 (IKE SA rekey).
//
// The UE acts as the rekey initiator. We respond as the IKE responder.
//
// Dispatch:
//   TSi/TSr present → CHILD SA rekey
//   No TSi/TSr      → IKE SA rekey

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"

	"vectorcore-epdg/internal/xfrm"

	"github.com/free5gc/ike/message"
)

// ─────────────────────────────────────────────────────────────────────────────
// Payload types for CREATE_CHILD_SA
// ─────────────────────────────────────────────────────────────────────────────

type childSAPayloads struct {
	sa    *message.SecurityAssociation
	nonce *message.Nonce
	ke    *message.KeyExchange
	tsi   *message.TrafficSelectorInitiator
	tsr   *message.TrafficSelectorResponder
}

func parseChildSAPayloads(firstType uint8, plain []byte) (*childSAPayloads, error) {
	result := &childSAPayloads{}
	curType := firstType
	off := 0

	for curType != 0 && off < len(plain) {
		if off+4 > len(plain) {
			break
		}
		nextType := plain[off]
		payloadLen := int(binary.BigEndian.Uint16(plain[off+2 : off+4]))
		if payloadLen < 4 || off+payloadLen > len(plain) {
			break
		}
		body := plain[off+4 : off+payloadLen]

		switch message.IkePayloadType(curType) {
		case message.TypeSA:
			pl := &message.SecurityAssociation{}
			if err := pl.Unmarshal(body); err == nil {
				result.sa = pl
			}
		case message.TypeNiNr:
			pl := &message.Nonce{}
			if err := pl.Unmarshal(body); err == nil {
				result.nonce = pl
			}
		case message.TypeKE:
			pl := &message.KeyExchange{}
			if err := pl.Unmarshal(body); err == nil {
				result.ke = pl
			}
		case message.TypeTSi:
			pl := &message.TrafficSelectorInitiator{}
			if err := pl.Unmarshal(body); err == nil {
				result.tsi = pl
			}
		case message.TypeTSr:
			pl := &message.TrafficSelectorResponder{}
			if err := pl.Unmarshal(body); err == nil {
				result.tsr = pl
			}
		}

		off += payloadLen
		curType = nextType
	}
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Notify helpers
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) sendChildSANotify(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, msgID uint32, notifyType uint16, natt bool) {
	var inner message.IKEPayloadContainer
	inner.BuildNotification(message.TypeNone, notifyType, nil, nil)
	if err := s.sendEncryptedResponse(conn, remote, sa, message.CREATE_CHILD_SA, msgID, inner, natt); err != nil {
		s.log.Debug("CREATE_CHILD_SA: send notify failed", "notify", notifyType, "err", err)
	}
}

func (s *Server) sendChildSANotifyData(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, msgID uint32, notifyType uint16, data []byte, natt bool) {
	var inner message.IKEPayloadContainer
	inner.BuildNotification(message.TypeNone, notifyType, nil, data)
	if err := s.sendEncryptedResponse(conn, remote, sa, message.CREATE_CHILD_SA, msgID, inner, natt); err != nil {
		s.log.Debug("CREATE_CHILD_SA: send notify failed", "notify", notifyType, "err", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation helpers
// ─────────────────────────────────────────────────────────────────────────────

// deriveChildSAKeysPFS derives CHILD SA keying material with PFS (RFC 7296 §2.17).
// KEYMAT = prf+(SK_d, g^ir | Ni | Nr)
func deriveChildSAKeysPFS(saKey *ikeSAKey, dhShared, nonceI, nonceR []byte, encrKeyLen, integKeyLen int) (encrIn, integIn, encrOut, integOut []byte) {
	seed := make([]byte, len(dhShared)+len(nonceI)+len(nonceR))
	copy(seed, dhShared)
	copy(seed[len(dhShared):], nonceI)
	copy(seed[len(dhShared)+len(nonceI):], nonceR)

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

// deriveIKERekeyKeys computes the new IKE SA keying material after a rekey exchange.
// Per RFC 7296 §2.18:
//
//	SKEYSEED = prf(SK_d_old, g^ir (new) | Ni | Nr)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} = prf+(SKEYSEED, Ni | Nr | SPI_I | SPI_R)
func deriveIKERekeyKeys(oldKey *ikeSAKey, newProp *negotiatedProposal, dhShared, nonceI, nonceR []byte, newSPII, newSPIR uint64) (*ikeSAKey, error) {
	newKey := &ikeSAKey{
		dh:    newProp.dh,
		encr:  newProp.encr,
		integ: newProp.integ,
		prf:   newProp.prf,
	}

	// SKEYSEED = prf(SK_d_old, g^ir | Ni | Nr) — PRF keyed with old SK_d.
	skeySeed := make([]byte, len(dhShared)+len(nonceI)+len(nonceR))
	copy(skeySeed, dhShared)
	copy(skeySeed[len(dhShared):], nonceI)
	copy(skeySeed[len(dhShared)+len(nonceI):], nonceR)
	skeyH := newProp.prf.New(oldKey.SK_d)
	skeyH.Write(skeySeed)
	skeyseed := skeyH.Sum(nil)

	// prf+ seed: Ni | Nr | SPI_I | SPI_R.
	nonceSeed := make([]byte, len(nonceI)+len(nonceR)+16)
	copy(nonceSeed, nonceI)
	copy(nonceSeed[len(nonceI):], nonceR)
	binary.BigEndian.PutUint64(nonceSeed[len(nonceI)+len(nonceR):], newSPII)
	binary.BigEndian.PutUint64(nonceSeed[len(nonceI)+len(nonceR)+8:], newSPIR)

	integKeyLen := newProp.integKeyLen()
	totalLen := newProp.prf.KeyLen() + // SK_d
		integKeyLen*2 + // SK_ai + SK_ar
		newProp.encr.KeyLen()*2 + // SK_ei + SK_er
		newProp.prf.KeyLen()*2 // SK_pi + SK_pr

	keymat := prfPlus(newProp.prf.New(skeyseed), nonceSeed, totalLen)

	off := 0
	take := func(n int) []byte {
		b := make([]byte, n)
		copy(b, keymat[off:off+n])
		off += n
		return b
	}
	newKey.SK_d = take(newProp.prf.KeyLen())
	newKey.SK_ai = take(integKeyLen)
	newKey.SK_ar = take(integKeyLen)
	newKey.SK_ei = take(newProp.encr.KeyLen())
	newKey.SK_er = take(newProp.encr.KeyLen())
	newKey.SK_pi = take(newProp.prf.KeyLen())
	newKey.SK_pr = take(newProp.prf.KeyLen())
	return newKey, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// CREATE_CHILD_SA dispatcher (replaces stub in server.go)
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) handleCreateChildSA(conn *net.UDPConn, remote *net.UDPAddr, pkt []byte, hdr *message.IKEHeader) {
	sa := s.lookupSA(hdr.InitiatorSPI)
	if sa == nil {
		s.log.Debug("CREATE_CHILD_SA: unknown SPI", "spi_i", hdr.InitiatorSPI, "remote", remote)
		return
	}

	sa.mu.Lock()
	defer sa.mu.Unlock()

	if sa.state != ikeStateEstablished {
		s.log.Warn("CREATE_CHILD_SA: SA not established", "state", sa.state, "remote", remote)
		return
	}
	sa.lastSeen = time.Now()
	natt := sa.natT

	innerType, plain, err := decryptSK(sa.saKey, pkt)
	if err != nil {
		s.log.Warn("CREATE_CHILD_SA: decrypt failed", "err", err, "remote", remote)
		return
	}

	pl, err := parseChildSAPayloads(innerType, plain)
	if err != nil {
		s.log.Warn("CREATE_CHILD_SA: parse error", "err", err, "remote", remote)
		s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
		return
	}
	if pl.sa == nil || pl.nonce == nil {
		s.log.Warn("CREATE_CHILD_SA: missing SA or Nonce payload", "remote", remote)
		s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
		return
	}

	// RFC 7296 §2.8: TSi/TSr present means CHILD SA rekey; absent means IKE SA rekey.
	if pl.tsi != nil || pl.tsr != nil {
		s.handleChildSARekey(conn, remote, sa, hdr, pl, natt)
	} else {
		s.handleIKESARekey(conn, remote, sa, hdr, pl, natt)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CHILD SA rekey (RFC 7296 §2.8)
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) handleChildSARekey(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, hdr *message.IKEHeader, pl *childSAPayloads, natt bool) {
	prop, propNum, peerSPI, err := selectAndExtractESP(pl.sa)
	if err != nil {
		s.log.Info("CREATE_CHILD_SA: no acceptable ESP proposal", "imsi", sa.imsi, "err", err)
		s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.NO_PROPOSAL_CHOSEN, natt)
		return
	}

	// PFS: negotiate DH if the selected proposal requires it.
	var dhShared, ourDHPub []byte
	if prop.dh != nil {
		groupBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(groupBytes, prop.dh.TransformID())
		if pl.ke == nil {
			s.log.Info("CREATE_CHILD_SA: PFS required but no KE payload", "imsi", sa.imsi)
			s.sendChildSANotifyData(conn, remote, sa, hdr.MessageID, message.INVALID_KE_PAYLOAD, groupBytes, natt)
			return
		}
		if pl.ke.DiffieHellmanGroup != prop.dh.TransformID() {
			s.log.Info("CREATE_CHILD_SA: wrong DH group",
				"got", pl.ke.DiffieHellmanGroup, "want", prop.dh.TransformID(), "imsi", sa.imsi)
			s.sendChildSANotifyData(conn, remote, sa, hdr.MessageID, message.INVALID_KE_PAYLOAD, groupBytes, natt)
			return
		}
		dhPriv, err2 := prop.dh.GeneratePrivateKey()
		if err2 != nil {
			s.log.Error("CREATE_CHILD_SA: DH keygen failed", "err", err2)
			s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
			return
		}
		ourDHPub = prop.dh.PublicKey(dhPriv)
		dhShared, err2 = prop.dh.SharedKey(dhPriv, pl.ke.KeyExchangeData)
		if err2 != nil {
			s.log.Warn("CREATE_CHILD_SA: DH shared key failed", "err", err2, "imsi", sa.imsi)
			s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
			return
		}
	}

	nonceI := pl.nonce.NonceData
	nonceR := make([]byte, 32)
	if _, err2 := io.ReadFull(rand.Reader, nonceR); err2 != nil {
		s.log.Error("CREATE_CHILD_SA: nonce gen failed", "err", err2)
		return
	}

	spiBytes := make([]byte, 4)
	if _, err2 := io.ReadFull(rand.Reader, spiBytes); err2 != nil {
		s.log.Error("CREATE_CHILD_SA: SPI gen failed", "err", err2)
		return
	}
	newLocalSPI := binary.BigEndian.Uint32(spiBytes)

	encrName, integName, integTrunc := childAlgNames(prop)
	var encrIn, integIn, encrOut, integOut []byte
	if dhShared != nil {
		encrIn, integIn, encrOut, integOut = deriveChildSAKeysPFS(sa.saKey, dhShared, nonceI, nonceR,
			prop.encr.KeyLen(), prop.integKeyLen())
	} else {
		encrIn, integIn, encrOut, integOut = deriveChildSAKeys(sa.saKey, nonceI, nonceR,
			prop.encr.KeyLen(), prop.integKeyLen())
	}

	// Traffic selectors: PAA from session (same as originally negotiated).
	var remoteTS *net.IPNet
	var paa net.IP
	if s.sessions != nil && sa.sessionID != "" {
		if sess := s.sessions.Get(sa.sessionID); sess != nil && sess.S2B != nil {
			if p := net.ParseIP(sess.S2B.PAA); p != nil {
				if p4 := p.To4(); p4 != nil {
					paa = p4
					remoteTS = &net.IPNet{IP: p4, Mask: net.CIDRMask(32, 32)}
				}
			}
		}
	}
	if remoteTS == nil {
		remoteTS = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	_, localTS, _ := net.ParseCIDR("0.0.0.0/0")

	// Install new CHILD SA states only — policies already exist from initial negotiation
	// and don't need to change since the traffic selectors are identical.
	xfrmParams := xfrm.ChildSAParams{
		LocalIP:      sa.localIP,
		RemoteIP:     remote.IP,
		InboundSPI:   newLocalSPI,
		OutboundSPI:  peerSPI,
		EncKeyIn:     encrIn,
		IntKeyIn:     integIn,
		EncKeyOut:    encrOut,
		IntKeyOut:    integOut,
		EncAlgName:   encrName,
		IntAlgName:   integName,
		IntTruncBits: integTrunc,
		NATT:         natt,
		NATTSrcPort:  nattPort,
		NATTDstPort:  remote.Port,
		LocalTS:      localTS,
		RemoteTS:     remoteTS,
		IfID:         xfrm.IfID,
	}
	if err2 := xfrm.AddChildSAStates(xfrmParams); err2 != nil {
		s.log.Error("CREATE_CHILD_SA: XFRM install failed", "err", err2, "imsi", sa.imsi)
		s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
		return
	}

	// Store as pending — promoted to current when UE sends DELETE for the old SPI.
	sa.pendingESPProp = prop
	sa.pendingESPPropNum = propNum
	sa.pendingPeerESPSPI = peerSPI
	sa.pendingLocalESPSPI = newLocalSPI
	sa.pendingNonceI = nonceI
	sa.pendingNonceR = nonceR

	var inner message.IKEPayloadContainer
	buildESPSAResponse(&inner, prop, propNum, newLocalSPI)
	inner.BuildNonce(nonceR)
	if ourDHPub != nil {
		inner.BuildKeyExchange(prop.dh.TransformID(), ourDHPub)
	}
	buildTSResponse(&inner, paa)

	if err2 := s.sendEncryptedResponse(conn, remote, sa, message.CREATE_CHILD_SA, hdr.MessageID, inner, natt); err2 != nil {
		s.log.Error("CREATE_CHILD_SA: send response failed", "err", err2, "remote", remote)
		return
	}

	s.log.Info("CREATE_CHILD_SA: CHILD SA rekeyed",
		"imsi", sa.imsi,
		"old_inbound_spi", sa.localESPSPI,
		"new_inbound_spi", newLocalSPI,
		"encr", encrName, "encr_bits", prop.encr.keyBits,
		"integ", integName, "pfs", dhShared != nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// IKE SA rekey (RFC 7296 §2.18)
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) handleIKESARekey(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, hdr *message.IKEHeader, pl *childSAPayloads, natt bool) {
	if pl.ke == nil {
		s.log.Warn("CREATE_CHILD_SA: IKE rekey missing KE", "imsi", sa.imsi)
		s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
		return
	}

	newProp, propNum, err := selectIKEProposal(pl.sa)
	if err != nil {
		s.log.Info("CREATE_CHILD_SA: IKE rekey no acceptable proposal", "imsi", sa.imsi)
		s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.NO_PROPOSAL_CHOSEN, natt)
		return
	}

	if pl.ke.DiffieHellmanGroup != newProp.dh.TransformID() {
		groupBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(groupBytes, newProp.dh.TransformID())
		s.log.Info("CREATE_CHILD_SA: IKE rekey wrong DH group",
			"got", pl.ke.DiffieHellmanGroup, "want", newProp.dh.TransformID(), "imsi", sa.imsi)
		s.sendChildSANotifyData(conn, remote, sa, hdr.MessageID, message.INVALID_KE_PAYLOAD, groupBytes, natt)
		return
	}

	// Extract new SPI_I from the SA proposal (RFC 7296 §2.18: 8-byte SPI for IKE).
	var newSPII uint64
	for _, p := range pl.sa.Proposals {
		if p.ProposalNumber == propNum && p.ProtocolID == message.TypeIKE && len(p.SPI) == 8 {
			newSPII = binary.BigEndian.Uint64(p.SPI)
			break
		}
	}
	if newSPII == 0 {
		s.log.Warn("CREATE_CHILD_SA: IKE rekey missing SPI_I in proposal", "imsi", sa.imsi)
		s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
		return
	}

	// Generate new responder SPI and nonce.
	var spiRBytes [8]byte
	if _, err2 := io.ReadFull(rand.Reader, spiRBytes[:]); err2 != nil {
		s.log.Error("CREATE_CHILD_SA: IKE rekey SPI gen failed", "err", err2)
		return
	}
	newSPIR := binary.BigEndian.Uint64(spiRBytes[:])

	nonceR := make([]byte, 32)
	if _, err2 := io.ReadFull(rand.Reader, nonceR); err2 != nil {
		s.log.Error("CREATE_CHILD_SA: IKE rekey nonce gen failed", "err", err2)
		return
	}
	nonceI := pl.nonce.NonceData

	// DH exchange.
	dhPriv, err2 := newProp.dh.GeneratePrivateKey()
	if err2 != nil {
		s.log.Error("CREATE_CHILD_SA: IKE rekey DH keygen failed", "err", err2)
		return
	}
	dhPub := newProp.dh.PublicKey(dhPriv)
	dhShared, err2 := newProp.dh.SharedKey(dhPriv, pl.ke.KeyExchangeData)
	if err2 != nil {
		s.log.Warn("CREATE_CHILD_SA: IKE rekey DH failed", "err", err2, "imsi", sa.imsi)
		s.sendChildSANotify(conn, remote, sa, hdr.MessageID, message.INVALID_SYNTAX, natt)
		return
	}

	// Derive new IKE SA keys from old SK_d.
	newSAKey, err2 := deriveIKERekeyKeys(sa.saKey, newProp, dhShared, nonceI, nonceR, newSPII, newSPIR)
	if err2 != nil {
		s.log.Error("CREATE_CHILD_SA: IKE rekey key derivation failed", "err", err2, "imsi", sa.imsi)
		return
	}

	// Build response (encrypted with OLD SA's keys).
	newSPIRBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(newSPIRBytes, newSPIR)

	var inner message.IKEPayloadContainer
	inner = append(inner, buildIKESAPayload(newProp, propNum, newSPIRBytes))
	inner.BuildNonce(nonceR)
	inner.BuildKeyExchange(newProp.dh.TransformID(), dhPub)

	if err2 = s.sendEncryptedResponse(conn, remote, sa, message.CREATE_CHILD_SA, hdr.MessageID, inner, natt); err2 != nil {
		s.log.Error("CREATE_CHILD_SA: IKE rekey send failed", "err", err2, "remote", remote)
		return
	}

	// Create the new IKE SA. It inherits the CHILD SA and session from the old SA.
	// nonceI/nonceR are the rekey exchange nonces, used here as the new IKE SA nonces.
	// removeXFRMChildSA will re-derive CHILD SA keys using these (yielding wrong keys),
	// but XfrmStateDel matches by SPI+endpoints and ignores key material — harmless.
	newIKESA := &ikeSA{
		spiI:          newSPII,
		spiR:          newSPIR,
		remoteAddr:    sa.remoteAddr,
		natT:          sa.natT,
		nonceI:        nonceI,
		nonceR:        nonceR,
		proposal:      newProp,
		saKey:         newSAKey,
		state:         ikeStateEstablished,
		createdAt:     time.Now(),
		lastSeen:      time.Now(),
		localIP:       sa.localIP,
		imsi:          sa.imsi,
		nai:           sa.nai,
		apn:           sa.apn,
		mobikeEnabled: sa.mobikeEnabled,
		swmSessionID:  sa.swmSessionID,
		sessionID:     sa.sessionID,
		// CHILD SA fields: new IKE SA owns the same CHILD SA states.
		espProp:     sa.espProp,
		espPropNum:  sa.espPropNum,
		peerESPSPI:  sa.peerESPSPI,
		localESPSPI: sa.localESPSPI,
	}

	s.storeSA(newIKESA)

	// Update session to reference new IKE SA SPIs.
	if s.sessions != nil && sa.sessionID != "" {
		if sess := s.sessions.Get(sa.sessionID); sess != nil {
			sess.IkeSPII = newSPII
			sess.IkeSPIR = newSPIR
		}
	}

	// Clear session references from the old SA so fullTeardown on it (triggered
	// when the UE sends DELETE for the old IKE SA) does not tear down the session.
	sa.sessionID = ""
	sa.swmSessionID = ""
	sa.espProp = nil // prevents removeXFRMChildSA from deleting still-active CHILD SA

	s.log.Info("CREATE_CHILD_SA: IKE SA rekeyed",
		"imsi", sa.imsi,
		"old_spi_i", sa.spiI,
		"new_spi_i", newSPII, "new_spi_r", newSPIR,
		"dh", newProp.dh.TransformID(),
		"encr", newProp.encr.id, "encr_bits", newProp.encr.keyBits,
		"integ", newProp.integID(), "prf", newProp.prf.id)
}
