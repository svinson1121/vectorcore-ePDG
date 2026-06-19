package ikev2

// INFORMATIONAL exchange handler (RFC 7296 §1.4, §2.24, §3.11).
//
// Handles:
//   - IKE SA delete: UE sends DELETE{IKE} → ePDG tears down XFRM, GTP-U, S2b, session.
//   - CHILD SA delete: UE sends DELETE{ESP, spi=...} → remove those CHILD SAs only.
//   - DPD / liveness: empty INFORMATIONAL from UE → respond with empty INFORMATIONAL.
//   - DPD response: UE responds to our probe → clear pending DPD state.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"vectorcore-epdg/internal/session"
	"vectorcore-epdg/internal/xfrm"

	"github.com/free5gc/ike/message"
)

func (s *Server) handleInformational(conn *net.UDPConn, remote *net.UDPAddr, pkt []byte, hdr *message.IKEHeader) {
	isRequest := hdr.Flags&message.ResponseBitCheck == 0
	// UE responding to our DPD probe: InitiatorBit set (UE is IKE initiator), ResponseBit set.
	isUEResponse := hdr.Flags&message.ResponseBitCheck != 0 && hdr.Flags&message.InitiatorBitCheck != 0

	if !isRequest && !isUEResponse {
		return
	}

	sa := s.lookupSA(hdr.InitiatorSPI)
	if sa == nil {
		s.log.Debug("INFORMATIONAL: unknown SPI", "spi_i", hdr.InitiatorSPI)
		return
	}

	// Handle UE's response to our DPD probe (no decrypt needed — it's empty).
	if isUEResponse {
		sa.mu.Lock()
		if !sa.dpdSentAt.IsZero() && hdr.MessageID == sa.dpdMsgID {
			sa.lastSeen = time.Now()
			sa.dpdSentAt = time.Time{}
			sa.dpdMsgID = 0
			s.log.Debug("INFORMATIONAL: DPD response received", "imsi", sa.imsi, "msg_id", hdr.MessageID)
		}
		sa.mu.Unlock()
		return
	}

	// From here: handling an inbound request from the UE.
	sa.mu.Lock()
	defer sa.mu.Unlock()

	if sa.state == ikeStateDeleting {
		return
	}

	natt := sa.natT
	sa.lastSeen = time.Now()
	// Clear any pending DPD probe — the UE is clearly alive.
	if !sa.dpdSentAt.IsZero() {
		sa.dpdSentAt = time.Time{}
		sa.dpdMsgID = 0
	}

	innerType, plain, err := decryptSK(sa.saKey, pkt)
	if err != nil {
		s.log.Warn("INFORMATIONAL: decrypt failed", "err", err, "remote", remote)
		return
	}

	// Parse inner payloads looking for DELETE and MOBIKE notifies.
	var deleteIKE bool
	var deleteESPSPIs []uint32
	hasUpdateSA, incomingCookie2 := parseInfoPayloads(innerType, plain, &deleteIKE, &deleteESPSPIs)

	// MOBIKE UPDATE_SA_ADDRESSES: path migration — sends its own response.
	if hasUpdateSA && sa.mobikeEnabled {
		s.handleUpdateSA(conn, remote, sa, hdr.MessageID, incomingCookie2, natt)
		return
	}

	// RFC 7296 §2.24: always respond, even to delete.
	// Empty INFORMATIONAL response (NextPayload = 0, no inner payloads).
	if err2 := s.sendEncryptedRaw(conn, remote, sa, message.INFORMATIONAL, hdr.MessageID, 0, nil, natt); err2 != nil {
		s.log.Warn("INFORMATIONAL: send response failed", "err", err2)
	}

	switch {
	case deleteIKE:
		s.log.Info("INFORMATIONAL: UE requested IKE SA delete",
			"imsi", sa.imsi, "spi_i", hdr.InitiatorSPI, "remote", remote)
		sa.state = ikeStateDeleting
		s.fullTeardown(sa, "ike_delete_by_ue")

	case len(deleteESPSPIs) > 0:
		s.log.Info("INFORMATIONAL: UE requested CHILD SA delete",
			"imsi", sa.imsi, "spis", deleteESPSPIs, "remote", remote)
		for _, spi := range deleteESPSPIs {
			switch {
			case sa.espProp != nil && (spi == sa.localESPSPI || spi == sa.peerESPSPI):
				if sa.pendingESPProp != nil {
					// Rekey in progress: remove only the old SA states; policies remain for the new SA.
					oldParams := xfrm.ChildSAParams{
						LocalIP:     sa.localIP,
						RemoteIP:    sa.remoteAddr.IP,
						InboundSPI:  sa.localESPSPI,
						OutboundSPI: sa.peerESPSPI,
						NATT:        sa.natT,
						NATTSrcPort: nattPort,
						NATTDstPort: sa.remoteAddr.Port,
						IfID:        xfrm.IfID,
					}
					if err := xfrm.RemoveChildSAStates(oldParams); err != nil && !errors.Is(err, os.ErrNotExist) {
						s.log.Warn("INFORMATIONAL: remove old CHILD SA states failed", "err", err, "imsi", sa.imsi)
					}
					// Promote the pending SA to current.
					sa.espProp = sa.pendingESPProp
					sa.espPropNum = sa.pendingESPPropNum
					sa.peerESPSPI = sa.pendingPeerESPSPI
					sa.localESPSPI = sa.pendingLocalESPSPI
					sa.nonceI = sa.pendingNonceI
					sa.nonceR = sa.pendingNonceR
					sa.pendingESPProp = nil
					sa.pendingESPPropNum = 0
					sa.pendingPeerESPSPI = 0
					sa.pendingLocalESPSPI = 0
					sa.pendingNonceI = nil
					sa.pendingNonceR = nil
					if s.sessions != nil && sa.sessionID != "" {
						if sess := s.sessions.Get(sa.sessionID); sess != nil {
							sess.ESPInboundSPI = sa.localESPSPI
							sess.ESPOutboundSPI = sa.peerESPSPI
						}
					}
					s.log.Info("INFORMATIONAL: CHILD SA rekey complete — pending SA promoted",
						"imsi", sa.imsi, "new_inbound_spi", sa.localESPSPI)
				} else {
					// No rekey in progress: full removal (states + policies).
					s.removeXFRMChildSA(sa)
				}

			case sa.pendingESPProp != nil && (spi == sa.pendingLocalESPSPI || spi == sa.pendingPeerESPSPI):
				// UE aborting rekey before completing it — remove the new states, keep the current SA.
				abortParams := xfrm.ChildSAParams{
					LocalIP:     sa.localIP,
					RemoteIP:    sa.remoteAddr.IP,
					InboundSPI:  sa.pendingLocalESPSPI,
					OutboundSPI: sa.pendingPeerESPSPI,
					NATT:        sa.natT,
					NATTSrcPort: nattPort,
					NATTDstPort: sa.remoteAddr.Port,
					IfID:        xfrm.IfID,
				}
				if err := xfrm.RemoveChildSAStates(abortParams); err != nil && !errors.Is(err, os.ErrNotExist) {
					s.log.Warn("INFORMATIONAL: remove pending CHILD SA states failed", "err", err, "imsi", sa.imsi)
				}
				sa.pendingESPProp = nil
				sa.pendingESPPropNum = 0
				sa.pendingPeerESPSPI = 0
				sa.pendingLocalESPSPI = 0
				sa.pendingNonceI = nil
				sa.pendingNonceR = nil
				s.log.Info("INFORMATIONAL: CHILD SA rekey aborted by UE", "imsi", sa.imsi)
			}
		}

	default:
		// DPD / liveness — response already sent above.
		s.log.Debug("INFORMATIONAL: DPD/liveness", "imsi", sa.imsi, "remote", remote)
	}
}

// fullTeardown cleans up everything associated with an IKE SA:
// XFRM SAs/policies, GTP-U session, S2b session, SWm session, session FSM, and IKE SA map entry.
// Must be called with sa.mu held.
func (s *Server) fullTeardown(sa *ikeSA, reason string) {
	s.removeXFRMChildSA(sa)

	// If a CHILD SA rekey was in progress, also remove the pending SA states.
	// (Policies were already removed by removeXFRMChildSA above.)
	if sa.pendingESPProp != nil && sa.localIP != nil {
		pendingParams := xfrm.ChildSAParams{
			LocalIP:     sa.localIP,
			RemoteIP:    sa.remoteAddr.IP,
			InboundSPI:  sa.pendingLocalESPSPI,
			OutboundSPI: sa.pendingPeerESPSPI,
			NATT:        sa.natT,
			NATTSrcPort: nattPort,
			NATTDstPort: sa.remoteAddr.Port,
			IfID:        xfrm.IfID,
		}
		if err := xfrm.RemoveChildSAStates(pendingParams); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.log.Warn("fullTeardown: remove pending CHILD SA states failed", "err", err)
		}
	}

	handoverComplete := false
	if s.sessions != nil && sa.sessionID != "" {
		if sess := s.sessions.Get(sa.sessionID); sess != nil {
			handoverComplete = sess.HandoverComplete
			_ = sess.Transition(session.StateCleaningUp)

			if s.gtpuMgr != nil && sess.S2B != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				if err := s.gtpuMgr.RemoveSession(ctx, sess); err != nil {
					s.log.Warn("fullTeardown: GTP-U remove failed", "err", err, "session_id", sess.ID)
				}
				cancel()
			}

			if s.s2b != nil && sess.S2B != nil && sess.S2B.PGWControlTEID != 0 && sess.S2B.EBI != 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				if err := s.s2b.DeleteSession(ctx,
					sess.S2B.PGWControlIP,
					sess.S2B.PGWControlTEID,
					sess.S2B.LocalControlTEID,
					sess.S2B.LocalUserTEID,
					sess.S2B.EBI,
				); err != nil {
					s.log.Warn("fullTeardown: S2b DeleteSession failed", "err", err, "session_id", sess.ID)
				}
				cancel()
			}

			_ = sess.Transition(session.StateDeleted)
			s.sessions.Delete(sess.ID)
		}
	}

	if s.swm != nil && sa.swmSessionID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var err error
		if handoverComplete {
			err = s.swm.TerminateSessionHandover(ctx, sa.swmSessionID)
		} else {
			err = s.swm.TerminateSession(ctx, sa.swmSessionID)
		}
		if err != nil {
			s.log.Warn("fullTeardown: SWm STR failed", "err", err, "imsi", sa.imsi)
		}
		cancel()
	}

	s.deleteSA(sa.spiI)
	s.log.Info("IKE SA torn down", "imsi", sa.imsi, "reason", reason, "spi_i", sa.spiI)
}

// removeXFRMChildSA removes XFRM SA and policy for the CHILD SA, if installed.
// Safe to call multiple times (errors are logged but not fatal).
func (s *Server) removeXFRMChildSA(sa *ikeSA) {
	if sa.espProp == nil || sa.localIP == nil || sa.localESPSPI == 0 {
		return
	}

	var remoteTS *net.IPNet
	// Try to reconstruct the remote TS from the session PAA.
	if s.sessions != nil && sa.sessionID != "" {
		if sess := s.sessions.Get(sa.sessionID); sess != nil && sess.S2B != nil {
			if paa := net.ParseIP(sess.S2B.PAA); paa != nil {
				if paa4 := paa.To4(); paa4 != nil {
					remoteTS = &net.IPNet{IP: paa4, Mask: net.CIDRMask(32, 32)}
				}
			}
		}
	}
	if remoteTS == nil {
		remoteTS = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	_, localTS, _ := net.ParseCIDR("0.0.0.0/0")

	encrName, integName, integTrunc := childAlgNames(sa.espProp)
	encrIn, integIn, encrOut, integOut := deriveChildSAKeys(sa.saKey, sa.nonceI, sa.nonceR,
		sa.espProp.encr.KeyLen(), sa.espProp.integKeyLen())

	params := xfrm.ChildSAParams{
		LocalIP:      sa.localIP,
		RemoteIP:     sa.remoteAddr.IP,
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
		NATTDstPort:  sa.remoteAddr.Port,
		LocalTS:      localTS,
		RemoteTS:     remoteTS,
		IfID:         xfrm.IfID,
	}
	if err := xfrm.RemoveChildSA(params); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("removeXFRMChildSA: xfrm remove failed", "err", err, "imsi", sa.imsi)
	}
}

// parseInfoPayloads walks the decrypted INFORMATIONAL payload chain.
// Returns hasUpdateSA=true and any COOKIE2 data found alongside MOBIKE notifies.
func parseInfoPayloads(firstType uint8, plain []byte, deleteIKE *bool, deleteESPSPIs *[]uint32) (hasUpdateSA bool, cookie2 []byte) {
	curType := firstType
	off := 0
	for curType != 0 && off < len(plain) {
		if off+4 > len(plain) {
			return
		}
		nextType := plain[off]
		payloadLen := int(binary.BigEndian.Uint16(plain[off+2 : off+4]))
		if payloadLen < 4 || off+payloadLen > len(plain) {
			return
		}
		body := plain[off+4 : off+payloadLen]

		switch message.IkePayloadType(curType) {
		case message.TypeD:
			d := &message.Delete{}
			if err := d.Unmarshal(body); err == nil {
				switch d.ProtocolID {
				case uint8(message.TypeIKE):
					*deleteIKE = true
				case uint8(message.TypeESP):
					*deleteESPSPIs = append(*deleteESPSPIs, d.SPIs...)
				}
			}
		case message.TypeN:
			// Notify payload: [1 ProtoID][1 SPISize][2 Type][SPISize SPI][data]
			if len(body) >= 4 {
				spiSize := int(body[1])
				notifyType := binary.BigEndian.Uint16(body[2:4])
				dataOff := 4 + spiSize
				switch notifyType {
				case message.UPDATE_SA_ADDRESSES:
					hasUpdateSA = true
				case message.COOKIE2:
					if dataOff <= len(body) {
						cookie2 = append([]byte(nil), body[dataOff:]...)
					}
				}
			}
		}

		off += payloadLen
		curType = nextType
	}
	return
}

// handleUpdateSA processes a MOBIKE UPDATE_SA_ADDRESSES request (RFC 4555 §3.5).
// Must be called with sa.mu held.
func (s *Server) handleUpdateSA(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, msgID uint32, incomingCookie2 []byte, natt bool) {
	if sa.espProp == nil || sa.localIP == nil {
		_ = s.sendEncryptedRaw(conn, remote, sa, message.INFORMATIONAL, msgID, 0, nil, natt)
		return
	}

	if len(incomingCookie2) == 0 || sa.cookie2 == nil {
		// Step 1: UE announces new address. Challenge return routability with COOKIE2.
		c2 := make([]byte, 16)
		if _, err := rand.Read(c2); err != nil {
			s.log.Error("MOBIKE: cookie2 gen failed", "err", err)
			_ = s.sendEncryptedRaw(conn, remote, sa, message.INFORMATIONAL, msgID, 0, nil, natt)
			return
		}
		sa.cookie2 = c2

		var inner message.IKEPayloadContainer
		inner.BuildNotification(message.TypeNone, message.COOKIE2, nil, c2)
		if err := s.sendEncryptedResponse(conn, remote, sa, message.INFORMATIONAL, msgID, inner, natt); err != nil {
			s.log.Warn("MOBIKE: send COOKIE2 challenge failed", "err", err)
		}
		s.log.Info("MOBIKE: COOKIE2 challenge sent", "imsi", sa.imsi, "new_addr", remote)
		return
	}

	// Step 3: UE echoes COOKIE2. Verify return routability before migrating.
	if !constEqual(incomingCookie2, sa.cookie2) {
		s.log.Warn("MOBIKE: COOKIE2 mismatch, ignoring", "imsi", sa.imsi, "remote", remote)
		_ = s.sendEncryptedRaw(conn, remote, sa, message.INFORMATIONAL, msgID, 0, nil, natt)
		return
	}

	oldAddr := sa.remoteAddr
	if err := s.migrateMobikeXFRM(sa, remote); err != nil {
		s.log.Error("MOBIKE: XFRM migration failed", "err", err, "imsi", sa.imsi, "new_addr", remote)
		_ = s.sendEncryptedRaw(conn, remote, sa, message.INFORMATIONAL, msgID, 0, nil, natt)
		return
	}

	sa.remoteAddr = remote
	sa.cookie2 = nil
	if s.sessions != nil && sa.sessionID != "" {
		if sess := s.sessions.Get(sa.sessionID); sess != nil {
			sess.OuterIP = remote.String()
		}
	}
	_ = s.sendEncryptedRaw(conn, remote, sa, message.INFORMATIONAL, msgID, 0, nil, natt)
	s.log.Info("MOBIKE: path migrated", "imsi", sa.imsi, "old_addr", oldAddr, "new_addr", remote)
}

// migrateMobikeXFRM replaces the XFRM CHILD SA outer endpoints.
// Must be called with sa.mu held.
func (s *Server) migrateMobikeXFRM(sa *ikeSA, newRemote *net.UDPAddr) error {
	var remoteTS *net.IPNet
	if s.sessions != nil && sa.sessionID != "" {
		if sess := s.sessions.Get(sa.sessionID); sess != nil && sess.S2B != nil {
			if paa := net.ParseIP(sess.S2B.PAA); paa != nil {
				if paa4 := paa.To4(); paa4 != nil {
					remoteTS = &net.IPNet{IP: paa4, Mask: net.CIDRMask(32, 32)}
				}
			}
		}
	}
	if remoteTS == nil {
		remoteTS = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	_, localTS, _ := net.ParseCIDR("0.0.0.0/0")

	encrName, integName, integTrunc := childAlgNames(sa.espProp)
	encrIn, integIn, encrOut, integOut := deriveChildSAKeys(sa.saKey, sa.nonceI, sa.nonceR,
		sa.espProp.encr.KeyLen(), sa.espProp.integKeyLen())

	base := xfrm.ChildSAParams{
		LocalIP:      sa.localIP,
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
		LocalTS:      localTS,
		RemoteTS:     remoteTS,
		IfID:         xfrm.IfID,
	}

	oldParams := base
	oldParams.RemoteIP = sa.remoteAddr.IP
	oldParams.NATTDstPort = sa.remoteAddr.Port

	if (sa.remoteAddr.IP.To4() == nil) != (newRemote.IP.To4() == nil) {
		// MOBIKE path migration across address families (v4<->v6) would require
		// tearing down and re-keying the XFRM SA under a different family, not
		// just patching endpoints — explicitly unsupported, reject rather than
		// silently corrupt the SA.
		return fmt.Errorf("mobike: cross-family migration unsupported (old=%v new=%v)", sa.remoteAddr.IP, newRemote.IP)
	}

	newParams := base
	newParams.RemoteIP = newRemote.IP
	newParams.NATTDstPort = newRemote.Port

	return xfrm.MigrateChildSA(oldParams, newParams)
}

// reaperLoop periodically checks all established IKE SAs for liveness.
// For SAs idle longer than DPDDelay it sends a DPD probe; for SAs that have not
// responded to a probe within DPDTimeout it calls fullTeardown.
func (s *Server) reaperLoop() {
	if s.fullCfg == nil || !s.fullCfg.IKEv2.DPDEnabled {
		return
	}
	delay := time.Duration(s.fullCfg.IKEv2.DPDDelay) * time.Second
	timeout := time.Duration(s.fullCfg.IKEv2.DPDTimeout) * time.Second
	if delay <= 0 {
		delay = 30 * time.Second
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}

	// Scan at 1/3 the probe delay so we catch timeouts promptly, min 10s.
	tick := delay / 3
	if tick < 10*time.Second {
		tick = 10 * time.Second
	}

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}

		// Snapshot SPIs under the read lock so we don't hold it during teardown.
		s.mu.RLock()
		spis := make([]uint64, 0, len(s.sas))
		for spiI := range s.sas {
			spis = append(spis, spiI)
		}
		s.mu.RUnlock()

		for _, spiI := range spis {
			sa := s.lookupSA(spiI)
			if sa == nil {
				continue
			}
			sa.mu.Lock()
			if sa.state != ikeStateEstablished {
				sa.mu.Unlock()
				continue
			}
			if sa.dpdSentAt.IsZero() {
				// No probe pending — check if we should send one.
				if time.Since(sa.lastSeen) > delay {
					s.sendDPDProbe(sa)
				}
			} else {
				// Probe is outstanding — check if it has timed out.
				if time.Since(sa.dpdSentAt) > timeout {
					s.log.Info("DPD timeout: tearing down IKE SA",
						"imsi", sa.imsi, "spi_i", spiI,
						"probe_sent_ago", time.Since(sa.dpdSentAt).Round(time.Second))
					sa.state = ikeStateDeleting
					s.fullTeardown(sa, "dpd_timeout")
				}
			}
			sa.mu.Unlock()
		}
	}
}

// sendDPDProbe sends an empty INFORMATIONAL request to the UE as a liveness probe.
// Must be called with sa.mu held. sa.state must be ikeStateEstablished.
func (s *Server) sendDPDProbe(sa *ikeSA) {
	msgID := sa.ourMsgID
	sa.ourMsgID++

	conn := s.conn500
	if sa.natT {
		conn = s.conn4500
	}
	if conn == nil {
		return
	}

	if err := s.sendEncryptedRequest(conn, sa.remoteAddr, sa, message.INFORMATIONAL, msgID, 0, nil, sa.natT); err != nil {
		s.log.Warn("DPD probe send failed", "imsi", sa.imsi, "err", err)
		return
	}

	sa.dpdMsgID = msgID
	sa.dpdSentAt = time.Now()
	s.log.Debug("DPD probe sent", "imsi", sa.imsi, "msg_id", msgID)
}

// sendEncryptedRequest encrypts and sends an IKE request message initiated by the ePDG
// (as IKE responder). Differs from sendEncryptedRaw in that the IKE header flags are
// 0x00 — no Initiator bit (ePDG is IKE responder), no Response bit (this is a request).
func (s *Server) sendEncryptedRequest(conn *net.UDPConn, remote *net.UDPAddr, sa *ikeSA, exchType uint8, msgID uint32, innerNextPayload uint8, plain []byte, natt bool) error {
	integLen := sa.saKey.integ.OutputLen()
	blockSize := sa.saKey.encr.BlockSize()
	padLen := blockSize - (len(plain) % blockSize)
	cipherLen := blockSize + len(plain) + padLen
	skPayloadLen := 4 + cipherLen + integLen
	totalLen := message.IKE_HEADER_LEN + skPayloadLen

	hdrBytes := buildIKERequestHeaderBytes(sa.spiI, sa.spiR, exchType, msgID, totalLen)

	out, err := encryptSK(sa.saKey, innerNextPayload, plain, hdrBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	s.send(conn, remote, out, natt)
	return nil
}
