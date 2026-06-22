package ikev2

// IKE_SA_INIT exchange handler — RFC 7296 §1.2.

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"time"

	"vectorcore-epdg/internal/xfrm"

	"github.com/free5gc/ike/message"
)

func (s *Server) handleIKESAInit(conn *net.UDPConn, remote *net.UDPAddr, pkt []byte, hdr *message.IKEHeader, natt bool) {
	// Initiator flag must be set; Response flag must not.
	if hdr.Flags&message.InitiatorBitCheck == 0 || hdr.Flags&message.ResponseBitCheck != 0 {
		s.log.Debug("IKE_SA_INIT: unexpected flags", "flags", hdr.Flags, "remote", remote)
		return
	}

	// A retransmitted IKE_SA_INIT for an SPI we've already answered doesn't
	// need to redo any work: resend the cached response instead of repeating
	// DH/key derivation. Requiring the source to match the original sender
	// keeps this from being usable to reflect a cached response at a
	// different address by guessing/colliding a (cryptographically random,
	// 64-bit) SPI.
	if existing := s.lookupSA(hdr.InitiatorSPI); existing != nil {
		existing.mu.Lock()
		isRetransmit := existing.state == ikeStateAuth &&
			len(existing.initRespRaw) > 0 &&
			existing.remoteAddr != nil &&
			existing.remoteAddr.IP.Equal(remote.IP) && existing.remoteAddr.Port == remote.Port
		respRaw := existing.initRespRaw
		existing.mu.Unlock()
		if isRetransmit {
			s.log.Debug("IKE_SA_INIT: retransmission, resending cached response", "spi_i", hdr.InitiatorSPI, "remote", remote)
			s.send(conn, remote, respRaw, natt)
			return
		}
	}

	ikeMsg := new(message.IKEMessage)
	ikeMsg.IKEHeader = hdr
	if err := ikeMsg.DecodePayload(pkt[message.IKE_HEADER_LEN:]); err != nil {
		s.log.Debug("IKE_SA_INIT: decode failed", "err", err, "remote", remote)
		return
	}

	// Extract payloads.
	var saPayload *message.SecurityAssociation
	var kePayload *message.KeyExchange
	var noncePayload *message.Nonce
	var notifyPayloads []*message.Notification

	for _, pl := range ikeMsg.Payloads {
		switch pl.Type() {
		case message.TypeSA:
			saPayload = pl.(*message.SecurityAssociation)
		case message.TypeKE:
			kePayload = pl.(*message.KeyExchange)
		case message.TypeNiNr:
			noncePayload = pl.(*message.Nonce)
		case message.TypeN:
			notifyPayloads = append(notifyPayloads, pl.(*message.Notification))
		}
	}

	if saPayload == nil || kePayload == nil || noncePayload == nil {
		s.log.Warn("IKE_SA_INIT: missing required payload", "remote", remote)
		s.sendInitNotify(conn, remote, hdr, message.INVALID_SYNTAX, nil, natt)
		return
	}

	// RFC 7296 §2.6 COOKIE challenge: once at/above the configured half-open
	// load, require proof the initiator can receive traffic at its claimed
	// source address before doing any DH/key-derivation work or allocating
	// an SA. Below the threshold, skip the extra round trip entirely.
	if load := s.saCount(); load >= s.cookieThreshold() {
		cookie := findNotifyData(notifyPayloads, message.COOKIE)
		if cookie == nil || !s.cookies.verify(cookie, hdr.InitiatorSPI, remote) {
			challenge := s.cookies.issue(hdr.InitiatorSPI, remote)
			s.log.Debug("IKE_SA_INIT: issuing COOKIE challenge", "remote", remote, "half_open", load)
			s.sendInitNotify(conn, remote, hdr, message.COOKIE, challenge, natt)
			return
		}
	}

	// Hard cap regardless of cookie validity: a verified cookie proves the
	// initiator can receive traffic at that address, not that there's room
	// in the half-open SA table.
	if load := s.saCount(); load >= s.maxHalfOpenSAs() {
		s.log.Warn("IKE_SA_INIT: half-open SA table full, rejecting", "remote", remote, "count", load)
		s.sendInitNotify(conn, remote, hdr, message.TEMPORARY_FAILURE, nil, natt)
		return
	}

	// SA proposal negotiation.
	prop, propNum, err := selectIKEProposal(saPayload)
	if err != nil {
		s.log.Info("IKE_SA_INIT: no acceptable proposal", "remote", remote)
		s.sendInitNotify(conn, remote, hdr, message.NO_PROPOSAL_CHOSEN, nil, natt)
		return
	}

	// Verify the KE DH group matches the selected proposal.
	// RFC 7296 §2.6.1: if wrong group, send INVALID_KE_PAYLOAD with correct group.
	if kePayload.DiffieHellmanGroup != prop.dh.TransformID() {
		groupBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(groupBytes, prop.dh.TransformID())
		s.log.Info("IKE_SA_INIT: wrong KE group",
			"got", kePayload.DiffieHellmanGroup,
			"want", prop.dh.TransformID(),
			"remote", remote)
		s.sendInitNotify(conn, remote, hdr, message.INVALID_KE_PAYLOAD, groupBytes, natt)
		return
	}

	// Generate responder SPI (8 random bytes).
	spiRBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, spiRBytes); err != nil {
		s.log.Error("IKE_SA_INIT: SPI gen failed", "err", err)
		return
	}
	spiR := binary.BigEndian.Uint64(spiRBytes)
	spiI := hdr.InitiatorSPI

	// Generate responder nonce (32 bytes, RFC 7296 §2.10).
	nonceR := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonceR); err != nil {
		s.log.Error("IKE_SA_INIT: nonce gen failed", "err", err)
		return
	}
	nonceI := noncePayload.NonceData

	// DH: our private key and public value.
	dhPriv, err := prop.dh.GeneratePrivateKey()
	if err != nil {
		s.log.Error("IKE_SA_INIT: DH keygen failed", "err", err)
		return
	}
	dhPub := prop.dh.PublicKey(dhPriv)

	// DH: shared secret from initiator's public value.
	dhShared, err := prop.dh.SharedKey(dhPriv, kePayload.KeyExchangeData)
	if err != nil {
		s.log.Warn("IKE_SA_INIT: DH shared key failed", "err", err, "remote", remote)
		s.sendInitNotify(conn, remote, hdr, message.INVALID_KE_PAYLOAD, nil, natt)
		return
	}

	// NAT detection: if the initiator's NAT_DETECTION_SOURCE_IP hash doesn't
	// match what we'd compute for the remote address, NAT is present.
	natDetected := natt // already on 4500 → NAT known from the start
	if !natDetected {
		natDetected = detectNAT(notifyPayloads, remote, spiI, spiR)
	}

	// Derive all IKE SA keying material (RFC 7296 §2.14).
	concatenatedNonce := append(nonceI, nonceR...)
	saKey := &ikeSAKey{
		dh:    prop.dh,
		encr:  prop.encr,
		integ: prop.integ,
		prf:   prop.prf,
	}
	if err := saKey.deriveKeys(concatenatedNonce, dhShared, spiI, spiR); err != nil {
		s.log.Error("IKE_SA_INIT: key derivation failed", "err", err)
		return
	}

	// Build IKE_SA_INIT response.
	var payloads message.IKEPayloadContainer

	// SA payload — single proposal with selected transforms.
	sa := payloads.BuildSecurityAssociation()
	p := sa.Proposals.BuildProposal(propNum, message.TypeIKE, nil)
	p.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, prop.dh.TransformID(), nil, nil, nil)
	keyBits := uint16(prop.encr.keyBits)
	attrType := uint16(message.AttributeTypeKeyLength)
	p.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, prop.encr.id, &attrType, &keyBits, nil)
	if prop.integ != nil {
		p.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, prop.integ.id, nil, nil, nil)
	}
	p.PseudorandomFunction.BuildTransform(message.TypePseudorandomFunction, prop.prf.id, nil, nil, nil)

	// KE payload.
	payloads.BuildKeyExchange(prop.dh.TransformID(), dhPub)

	// Nonce payload.
	payloads.BuildNonce(nonceR)

	// NAT detection notifies (RFC 7296 §2.23).
	localUDPAddr := conn.LocalAddr().(*net.UDPAddr)
	payloads.BuildNotification(message.TypeNone, message.NAT_DETECTION_SOURCE_IP, nil,
		natHash(spiI, spiR, localUDPAddr.IP, uint16(localUDPAddr.Port)))
	payloads.BuildNotification(message.TypeNone, message.NAT_DETECTION_DESTINATION_IP, nil,
		natHash(spiI, spiR, remote.IP, uint16(remote.Port)))

	respMsg := message.NewMessage(spiI, spiR, message.IKE_SA_INIT, true, false, hdr.MessageID, payloads)
	respBytes, err := respMsg.Encode()
	if err != nil {
		s.log.Error("IKE_SA_INIT: encode failed", "err", err)
		return
	}

	// Store IKE SA before sending (avoids race if UE retransmits immediately).
	localIP, _ := xfrm.LocalIPFor(remote.IP)

	sa2 := &ikeSA{
		spiI:        spiI,
		spiR:        spiR,
		remoteAddr:  remote,
		natT:        natDetected,
		nonceI:      nonceI,
		nonceR:      nonceR,
		proposal:    prop,
		saKey:       saKey,
		dhPriv:      dhPriv,
		dhPub:       dhPub,
		initReqRaw:  pkt,
		initRespRaw: respBytes,
		state:       ikeStateAuth,
		createdAt:   time.Now(),
		lastSeen:    time.Now(),
		localIP:     localIP,
	}
	s.storeSA(sa2)
	s.send(conn, remote, respBytes, natt)

	s.log.Info("IKE_SA_INIT complete",
		"spi_i", spiI,
		"spi_r", spiR,
		"dh", prop.dh.TransformID(),
		"encr", prop.encr.id,
		"encr_bits", prop.encr.keyBits,
		"integ", prop.integID(),
		"prf", prop.prf.id,
		"nat", natDetected,
		"remote", remote)
}

// detectNAT checks the initiator's NAT_DETECTION_SOURCE_IP notify.
// Returns true if NAT is present between UE and ePDG.
// findNotifyData returns the NotificationData of the first notify of the
// given type, or nil if none is present.
func findNotifyData(notifies []*message.Notification, notifyType uint16) []byte {
	for _, n := range notifies {
		if n.NotifyMessageType == notifyType {
			return n.NotificationData
		}
	}
	return nil
}

func detectNAT(notifies []*message.Notification, remote *net.UDPAddr, spiI, spiR uint64) bool {
	for _, n := range notifies {
		if n.NotifyMessageType != message.NAT_DETECTION_SOURCE_IP {
			continue
		}
		expected := natHash(spiI, spiR, remote.IP, uint16(remote.Port))
		if len(n.NotificationData) != len(expected) {
			return true
		}
		for i := range expected {
			if n.NotificationData[i] != expected[i] {
				return true
			}
		}
	}
	return false
}

// natAddrBytes returns the native byte form of ip: 4 bytes for IPv4, 16 for IPv6.
func natAddrBytes(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// natHash computes SHA1(SPI_i | SPI_r | IP | Port) per RFC 7296 §3.10.1.
// IP is hashed as 4 bytes for IPv4 or 16 bytes for IPv6 — the buffer is sized
// to match, since a fixed IPv4-only size would silently truncate a v6 address
// and corrupt the trailing port field.
func natHash(spiI, spiR uint64, ip net.IP, port uint16) []byte {
	addr := natAddrBytes(ip)
	buf := make([]byte, 16+len(addr)+2)
	binary.BigEndian.PutUint64(buf[0:], spiI)
	binary.BigEndian.PutUint64(buf[8:], spiR)
	copy(buf[16:], addr)
	binary.BigEndian.PutUint16(buf[16+len(addr):], port)
	h := sha1.New()
	h.Write(buf)
	return h.Sum(nil)
}

// sendInitNotify sends an IKE_SA_INIT error response with a single notify.
func (s *Server) sendInitNotify(conn *net.UDPConn, remote *net.UDPAddr, reqHdr *message.IKEHeader, notifyType uint16, data []byte, natt bool) {
	var payloads message.IKEPayloadContainer
	payloads.BuildNotification(message.TypeNone, notifyType, nil, data)
	resp := message.NewMessage(reqHdr.InitiatorSPI, 0, message.IKE_SA_INIT, true, false, reqHdr.MessageID, payloads)
	b, err := resp.Encode()
	if err != nil {
		s.log.Error("sendInitNotify encode failed", "err", err)
		return
	}
	s.send(conn, remote, b, natt)
}
