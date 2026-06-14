package s2b

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

const (
	gtpv2VersionFlag      byte   = 0x40
	gtpv2TEIDFlag         byte   = 0x08
	msgEchoRequest        uint8  = 1
	msgEchoResponse       uint8  = 2
	msgCreateSessionReq   uint8  = 32
	msgCreateSessionResp  uint8  = 33
	msgDeleteSessionReq   uint8  = 36
	msgDeleteSessionResp  uint8  = 37
	msgCreateBearerReq    uint8  = 95
	msgCreateBearerResp   uint8  = 96
	msgUpdateBearerReq    uint8  = 97
	msgUpdateBearerResp   uint8  = 98
	msgDeleteBearerReq    uint8  = 99
	msgDeleteBearerResp   uint8  = 100
	minSequence           uint32 = 0x000001
	maxSequence           uint32 = 0xffffff
	defaultGTPControlPort        = 2123
)

const (
	ieIMSI           uint8 = 1
	ieCause          uint8 = 2
	ieRecovery       uint8 = 3
	ieAPN            uint8 = 71
	ieAMBR           uint8 = 72
	ieEBI            uint8 = 73
	ieIndication     uint8 = 77 // TS 29.274 §8.12
	iePAA            uint8 = 79
	ieBearerQoS      uint8 = 80
	ieTFT            uint8 = 84
	ieRATType        uint8 = 82
	ieServingNetwork uint8 = 83
	ieFTEID          uint8 = 87
	ieBearerContext  uint8 = 93
	ieChargingID     uint8 = 94
	ieSelectionMode  uint8 = 128
	iePCO            uint8 = 78
	ieAPCO           uint8 = 163
)

const (
	causeReactivationRequested uint8 = 8  // generic reactivation (not used for access handover)
	causeAccessChangedTo3GPP   uint8 = 10 // TS 29.274 Table 8.4-1: Access changed from Non-3GPP to 3GPP (VoWiFi→VoLTE)
	causeRequestAccepted       uint8 = 16
	causeContextNotFound       uint8 = 64
	ratTypeWLAN          uint8 = 3
	pdnTypeIPv4          uint8 = 1
	ifaceS5S8SGWGTPU     uint8 = 4
	ifaceS5S8PGWGTPU     uint8 = 5
	ifaceS2BePDGGTPC     uint8 = 30
	ifaceS2BePDGGTPU     uint8 = 31
	ifaceS2BPGWGTPC      uint8 = 32
	ifaceS2BPGWGTPU      uint8 = 33
	defaultEBI           uint8 = 5
	defaultBearerQCI     uint8 = 8

	// Create Bearer Response Bearer Context: the ePDG's S2b GTP-U endpoint.
	// Cisco StarOS requires instance 8 for the S2b-U ePDG F-TEID (verified against live PGW).
	instanceCreateBearerResponseS2bEPDGDataFTEID uint8 = 8
)

type message struct {
	Type     uint8
	TEID     uint32
	HasTEID  bool
	Sequence uint32
	Payload  []byte
}

type ie struct {
	Type     uint8
	Instance uint8
	Payload  []byte
}

type decodedIE struct {
	ie
	Offset int
	Length int
	Raw    []byte
}

type sequenceAllocator struct {
	seq atomic.Uint32
	// cap holds the effective maximum sequence number for this allocator.
	// When zero, next() falls back to the package-level maxSequence constant.
	cap uint32
}

func newSequenceAllocator() *sequenceAllocator {
	return newSequenceAllocatorWithMax(maxSequence)
}

// newSequenceAllocatorWithMax creates an allocator capped at max.
// Use this for PGW interop overrides (e.g. Cisco StarOS requires max=0x7FFFFF).
func newSequenceAllocatorWithMax(max uint32) *sequenceAllocator {
	if max == 0 || max > maxSequence {
		max = maxSequence
	}
	a := &sequenceAllocator{cap: max}
	a.seq.Store(randomSequenceMax(max))
	return a
}

func (a *sequenceAllocator) next() uint32 {
	cap := a.cap
	if cap == 0 {
		cap = maxSequence
	}
	for {
		cur := a.seq.Load()
		next := cur + 1
		if next == 0 || next > cap {
			next = minSequence
		}
		if a.seq.CompareAndSwap(cur, next) {
			return next
		}
	}
}

func randomSequence() uint32 {
	return randomSequenceMax(maxSequence)
}

func randomSequenceMax(max uint32) uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return minSequence
	}
	n := binary.BigEndian.Uint32(b[:]) & max
	if n == 0 {
		return minSequence
	}
	return n
}

func randUint32() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 1
		}
		if v := binary.BigEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}

func (m message) encode() ([]byte, error) {
	if m.Sequence < minSequence || m.Sequence > maxSequence {
		return nil, fmt.Errorf("GTPv2-C sequence %d outside range", m.Sequence)
	}
	headerLen := 8
	flags := gtpv2VersionFlag
	if m.HasTEID {
		flags |= gtpv2TEIDFlag
		headerLen = 12
	}
	length := headerLen - 4 + len(m.Payload)
	if length > 0xffff {
		return nil, fmt.Errorf("GTPv2-C message too large: %d", length)
	}
	out := make([]byte, headerLen+len(m.Payload))
	out[0] = flags
	out[1] = m.Type
	binary.BigEndian.PutUint16(out[2:4], uint16(length))
	offset := 4
	if m.HasTEID {
		binary.BigEndian.PutUint32(out[offset:offset+4], m.TEID)
		offset += 4
	}
	put24(out[offset:offset+3], m.Sequence)
	offset += 4
	copy(out[offset:], m.Payload)
	return out, nil
}

func decodeMessage(b []byte) (message, error) {
	if len(b) < 8 {
		return message{}, fmt.Errorf("GTPv2-C message too short: %d", len(b))
	}
	if b[0]&0xe0 != gtpv2VersionFlag {
		return message{}, fmt.Errorf("unsupported GTP version flags 0x%02x", b[0])
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length != len(b)-4 {
		return message{}, fmt.Errorf("GTPv2-C length %d does not match packet length %d", length, len(b)-4)
	}
	msg := message{Type: b[1], HasTEID: b[0]&gtpv2TEIDFlag != 0}
	offset := 4
	if msg.HasTEID {
		if len(b) < 12 {
			return message{}, fmt.Errorf("GTPv2-C TEID message too short: %d", len(b))
		}
		msg.TEID = binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
	}
	msg.Sequence = read24(b[offset : offset+3])
	offset += 4
	msg.Payload = append([]byte(nil), b[offset:]...)
	return msg, nil
}

func (e ie) encode() []byte {
	out := make([]byte, 4+len(e.Payload))
	out[0] = e.Type
	binary.BigEndian.PutUint16(out[1:3], uint16(len(e.Payload)))
	out[3] = e.Instance & 0x0f
	copy(out[4:], e.Payload)
	return out
}

func encodeIEs(ies ...ie) []byte {
	var out []byte
	for _, e := range ies {
		out = append(out, e.encode()...)
	}
	return out
}

func decodeIEs(payload []byte) ([]ie, error) {
	var out []ie
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, fmt.Errorf("GTPv2-C IE header truncated")
		}
		l := int(binary.BigEndian.Uint16(payload[1:3]))
		if len(payload) < 4+l {
			return nil, fmt.Errorf("GTPv2-C IE %d length %d exceeds remaining %d", payload[0], l, len(payload)-4)
		}
		out = append(out, ie{Type: payload[0], Instance: payload[3] & 0x0f, Payload: append([]byte(nil), payload[4:4+l]...)})
		payload = payload[4+l:]
	}
	return out, nil
}

func decodeIEsWithRaw(payload []byte) ([]decodedIE, error) {
	var out []decodedIE
	offset := 0
	for offset < len(payload) {
		remaining := payload[offset:]
		if len(remaining) < 4 {
			return nil, fmt.Errorf("GTPv2-C IE header truncated")
		}
		l := int(binary.BigEndian.Uint16(remaining[1:3]))
		end := offset + 4 + l
		if end > len(payload) {
			return nil, fmt.Errorf("GTPv2-C IE %d length %d exceeds remaining %d", remaining[0], l, len(remaining)-4)
		}
		raw := append([]byte(nil), payload[offset:end]...)
		out = append(out, decodedIE{
			ie: ie{
				Type:     remaining[0],
				Instance: remaining[3] & 0x0f,
				Payload:  append([]byte(nil), remaining[4:4+l]...),
			},
			Offset: offset,
			Length: l,
			Raw:    raw,
		})
		offset = end
	}
	return out, nil
}

func findIE(ies []ie, typ, instance uint8) (ie, bool) {
	for _, e := range ies {
		if e.Type == typ && e.Instance == instance {
			return e, true
		}
	}
	return ie{}, false
}

func findIEAnyInstance(ies []ie, typ uint8) (ie, bool) {
	for _, e := range ies {
		if e.Type == typ {
			return e, true
		}
	}
	return ie{}, false
}

func ieTypes(ies []ie) []uint8 {
	out := make([]uint8, 0, len(ies))
	for _, e := range ies {
		out = append(out, e.Type)
	}
	return out
}

func ieTypesFromDecoded(ies []decodedIE) []uint8 {
	out := make([]uint8, 0, len(ies))
	for _, e := range ies {
		out = append(out, e.Type)
	}
	return out
}

func bcdIE(typ uint8, value string) ie {
	return ie{Type: typ, Payload: encodeTBCD(value)}
}

func apnIE(apn string) ie {
	labels := strings.Split(apn, ".")
	var payload []byte
	for _, label := range labels {
		if label == "" {
			continue
		}
		payload = append(payload, byte(len(label)))
		payload = append(payload, []byte(label)...)
	}
	return ie{Type: ieAPN, Payload: payload}
}

func uint8IE(typ, v uint8) ie {
	return ie{Type: typ, Payload: []byte{v}}
}

func ebiValueIE(v uint8) ie {
	return ie{Type: ieEBI, Payload: []byte{v & 0x0f}}
}

func parseEBI(payload []byte) (uint8, error) {
	if len(payload) == 0 {
		return 0, fmt.Errorf("EBI IE payload too short: len=0")
	}
	ebi := payload[0] & 0x0f
	if ebi == 0 {
		return 0, fmt.Errorf("invalid EBI value 0 raw=%02x", payload[0])
	}
	return ebi, nil
}

func recoveryIE(restartCounter uint8) ie {
	return uint8IE(ieRecovery, restartCounter)
}

func ambrIE(uplinkKbps, downlinkKbps uint32) ie {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], uplinkKbps)
	binary.BigEndian.PutUint32(payload[4:8], downlinkKbps)
	return ie{Type: ieAMBR, Payload: payload}
}

func bearerQoSIE(qci uint8) ie {
	payload := make([]byte, 22)
	payload[0] = 0x68
	payload[1] = qci
	return ie{Type: ieBearerQoS, Payload: payload}
}

func fteidIE(instance, iface uint8, teid uint32, ip net.IP) ie {
	ip4 := ip.To4()
	payload := make([]byte, 5, 9)
	payload[0] = 0x80 | (iface & 0x3f)
	binary.BigEndian.PutUint32(payload[1:5], teid)
	if ip4 != nil {
		payload = append(payload, ip4...)
	}
	return ie{Type: ieFTEID, Instance: instance, Payload: payload}
}

func paaIPv4RequestIE() ie {
	return ie{Type: iePAA, Payload: []byte{pdnTypeIPv4, 0, 0, 0, 0}}
}

func servingNetworkIE(mcc, mnc string) ie {
	return ie{Type: ieServingNetwork, Payload: encodePLMN(mcc, mnc)}
}

func parseCause(ies []ie) uint8 {
	causeIE, ok := findIE(ies, ieCause, 0)
	if !ok || len(causeIE.Payload) == 0 {
		return 0
	}
	return causeIE.Payload[0]
}

func parseRecovery(ies []ie) uint8 {
	rec, ok := findIE(ies, ieRecovery, 0)
	if !ok || len(rec.Payload) == 0 {
		return 0
	}
	return rec.Payload[0]
}

func parsePAA(ies []ie) net.IP {
	paa, ok := findIE(ies, iePAA, 0)
	if !ok || len(paa.Payload) < 5 || paa.Payload[0]&0x07 != pdnTypeIPv4 {
		return nil
	}
	return net.IPv4(paa.Payload[1], paa.Payload[2], paa.Payload[3], paa.Payload[4])
}

func parseFTEID(e ie) (uint8, uint32, net.IP, bool) {
	if len(e.Payload) < 5 {
		return 0, 0, nil, false
	}
	iface := e.Payload[0] & 0x3f
	teid := binary.BigEndian.Uint32(e.Payload[1:5])
	if e.Payload[0]&0x80 == 0 || len(e.Payload) < 9 {
		return iface, teid, nil, true
	}
	return iface, teid, net.IPv4(e.Payload[5], e.Payload[6], e.Payload[7], e.Payload[8]), true
}

func encodeTBCD(value string) []byte {
	digits := make([]byte, 0, len(value))
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits = append(digits, byte(r-'0'))
		}
	}
	out := make([]byte, (len(digits)+1)/2)
	for i := range out {
		lo := digits[i*2]
		hi := byte(0x0f)
		if i*2+1 < len(digits) {
			hi = digits[i*2+1]
		}
		out[i] = lo | hi<<4
	}
	return out
}

func encodePLMN(mcc, mnc string) []byte {
	mnc3 := byte(0x0f)
	if len(mnc) == 3 {
		mnc3 = digitNibble(mnc[2])
	}
	return []byte{
		digitNibble(mcc[0]) | digitNibble(mcc[1])<<4,
		digitNibble(mcc[2]) | mnc3<<4,
		digitNibble(mnc[0]) | digitNibble(mnc[1])<<4,
	}
}

func digitNibble(b byte) byte {
	if b >= '0' && b <= '9' {
		return b - '0'
	}
	return 0x0f
}

func put24(dst []byte, v uint32) {
	dst[0] = byte(v >> 16)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v)
}

func read24(src []byte) uint32 {
	return uint32(src[0])<<16 | uint32(src[1])<<8 | uint32(src[2])
}
