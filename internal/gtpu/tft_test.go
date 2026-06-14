package gtpu

import (
	"encoding/binary"
	"net"
	"testing"

	"vectorcore-epdg/internal/config"
)

// ===== TFT byte construction helpers per TS 24.008 §10.5.6.12 =====

const (
	tftOpCreate  = 0x01
	tftOpAdd     = 0x03
	tftOpReplace = 0x04
	tftOpDelete  = 0x02
	tftOpNoOp    = 0x06

	dirPreRel7       = 0x00
	dirUplink        = 0x01
	dirDownlink      = 0x02
	dirBidirectional = 0x03
)

// tftByte1 encodes the first TFT IE byte: opCode (bits 8-6), E=0 (bit 5), numFilters (bits 4-1).
func tftByte1(opCode uint8, numFilters int) byte {
	return (opCode << 5) | uint8(numFilters)
}

// filterHeaderByte encodes the first byte of a packet filter: direction (bits 6-5), id (bits 4-1).
func filterHeaderByte(direction, id uint8) byte {
	return (direction << 4) | (id & 0x0f)
}

// buildFilter constructs a packet filter: header | precedence | content length | content.
func buildFilter(direction, id, precedence uint8, content []byte) []byte {
	f := []byte{filterHeaderByte(direction, id), precedence, uint8(len(content))}
	return append(f, content...)
}

// Component type helpers per TS 24.008 Table 10.5.162.

func compIPv4Remote(ip net.IP, mask net.IPMask) []byte {
	c := []byte{0x10}
	c = append(c, ip.To4()...)
	return append(c, []byte(mask)...)
}

func compIPv4Local(ip net.IP, mask net.IPMask) []byte {
	c := []byte{0x18}
	c = append(c, ip.To4()...)
	return append(c, []byte(mask)...)
}

func compProtocol(proto uint8) []byte {
	return []byte{0x30, proto}
}

func compLocalPortSingle(port uint16) []byte {
	return []byte{0x40, byte(port >> 8), byte(port)}
}

func compLocalPortRange(lo, hi uint16) []byte {
	return []byte{0x41, byte(lo >> 8), byte(lo), byte(hi >> 8), byte(hi)}
}

func compRemotePortSingle(port uint16) []byte {
	return []byte{0x50, byte(port >> 8), byte(port)}
}

func compRemotePortRange(lo, hi uint16) []byte {
	return []byte{0x51, byte(lo >> 8), byte(lo), byte(hi >> 8), byte(hi)}
}

// ===== IPv4 packet construction helpers for matchesUplink tests =====

// makeIPv4UDP builds a minimal IPv4+UDP packet for testing.
// Ports occupy bytes 20-23 (IHL=5, no IP options).
func makeIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], 8)
	return pkt
}

// makeIPv4TCP builds a minimal IPv4+TCP packet for testing.
func makeIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

// makeIPv4ICMP builds a minimal IPv4+ICMP packet for testing.
func makeIPv4ICMP(srcIP, dstIP net.IP) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	return pkt
}

// ===== ParseTFT tests (TS 24.008 §10.5.6.12) =====

func TestParseTFT_CreateSingleIPv4RemoteAddress(t *testing.T) {
	remoteIP := net.ParseIP("192.168.1.0").To4()
	remoteMask := net.CIDRMask(24, 32)
	content := compIPv4Remote(remoteIP, remoteMask)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirUplink, 1, 128, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	if len(tft.Filters) != 1 {
		t.Fatalf("filter count = %d, want 1", len(tft.Filters))
	}
	f := tft.Filters[0]
	if f.ID != 1 {
		t.Errorf("ID = %d, want 1", f.ID)
	}
	if f.Direction != dirUplink {
		t.Errorf("Direction = %d, want %d (uplink)", f.Direction, dirUplink)
	}
	if f.Precedence != 128 {
		t.Errorf("Precedence = %d, want 128", f.Precedence)
	}
	if !f.RemoteIPv4.Equal(remoteIP) {
		t.Errorf("RemoteIPv4 = %s, want %s", f.RemoteIPv4, remoteIP)
	}
	if f.RemoteIPv4Mask.String() != remoteMask.String() {
		t.Errorf("RemoteIPv4Mask = %s, want %s", f.RemoteIPv4Mask, remoteMask)
	}
}

func TestParseTFT_IPv4LocalAddress(t *testing.T) {
	localIP := net.ParseIP("10.0.0.1").To4()
	localMask := net.CIDRMask(32, 32)
	content := compIPv4Local(localIP, localMask)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirUplink, 1, 10, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	f := tft.Filters[0]
	if !f.LocalIPv4.Equal(localIP) {
		t.Errorf("LocalIPv4 = %s, want %s", f.LocalIPv4, localIP)
	}
	if f.LocalIPv4Mask.String() != localMask.String() {
		t.Errorf("LocalIPv4Mask = %s, want %s", f.LocalIPv4Mask, localMask)
	}
}

func TestParseTFT_VoLTE_UDPRemotePortRange(t *testing.T) {
	// Typical VoWiFi RTP bearer: bidirectional, UDP, remote ports 49152-65535.
	// Per 3GPP TS 26.114 Table A.9 — dynamic RTP port range.
	content := append(compProtocol(17), compRemotePortRange(49152, 65535)...)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirBidirectional, 1, 8, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	if len(tft.Filters) != 1 {
		t.Fatalf("filter count = %d, want 1", len(tft.Filters))
	}
	f := tft.Filters[0]
	if f.Direction != dirBidirectional {
		t.Errorf("Direction = %d, want %d (bidirectional)", f.Direction, dirBidirectional)
	}
	if !f.HasProtocol || f.Protocol != 17 {
		t.Errorf("Protocol: has=%v val=%d, want has=true val=17 (UDP)", f.HasProtocol, f.Protocol)
	}
	if !f.HasRemotePort || f.RemotePortLo != 49152 || f.RemotePortHi != 65535 {
		t.Errorf("RemotePort: has=%v lo=%d hi=%d, want has=true lo=49152 hi=65535", f.HasRemotePort, f.RemotePortLo, f.RemotePortHi)
	}
}

func TestParseTFT_SIP_TCPSinglePort(t *testing.T) {
	// SIP over TCP: uplink, TCP, remote port 5060.
	content := append(compProtocol(6), compRemotePortSingle(5060)...)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirUplink, 2, 16, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	f := tft.Filters[0]
	if !f.HasProtocol || f.Protocol != 6 {
		t.Errorf("Protocol: has=%v val=%d, want has=true val=6 (TCP)", f.HasProtocol, f.Protocol)
	}
	if !f.HasRemotePort || f.RemotePortLo != 5060 || f.RemotePortHi != 5060 {
		t.Errorf("RemotePort: has=%v lo=%d hi=%d, want 5060-5060", f.HasRemotePort, f.RemotePortLo, f.RemotePortHi)
	}
}

func TestParseTFT_LocalPortRange(t *testing.T) {
	// Local port range (type 0x41): uplink source port constraint.
	content := compLocalPortRange(1024, 2048)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirUplink, 1, 20, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	f := tft.Filters[0]
	if !f.HasLocalPort || f.LocalPortLo != 1024 || f.LocalPortHi != 2048 {
		t.Errorf("LocalPort: has=%v lo=%d hi=%d, want has=true lo=1024 hi=2048", f.HasLocalPort, f.LocalPortLo, f.LocalPortHi)
	}
}

func TestParseTFT_LocalPortSingle(t *testing.T) {
	content := compLocalPortSingle(5060)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirBidirectional, 1, 10, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	f := tft.Filters[0]
	if !f.HasLocalPort || f.LocalPortLo != 5060 || f.LocalPortHi != 5060 {
		t.Errorf("LocalPort single: has=%v lo=%d hi=%d, want 5060-5060", f.HasLocalPort, f.LocalPortLo, f.LocalPortHi)
	}
}

func TestParseTFT_AllComponentTypes(t *testing.T) {
	// Combine all supported component types in one filter.
	var content []byte
	content = append(content, compIPv4Remote(net.ParseIP("203.0.113.0").To4(), net.CIDRMask(24, 32))...)
	content = append(content, compIPv4Local(net.ParseIP("10.0.0.1").To4(), net.CIDRMask(32, 32))...)
	content = append(content, compProtocol(17)...)
	content = append(content, compLocalPortRange(1024, 2048)...)
	content = append(content, compRemotePortRange(5000, 6000)...)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirBidirectional, 1, 10, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	if len(tft.Filters) != 1 {
		t.Fatalf("filter count = %d, want 1", len(tft.Filters))
	}
	f := tft.Filters[0]
	if f.RemoteIPv4 == nil {
		t.Error("RemoteIPv4 not parsed")
	}
	if f.LocalIPv4 == nil {
		t.Error("LocalIPv4 not parsed")
	}
	if !f.HasProtocol || f.Protocol != 17 {
		t.Errorf("Protocol: has=%v val=%d, want has=true val=17", f.HasProtocol, f.Protocol)
	}
	if !f.HasLocalPort || f.LocalPortLo != 1024 || f.LocalPortHi != 2048 {
		t.Errorf("LocalPort: has=%v lo=%d hi=%d, want 1024-2048", f.HasLocalPort, f.LocalPortLo, f.LocalPortHi)
	}
	if !f.HasRemotePort || f.RemotePortLo != 5000 || f.RemotePortHi != 6000 {
		t.Errorf("RemotePort: has=%v lo=%d hi=%d, want 5000-6000", f.HasRemotePort, f.RemotePortLo, f.RemotePortHi)
	}
}

func TestParseTFT_MultipleFilters(t *testing.T) {
	// Two filters with different precedence: UDP high ports (RTP) + TCP HTTPS.
	f1 := buildFilter(dirBidirectional, 1, 16, append(compProtocol(17), compRemotePortRange(49152, 65535)...))
	f2 := buildFilter(dirBidirectional, 2, 32, append(compProtocol(6), compRemotePortSingle(443)...))
	raw := append([]byte{tftByte1(tftOpCreate, 2)}, f1...)
	raw = append(raw, f2...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	if len(tft.Filters) != 2 {
		t.Fatalf("filter count = %d, want 2", len(tft.Filters))
	}
	if tft.Filters[0].ID != 1 || tft.Filters[1].ID != 2 {
		t.Errorf("filter IDs: %d, %d, want 1, 2", tft.Filters[0].ID, tft.Filters[1].ID)
	}
	if tft.Filters[0].Protocol != 17 {
		t.Errorf("filter[0] protocol = %d, want 17 (UDP)", tft.Filters[0].Protocol)
	}
	if tft.Filters[1].Protocol != 6 {
		t.Errorf("filter[1] protocol = %d, want 6 (TCP)", tft.Filters[1].Protocol)
	}
}

func TestParseTFT_AddOpCode_ParsesFilters(t *testing.T) {
	// Add packet filters to existing TFT (opcode 011 = 3).
	raw := append([]byte{tftByte1(tftOpAdd, 1)}, buildFilter(dirUplink, 3, 50, compProtocol(6))...)
	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	if len(tft.Filters) != 1 {
		t.Fatalf("filter count = %d, want 1", len(tft.Filters))
	}
}

func TestParseTFT_DeleteOpCode_ReturnsEmptyTFT(t *testing.T) {
	// Delete existing TFT (opcode 010 = 2) carries no filter list.
	raw := []byte{tftByte1(tftOpDelete, 0)}
	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	if len(tft.Filters) != 0 {
		t.Fatalf("filter count = %d, want 0 for delete opcode", len(tft.Filters))
	}
}

func TestParseTFT_NoOpOpCode_ReturnsEmptyTFT(t *testing.T) {
	// No TFT operation (opcode 110 = 6) — used when TFT stays unchanged.
	raw := []byte{tftByte1(tftOpNoOp, 0)}
	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	if len(tft.Filters) != 0 {
		t.Fatalf("filter count = %d, want 0 for no-op opcode", len(tft.Filters))
	}
}

func TestParseTFT_TruncatedInput(t *testing.T) {
	if _, err := ParseTFT(nil); err == nil {
		t.Error("expected error for nil input")
	}
	if _, err := ParseTFT([]byte{}); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseTFT_TruncatedFilterHeader(t *testing.T) {
	// TFT says 1 filter but body has only the header byte with no precedence/length.
	raw := []byte{tftByte1(tftOpCreate, 1), 0x11}
	if _, err := ParseTFT(raw); err == nil {
		t.Error("expected error for truncated filter header")
	}
}

func TestParseTFT_TruncatedComponentContent(t *testing.T) {
	// Content length field claims 9 bytes (IPv4 remote addr) but packet ends at 3.
	raw := []byte{tftByte1(tftOpCreate, 1), 0x11, 0x80, 0x09, 0x10, 0xC0, 0xA8}
	if _, err := ParseTFT(raw); err == nil {
		t.Error("expected error for truncated filter content")
	}
}

func TestParseTFT_SkipKnownOpaqueComponents(t *testing.T) {
	// SPI (0x60), TOS (0x70), flow label (0x80) are parsed and skipped
	// without error even when not stored in PacketFilter.
	var content []byte
	content = append(content, 0x60, 0x00, 0x00, 0x00, 0x01) // SPI=1
	content = append(content, 0x70, 0x10, 0xFF)              // TOS value=0x10 mask=0xFF
	content = append(content, 0x80, 0x00, 0x00, 0x01)        // flow label low 20 bits
	content = append(content, compProtocol(17)...)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirUplink, 1, 20, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	if !tft.Filters[0].HasProtocol || tft.Filters[0].Protocol != 17 {
		t.Error("protocol component after opaque components not parsed")
	}
}

// ===== tcpUDPPorts tests =====

func TestTCPUDPPorts_IPv4UDP(t *testing.T) {
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 53)
	src, dst, ok := tcpUDPPorts(pkt)
	if !ok {
		t.Fatal("tcpUDPPorts() ok=false, want true")
	}
	if src != 12345 {
		t.Errorf("src = %d, want 12345", src)
	}
	if dst != 53 {
		t.Errorf("dst = %d, want 53", dst)
	}
}

func TestTCPUDPPorts_IPv4TCP(t *testing.T) {
	pkt := makeIPv4TCP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 443, 8080)
	src, dst, ok := tcpUDPPorts(pkt)
	if !ok {
		t.Fatal("tcpUDPPorts() ok=false, want true")
	}
	if src != 443 {
		t.Errorf("src = %d, want 443", src)
	}
	if dst != 8080 {
		t.Errorf("dst = %d, want 8080", dst)
	}
}

func TestTCPUDPPorts_ICMP_ReturnsFalse(t *testing.T) {
	pkt := makeIPv4ICMP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"))
	if _, _, ok := tcpUDPPorts(pkt); ok {
		t.Error("tcpUDPPorts() ok=true for ICMP, want false")
	}
}

func TestTCPUDPPorts_TooShort_ReturnsFalse(t *testing.T) {
	if _, _, ok := tcpUDPPorts([]byte{0x45, 0x00}); ok {
		t.Error("tcpUDPPorts() ok=true for short packet, want false")
	}
}

// ===== matchesUplink tests (TS 24.008 §10.5.6.12 direction semantics) =====

func TestMatchesUplink_DirectionFiltering(t *testing.T) {
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 53)

	// Uplink-only (01): must match uplink traffic.
	fUp := PacketFilter{Direction: dirUplink}
	if !fUp.matchesUplink(pkt) {
		t.Error("uplink-only filter must match uplink packet")
	}

	// Bidirectional (11): must match uplink traffic.
	fBi := PacketFilter{Direction: dirBidirectional}
	if !fBi.matchesUplink(pkt) {
		t.Error("bidirectional filter must match uplink packet")
	}

	// Downlink-only (10): must NOT match uplink traffic.
	fDl := PacketFilter{Direction: dirDownlink}
	if fDl.matchesUplink(pkt) {
		t.Error("downlink-only filter must not match uplink packet")
	}

	// Pre-Rel-7 (00): treated as invalid for Rel-7+ uplink classification.
	fPre := PacketFilter{Direction: dirPreRel7}
	if fPre.matchesUplink(pkt) {
		t.Error("pre-Rel-7 direction (00) must not match in uplink classification")
	}
}

func TestMatchesUplink_IPv4RemoteAddress_ExactHost(t *testing.T) {
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("203.0.113.5"), 12345, 80)

	// Exact host match (/32).
	f := PacketFilter{
		Direction:      dirUplink,
		RemoteIPv4:     net.ParseIP("203.0.113.5").To4(),
		RemoteIPv4Mask: net.CIDRMask(32, 32),
	}
	if !f.matchesUplink(pkt) {
		t.Error("exact host /32 should match")
	}

	// Wrong host.
	f.RemoteIPv4 = net.ParseIP("203.0.113.6").To4()
	if f.matchesUplink(pkt) {
		t.Error("wrong host should not match")
	}
}

func TestMatchesUplink_IPv4RemoteAddress_Network(t *testing.T) {
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("203.0.113.5"), 12345, 80)

	// /24 network match.
	f := PacketFilter{
		Direction:      dirUplink,
		RemoteIPv4:     net.ParseIP("203.0.113.0").To4(),
		RemoteIPv4Mask: net.CIDRMask(24, 32),
	}
	if !f.matchesUplink(pkt) {
		t.Error("network /24 should match host in range")
	}

	// Different /24.
	f.RemoteIPv4 = net.ParseIP("203.0.114.0").To4()
	if f.matchesUplink(pkt) {
		t.Error("wrong /24 should not match")
	}
}

func TestMatchesUplink_Protocol_UDP(t *testing.T) {
	udpPkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 53)
	tcpPkt := makeIPv4TCP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 443)

	f := PacketFilter{Direction: dirUplink, HasProtocol: true, Protocol: 17}
	if !f.matchesUplink(udpPkt) {
		t.Error("UDP filter must match UDP packet")
	}
	if f.matchesUplink(tcpPkt) {
		t.Error("UDP filter must not match TCP packet")
	}
}

func TestMatchesUplink_Protocol_TCP(t *testing.T) {
	tcpPkt := makeIPv4TCP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 443)
	udpPkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 443)

	f := PacketFilter{Direction: dirUplink, HasProtocol: true, Protocol: 6}
	if !f.matchesUplink(tcpPkt) {
		t.Error("TCP filter must match TCP packet")
	}
	if f.matchesUplink(udpPkt) {
		t.Error("TCP filter must not match UDP packet")
	}
}

func TestMatchesUplink_Protocol_ICMP(t *testing.T) {
	// ICMP has no ports — a protocol-only filter still applies.
	pkt := makeIPv4ICMP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"))
	f := PacketFilter{Direction: dirUplink, HasProtocol: true, Protocol: 1}
	if !f.matchesUplink(pkt) {
		t.Error("ICMP filter must match ICMP packet")
	}
}

func TestMatchesUplink_LocalPort_Single(t *testing.T) {
	// Local port = source port for uplink direction.
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 5060, 53)

	f := PacketFilter{Direction: dirUplink, HasLocalPort: true, LocalPortLo: 5060, LocalPortHi: 5060}
	if !f.matchesUplink(pkt) {
		t.Error("exact local port match failed")
	}

	f.LocalPortLo, f.LocalPortHi = 5061, 5061
	if f.matchesUplink(pkt) {
		t.Error("wrong local port should not match")
	}
}

func TestMatchesUplink_LocalPort_Range(t *testing.T) {
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 1500, 53)

	f := PacketFilter{Direction: dirUplink, HasLocalPort: true, LocalPortLo: 1024, LocalPortHi: 2048}
	if !f.matchesUplink(pkt) {
		t.Error("local port in range should match")
	}

	pkt2 := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 1023, 53)
	if f.matchesUplink(pkt2) {
		t.Error("local port below range should not match")
	}

	pkt3 := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 2049, 53)
	if f.matchesUplink(pkt3) {
		t.Error("local port above range should not match")
	}
}

func TestMatchesUplink_LocalPort_RejectedOnNonTCPUDP(t *testing.T) {
	// Port filter on ICMP (no transport layer) must not match.
	pkt := makeIPv4ICMP(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"))
	f := PacketFilter{Direction: dirUplink, HasLocalPort: true, LocalPortLo: 0, LocalPortHi: 65535}
	if f.matchesUplink(pkt) {
		t.Error("port filter on ICMP packet must not match")
	}
}

func TestMatchesUplink_RemotePort_Single(t *testing.T) {
	// Remote port = destination port for uplink direction.
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 5004)

	f := PacketFilter{Direction: dirUplink, HasRemotePort: true, RemotePortLo: 5004, RemotePortHi: 5004}
	if !f.matchesUplink(pkt) {
		t.Error("exact remote port match failed")
	}

	f.RemotePortLo, f.RemotePortHi = 5005, 5005
	if f.matchesUplink(pkt) {
		t.Error("wrong remote port should not match")
	}
}

func TestMatchesUplink_RemotePort_Range(t *testing.T) {
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 50000)

	f := PacketFilter{Direction: dirUplink, HasRemotePort: true, RemotePortLo: 49152, RemotePortHi: 65535}
	if !f.matchesUplink(pkt) {
		t.Error("remote port in range should match")
	}

	pkt2 := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 49151)
	if f.matchesUplink(pkt2) {
		t.Error("remote port below range should not match")
	}
}

func TestMatchesUplink_CombinedFilter_AllCriteria(t *testing.T) {
	// All criteria must pass (AND semantics per TS 24.008 §10.5.6.12).
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("203.0.113.5"), 12345, 5004)

	f := PacketFilter{
		Direction:      dirUplink,
		RemoteIPv4:     net.ParseIP("203.0.113.0").To4(),
		RemoteIPv4Mask: net.CIDRMask(24, 32),
		HasProtocol:    true, Protocol: 17,
		HasRemotePort: true, RemotePortLo: 5000, RemotePortHi: 6000,
	}
	if !f.matchesUplink(pkt) {
		t.Error("all-criteria filter should match matching packet")
	}

	// Fail one criterion (wrong protocol) — whole filter must fail.
	tcpPkt := makeIPv4TCP(net.ParseIP("10.0.0.1"), net.ParseIP("203.0.113.5"), 12345, 5004)
	if f.matchesUplink(tcpPkt) {
		t.Error("wrong protocol should cause filter to not match")
	}
}

func TestMatchesUplink_VoWiFi_SIP_Filter(t *testing.T) {
	// VoWiFi SIP signaling: bidirectional, UDP, remote port 5060.
	sipPkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 49152, 5060)
	httpPkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 49152, 8080)

	f := PacketFilter{
		Direction:     dirBidirectional,
		HasProtocol:   true, Protocol: 17,
		HasRemotePort: true, RemotePortLo: 5060, RemotePortHi: 5060,
	}
	if !f.matchesUplink(sipPkt) {
		t.Error("SIP filter must match SIP/UDP packet")
	}
	if f.matchesUplink(httpPkt) {
		t.Error("SIP filter must not match HTTP packet")
	}
}

func TestMatchesUplink_RTP_Filter_ParsedFromWire(t *testing.T) {
	// End-to-end: parse a TFT from raw bytes, then classify a real RTP packet.
	content := append(compProtocol(17), compRemotePortRange(49152, 65535)...)
	raw := append([]byte{tftByte1(tftOpCreate, 1)}, buildFilter(dirBidirectional, 1, 8, content)...)

	tft, err := ParseTFT(raw)
	if err != nil {
		t.Fatalf("ParseTFT() error = %v", err)
	}
	f := tft.Filters[0]

	rtpPkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 50000)
	if !f.matchesUplink(rtpPkt) {
		t.Error("RTP filter must match RTP packet (dst port in 49152-65535)")
	}

	httpPkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 80)
	if f.matchesUplink(httpPkt) {
		t.Error("RTP filter must not match HTTP packet (dst port 80)")
	}
}

// ===== selectUplinkBearer tests =====

func newTestManager(tftEnabled bool) *Manager {
	return &Manager{
		cfg: config.Config{
			GTP: config.GTPConfig{
				DedicatedBearers: config.DedicatedBearerConfig{
					TFTUplinkSelection: tftEnabled,
				},
			},
		},
	}
}

func TestSelectUplinkBearer_TFTDisabled_AlwaysDefault(t *testing.T) {
	// When TFTUplinkSelection is false all uplink goes to the default bearer,
	// regardless of whether a dedicated bearer's TFT would match.
	m := newTestManager(false)
	ds := &Session{
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5},
			6: {EBI: 6, TFT: &TFT{Filters: []PacketFilter{{
				Direction: dirUplink, HasRemotePort: true, RemotePortLo: 49152, RemotePortHi: 65535,
			}}}},
		},
	}
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 50000)
	b := m.selectUplinkBearer(ds, pkt)
	if b.EBI != 5 {
		t.Errorf("EBI = %d, want 5 (default, TFT selection disabled)", b.EBI)
	}
}

func TestSelectUplinkBearer_NoMatchFallsToDefault(t *testing.T) {
	// When TFT is enabled but no filter matches, fall back to the default bearer.
	m := newTestManager(true)
	ds := &Session{
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5},
			6: {EBI: 6, TFT: &TFT{Filters: []PacketFilter{{
				Direction: dirUplink, HasProtocol: true, Protocol: 17,
				HasRemotePort: true, RemotePortLo: 49152, RemotePortHi: 65535,
			}}}},
		},
	}
	// TCP packet should not match the UDP filter.
	pkt := makeIPv4TCP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 443)
	b := m.selectUplinkBearer(ds, pkt)
	if b.EBI != 5 {
		t.Errorf("EBI = %d, want 5 (default fallback)", b.EBI)
	}
}

func TestSelectUplinkBearer_MatchesDedicatedBearer(t *testing.T) {
	// Matching packet is steered to dedicated bearer.
	m := newTestManager(true)
	ds := &Session{
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5},
			6: {EBI: 6, TFT: &TFT{Filters: []PacketFilter{{
				Direction: dirBidirectional, HasProtocol: true, Protocol: 17,
				HasRemotePort: true, RemotePortLo: 49152, RemotePortHi: 65535,
			}}}},
		},
	}
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 50000)
	b := m.selectUplinkBearer(ds, pkt)
	if b.EBI != 6 {
		t.Errorf("EBI = %d, want 6 (dedicated)", b.EBI)
	}
}

func TestSelectUplinkBearer_PrecedenceOrdering(t *testing.T) {
	// When multiple TFTs match, the filter with the lowest precedence value
	// (= highest priority per TS 24.008 §10.5.6.12) wins.
	m := newTestManager(true)
	ds := &Session{
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5},
			6: {EBI: 6, TFT: &TFT{Filters: []PacketFilter{{
				Direction: dirUplink, Precedence: 100,
				HasRemotePort: true, RemotePortLo: 49152, RemotePortHi: 65535,
			}}}},
			7: {EBI: 7, TFT: &TFT{Filters: []PacketFilter{{
				Direction: dirUplink, Precedence: 50, // higher priority (lower numeric value)
				HasRemotePort: true, RemotePortLo: 49152, RemotePortHi: 65535,
			}}}},
		},
	}
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 50000)
	b := m.selectUplinkBearer(ds, pkt)
	if b.EBI != 7 {
		t.Errorf("EBI = %d, want 7 (precedence 50 beats 100)", b.EBI)
	}
}

func TestSelectUplinkBearer_NilTFT_Skipped(t *testing.T) {
	// Dedicated bearer with nil TFT must not be selected.
	m := newTestManager(true)
	ds := &Session{
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5},
			6: {EBI: 6, TFT: nil},
		},
	}
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 50000)
	b := m.selectUplinkBearer(ds, pkt)
	if b.EBI != 5 {
		t.Errorf("EBI = %d, want 5 (nil TFT skipped)", b.EBI)
	}
}

func TestSelectUplinkBearer_EmptyTFT_Skipped(t *testing.T) {
	// Dedicated bearer with empty filter list must not be selected.
	m := newTestManager(true)
	ds := &Session{
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5},
			6: {EBI: 6, TFT: &TFT{}},
		},
	}
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 50000)
	b := m.selectUplinkBearer(ds, pkt)
	if b.EBI != 5 {
		t.Errorf("EBI = %d, want 5 (empty TFT skipped)", b.EBI)
	}
}

func TestSelectUplinkBearer_DownlinkFilter_NotSelected(t *testing.T) {
	// Dedicated bearer whose only filter has direction=downlink must not
	// be selected for uplink traffic (direction check in matchesUplink).
	m := newTestManager(true)
	ds := &Session{
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5},
			6: {EBI: 6, TFT: &TFT{Filters: []PacketFilter{{
				Direction: dirDownlink, HasProtocol: true, Protocol: 17,
			}}}},
		},
	}
	pkt := makeIPv4UDP(net.ParseIP("10.0.0.1"), net.ParseIP("10.10.10.1"), 12345, 50000)
	b := m.selectUplinkBearer(ds, pkt)
	if b.EBI != 5 {
		t.Errorf("EBI = %d, want 5 (downlink-only filter must not steer uplink)", b.EBI)
	}
}
