package gtpu

import (
	"net"
	"testing"
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
	content = append(content, 0x70, 0x10, 0xFF)             // TOS value=0x10 mask=0xFF
	content = append(content, 0x80, 0x00, 0x00, 0x01)       // flow label low 20 bits
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
func TestBuildTCBPFTFTRules_RemotePAASelectorRemainsDestinationMatch(t *testing.T) {
	paa := net.ParseIP("10.150.3.157").To4()
	ds := &Session{
		PAA:        paa,
		DefaultEBI: 5,
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5, RemoteTXTEID: 100},
			6: {
				EBI:          6,
				RemoteTXTEID: 200,
				TFT: &TFT{Filters: []PacketFilter{{
					Direction:      dirBidirectional,
					Precedence:     48,
					RemoteIPv4:     paa,
					RemoteIPv4Mask: net.CIDRMask(32, 32),
					HasProtocol:    true,
					Protocol:       17,
				}}},
			},
		},
	}

	rules := buildTCBPFTFTRules(ds, true)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Flags&tcTFTFlagRemoteIP == 0 {
		t.Fatalf("remote IP flag not set for UE PAA selector: flags=0x%02x", rules[0].Flags)
	}
	if got := net.IP(rules[0].RemoteIP[:]); !got.Equal(paa) {
		t.Fatalf("remote IP = %s, want %s", got, paa)
	}
	if rules[0].Flags&tcTFTFlagProtocol == 0 {
		t.Fatalf("protocol flag not set: flags=0x%02x", rules[0].Flags)
	}
	if rules[0].TEID != 200 {
		t.Fatalf("TEID = %d, want 200", rules[0].TEID)
	}
}
