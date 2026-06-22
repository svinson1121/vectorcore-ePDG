package gtpu

// Packet-level test for the TS 29.281 §4.3.0 fix (audit finding #8): the XDP
// downlink decap program must drop a G-PDU whose outer IP source doesn't
// match the PGW address that TEID was installed with, when outer-peer
// validation is enabled — and must behave exactly as before (PAA-gated
// XDP_PASS) when it's disabled, preserving existing non-strict deployments.
//
// Runs the actual compiled gtpu_decap_func via BPF_PROG_TEST_RUN
// (Program.Test), not a Go-side simulation, so it exercises the real
// teid_map/config_map layout and verdict logic.

import (
	"encoding/binary"
	"net"
	"testing"
)

const (
	xdpActionDrop = 1
	xdpActionPass = 2
)

// buildGPDU constructs a minimal Ethernet+IPv4+UDP+GTPv1-U+inner-IPv4 G-PDU
// frame with the given outer source IP, TEID, and inner destination IP.
func buildGPDU(t *testing.T, outerSrc, outerDst net.IP, teid uint32, innerDst net.IP) []byte {
	t.Helper()
	pkt := make([]byte, 14+20+8+8+20)

	// Ethernet: arbitrary MACs, EtherType IPv4.
	pkt[12], pkt[13] = 0x08, 0x00

	ip := pkt[14:34]
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(pkt)-14))
	ip[8] = 64 // TTL
	ip[9] = 17 // UDP
	copy(ip[12:16], outerSrc.To4())
	copy(ip[16:20], outerDst.To4())

	udp := pkt[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 2152)
	binary.BigEndian.PutUint16(udp[2:4], 2152)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(pkt)-34))

	gtp := pkt[42:50]
	gtp[0] = 0x30 // version=1, PT=1, E=S=PN=0
	gtp[1] = 255  // G-PDU
	binary.BigEndian.PutUint16(gtp[2:4], 20)
	binary.BigEndian.PutUint32(gtp[4:8], teid)

	inner := pkt[50:70]
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], 20)
	inner[8] = 64
	copy(inner[12:16], outerSrc.To4()) // irrelevant, just needs to be present
	copy(inner[16:20], innerDst.To4())

	return pkt
}

func loadTestGtpuDecap(t *testing.T) *GtpuDecapObjects {
	t.Helper()
	var objs GtpuDecapObjects
	if err := LoadGtpuDecapObjects(&objs, nil); err != nil {
		t.Fatalf("LoadGtpuDecapObjects() error = %v (requires root/CAP_BPF)", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

func TestXDPDropsGPDUFromUnexpectedPeerWhenEnforced(t *testing.T) {
	objs := loadTestGtpuDecap(t)

	localIP := net.IPv4(10, 90, 250, 57)
	pgwIP := net.IPv4(10, 90, 250, 92)
	attackerIP := net.IPv4(203, 0, 113, 50)
	paa := net.IPv4(10, 45, 0, 7)
	const teid = uint32(0x1000)

	if err := objs.ConfigMap.Put(configKeyLocalIP, binary.LittleEndian.Uint32(localIP.To4())); err != nil {
		t.Fatalf("write config_map local IP: %v", err)
	}
	if err := objs.ConfigMap.Put(configKeyValidatePeer, uint32(1)); err != nil {
		t.Fatalf("write config_map validate-peer flag: %v", err)
	}
	entry := GtpuDecapTeidEntry{}
	copy(entry.Paa[:], paa.To4())
	copy(entry.PgwAddr[:], pgwIP.To4())
	if err := objs.TeidMap.Put(teid, entry); err != nil {
		t.Fatalf("write teid_map: %v", err)
	}

	spoofed := buildGPDU(t, attackerIP, localIP, teid, paa)
	ret, _, err := objs.GtpuDecapFunc.Test(spoofed)
	if err != nil {
		t.Fatalf("Program.Test() error = %v", err)
	}
	if ret != xdpActionDrop {
		t.Fatalf("verdict for spoofed-peer G-PDU = %d, want XDP_DROP (%d)", ret, xdpActionDrop)
	}

	legit := buildGPDU(t, pgwIP, localIP, teid, paa)
	ret, _, err = objs.GtpuDecapFunc.Test(legit)
	if err != nil {
		t.Fatalf("Program.Test() error = %v", err)
	}
	if ret != xdpActionPass {
		t.Fatalf("verdict for legitimate-peer G-PDU = %d, want XDP_PASS (%d)", ret, xdpActionPass)
	}
}

func TestXDPAcceptsAnyPeerWhenValidationDisabled(t *testing.T) {
	objs := loadTestGtpuDecap(t)

	localIP := net.IPv4(10, 90, 250, 57)
	pgwIP := net.IPv4(10, 90, 250, 92)
	attackerIP := net.IPv4(203, 0, 113, 50)
	paa := net.IPv4(10, 45, 0, 7)
	const teid = uint32(0x2000)

	if err := objs.ConfigMap.Put(configKeyLocalIP, binary.LittleEndian.Uint32(localIP.To4())); err != nil {
		t.Fatalf("write config_map local IP: %v", err)
	}
	if err := objs.ConfigMap.Put(configKeyValidatePeer, uint32(0)); err != nil {
		t.Fatalf("write config_map validate-peer flag: %v", err)
	}
	entry := GtpuDecapTeidEntry{}
	copy(entry.Paa[:], paa.To4())
	copy(entry.PgwAddr[:], pgwIP.To4())
	if err := objs.TeidMap.Put(teid, entry); err != nil {
		t.Fatalf("write teid_map: %v", err)
	}

	pkt := buildGPDU(t, attackerIP, localIP, teid, paa)
	ret, _, err := objs.GtpuDecapFunc.Test(pkt)
	if err != nil {
		t.Fatalf("Program.Test() error = %v", err)
	}
	if ret != xdpActionPass {
		t.Fatalf("verdict with validation disabled = %d, want XDP_PASS (%d) — non-strict mode must still decap", ret, xdpActionPass)
	}
}
