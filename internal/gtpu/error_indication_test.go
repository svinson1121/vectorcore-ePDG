package gtpu

// Tests for the TS 29.281 §7.3.1 fix (audit finding #9): a G-PDU for a TEID
// with no context must be discarded and, for non-zero TEID, answered with a
// GTP-U Error Indication — and that mechanism must itself be rate-limited
// so it can't be turned into a reflection/amplification primitive.

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func newTestManagerWithUDP(t *testing.T, localGTPU string) (*Manager, *net.UDPConn) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	m := &Manager{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		udp: conn,
	}
	m.cfg.GTP.LocalGTPU = localGTPU
	return m, conn
}

// buildGPDUControlPacket builds a minimal GTP-U G-PDU packet as it would
// arrive at the UDP control socket (no Ethernet/IP/UDP framing — that's
// already stripped by the kernel before the application read).
func buildGPDUControlPacket(teid uint32) []byte {
	pkt := make([]byte, 8+4)
	pkt[0] = 0x30 // version=1, PT=1
	pkt[1] = 255  // G-PDU
	binary.BigEndian.PutUint16(pkt[2:4], 4)
	binary.BigEndian.PutUint32(pkt[4:8], teid)
	return pkt
}

func TestHandleDownlinkUnknownTEIDSendsErrorIndication(t *testing.T) {
	m, _ := newTestManagerWithUDP(t, "10.90.250.57")

	ueListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ueListener.Close()
	peer := ueListener.LocalAddr().(*net.UDPAddr)

	const teid = uint32(0xdeadbeef)
	m.handleDownlink(buildGPDUControlPacket(teid), peer)

	buf := make([]byte, 256)
	_ = ueListener.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := ueListener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("did not receive Error Indication: %v", err)
	}
	verifyErrorIndication(t, buf[:n], teid, net.IPv4(10, 90, 250, 57))

	if got := m.Stats().ErrorIndicationsSent; got != 1 {
		t.Fatalf("ErrorIndicationsSent = %d, want 1", got)
	}
}

func TestHandleDownlinkZeroTEIDSendsNoErrorIndication(t *testing.T) {
	m, _ := newTestManagerWithUDP(t, "10.90.250.57")
	ueListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ueListener.Close()
	peer := ueListener.LocalAddr().(*net.UDPAddr)

	m.handleDownlink(buildGPDUControlPacket(0), peer)

	buf := make([]byte, 256)
	_ = ueListener.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = ueListener.ReadFromUDP(buf)
	if err == nil {
		t.Fatal("received an Error Indication for TEID 0, want none (TS 29.281 §7.3.1)")
	}
	if got := m.Stats().ErrorIndicationsSent; got != 0 {
		t.Fatalf("ErrorIndicationsSent = %d, want 0", got)
	}
}

func TestSendErrorIndicationRateLimited(t *testing.T) {
	m, conn := newTestManagerWithUDP(t, "10.90.250.57")
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	_ = conn

	now := time.Now()
	m.eiLimiter.windowStart = now
	for i := 0; i < errorIndicationMaxPerSecond; i++ {
		if !m.eiLimiter.allow(now) {
			t.Fatalf("allow() returned false within budget at i=%d", i)
		}
	}
	if m.eiLimiter.allow(now) {
		t.Fatal("allow() returned true past the per-second budget")
	}

	// Sending past budget must not increment ErrorIndicationsSent and must
	// increment ErrorIndicationsRateLimited.
	m.sendErrorIndication(123, peer)
	if got := m.Stats().ErrorIndicationsSent; got != 0 {
		t.Fatalf("ErrorIndicationsSent = %d, want 0 (still rate-limited)", got)
	}
	if got := m.Stats().ErrorIndicationsRateLimited; got != 1 {
		t.Fatalf("ErrorIndicationsRateLimited = %d, want 1", got)
	}

	// A new window must allow traffic again.
	later := now.Add(2 * time.Second)
	if !m.eiLimiter.allow(later) {
		t.Fatal("allow() returned false in a new window")
	}
}

func verifyErrorIndication(t *testing.T, raw []byte, wantTEID uint32, wantPeerAddr net.IP) {
	t.Helper()
	if len(raw) < 12 {
		t.Fatalf("Error Indication too short: %d bytes", len(raw))
	}
	if raw[0]&gtpuFlagS == 0 {
		t.Fatalf("S flag not set in GTP-U header (TS 29.281 §4.4.3.4 requires it for Error Indication)")
	}
	if raw[1] != gtpuMsgErrorIndication {
		t.Fatalf("message type = %d, want %d (Error Indication)", raw[1], gtpuMsgErrorIndication)
	}
	if teid := binary.BigEndian.Uint32(raw[4:8]); teid != 0 {
		t.Fatalf("header TEID = %d, want 0 (TS 29.281: Error Indication TEID shall be all zeros)", teid)
	}

	payload := raw[12:]
	if len(payload) < 5 || payload[0] != ieTypeTEIDDataI {
		t.Fatalf("missing/wrong Tunnel Endpoint Identifier Data I IE: %x", payload)
	}
	gotTEID := binary.BigEndian.Uint32(payload[1:5])
	if gotTEID != wantTEID {
		t.Fatalf("TEID Data I = %d, want %d", gotTEID, wantTEID)
	}

	rest := payload[5:]
	if len(rest) < 7 || rest[0] != ieTypeGTPUPeerAddr {
		t.Fatalf("missing/wrong GTP-U Peer Address IE: %x", rest)
	}
	length := binary.BigEndian.Uint16(rest[1:3])
	if length != 4 {
		t.Fatalf("GTP-U Peer Address length = %d, want 4 (IPv4)", length)
	}
	gotAddr := net.IP(rest[3:7])
	if !gotAddr.Equal(wantPeerAddr) {
		t.Fatalf("GTP-U Peer Address = %s, want %s", gotAddr, wantPeerAddr)
	}
}
