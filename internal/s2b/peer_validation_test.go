package s2b

// Regression tests for unauthenticated S2b GTPv2-C peer spoofing (TS 29.274
// §4.1/4.2 identify a GTP tunnel by TEID, IP address, and UDP port). Before
// the fix, pending responses were matched by sequence number alone, and
// network-initiated requests (Delete/Create/Update Bearer) were dispatched
// without any check that they came from the PGW the session was established
// with. Both tests below use two distinct loopback addresses to stand in for
// the real PGW and an off-path attacker.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

const (
	realPGWIP  = "127.0.0.1"
	attackerIP = "127.0.0.2"
)

// newReadLoopTestClient builds a Client with a real loopback socket and runs
// its readLoop, without going through Start() (which binds to the fixed
// GTP-C port on a configured production address).
func newReadLoopTestClient(t *testing.T) (*Client, context.Context) {
	t.Helper()
	c := NewClient(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(realPGWIP)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	c.conn = conn

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.readLoop(ctx)
	return c, ctx
}

// newPeerSocket opens a UDP socket on the given loopback IP, used to act as
// either the legitimate PGW or an off-path attacker sending from a different
// source address.
func newPeerSocket(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatalf("listen %s: %v", ip, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestPendingResponseRejectsSpoofedPeer reproduces the spoofing gap: an
// attacker who knows (or guesses) the sequence number of an outstanding
// request used to be able to inject a fake response. With StrictPeerCheck
// (the default), only a response from the peer the request was actually
// sent to may satisfy the pending transaction.
func TestPendingResponseRejectsSpoofedPeer(t *testing.T) {
	c, ctx := newReadLoopTestClient(t)
	if !c.cfg.GTP.StrictPeerCheck {
		t.Fatal("test config must default to strict_peer_check=true")
	}

	attacker := newPeerSocket(t, attackerIP)
	realPGW := newPeerSocket(t, realPGWIP)

	const seq = 12345
	req := message{Type: msgCreateSessionReq, HasTEID: true, Sequence: seq, Payload: []byte{}}

	resultCh := make(chan message, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := c.transactionTo(ctx, req, msgCreateSessionResp, &net.UDPAddr{IP: net.ParseIP(realPGWIP), Port: realPGW.LocalAddr().(*net.UDPAddr).Port})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- resp
	}()

	// Give transactionTo time to register the pending transaction and send.
	time.Sleep(50 * time.Millisecond)

	// Attacker sends a forged response with the matching sequence number, but
	// from a different source address than the request was sent to.
	spoofed := message{Type: msgCreateSessionResp, HasTEID: true, Sequence: seq, Payload: []byte{0xAA}}
	spoofedBytes, err := spoofed.encode()
	if err != nil {
		t.Fatalf("encode spoofed response: %v", err)
	}
	if _, err := attacker.WriteToUDP(spoofedBytes, c.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send spoofed response: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Real PGW sends the genuine response, distinguishable by payload.
	genuine := message{Type: msgCreateSessionResp, HasTEID: true, Sequence: seq, Payload: []byte{0xBB}}
	genuineBytes, err := genuine.encode()
	if err != nil {
		t.Fatalf("encode genuine response: %v", err)
	}
	if _, err := realPGW.WriteToUDP(genuineBytes, c.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send genuine response: %v", err)
	}

	select {
	case resp := <-resultCh:
		if len(resp.Payload) != 1 || resp.Payload[0] != 0xBB {
			t.Fatalf("transactionTo() returned payload %x, want the genuine response (0xBB) — spoofed response (0xAA) was accepted", resp.Payload)
		}
	case err := <-errCh:
		t.Fatalf("transactionTo() error = %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("transactionTo() did not return — genuine response not delivered")
	}
}

// TestNetworkInitiatedRequestRejectsSpoofedPeer reproduces the second half of
// the gap: a Delete Session Request (or Create/Update/Delete Bearer Request)
// claiming our local control TEID must come from the PGW that session was
// established with, not from anyone who can reach the GTP-C port.
func TestNetworkInitiatedRequestRejectsSpoofedPeer(t *testing.T) {
	c, _ := newReadLoopTestClient(t)

	const localControlTEID = 0xC0FFEE01
	c.mu.Lock()
	c.sessionPeers[localControlTEID] = net.ParseIP(realPGWIP)
	c.mu.Unlock()

	events := make(chan DeleteSessionEvent, 2)
	c.SetDeleteSessionHandler(func(_ context.Context, e DeleteSessionEvent) {
		events <- e
	})

	attacker := newPeerSocket(t, attackerIP)
	realPGW := newPeerSocket(t, realPGWIP)

	send := func(conn *net.UDPConn, seq uint32) {
		t.Helper()
		req := message{Type: msgDeleteSessionReq, TEID: localControlTEID, HasTEID: true, Sequence: seq, Payload: []byte{}}
		b, err := req.encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := conn.WriteToUDP(b, c.conn.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	// Re-add the session entry after each send, since the (correct) handling
	// of a request — spoofed or genuine — that reaches handleDeleteSessionRequest
	// clears it; the spoofed one must never reach that point at all.
	send(attacker, 100)
	select {
	case e := <-events:
		t.Fatalf("Delete Session handler invoked for spoofed peer: %+v", e)
	case <-time.After(300 * time.Millisecond):
	}

	c.mu.Lock()
	c.sessionPeers[localControlTEID] = net.ParseIP(realPGWIP)
	c.mu.Unlock()

	send(realPGW, 101)
	select {
	case e := <-events:
		if e.LocalControlTEID != localControlTEID {
			t.Fatalf("event TEID = %x, want %x", e.LocalControlTEID, localControlTEID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Delete Session handler not invoked for genuine peer")
	}
}
