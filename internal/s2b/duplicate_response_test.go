package s2b

// Regression test for audit finding #10: the pending-response channel has
// capacity one, and readLoop is the sole goroutine reading from the GTP-C
// socket. Before the fix, a duplicate response for an already-claimed
// sequence number could be sent into an already-full channel and block
// readLoop forever, since nothing was deleting the pending-table entry
// before delivery. This deterministically reproduces that by registering a
// pending transaction whose channel nothing ever drains, then sending two
// responses for it — the second must be dropped, not block readLoop.

import (
	"net"
	"testing"
	"time"
)

func TestDuplicateResponseDoesNotBlockReadLoop(t *testing.T) {
	c, _ := newReadLoopTestClient(t)
	realPGW := newPeerSocket(t, realPGWIP)
	pgwAddr := &net.UDPAddr{IP: net.ParseIP(realPGWIP), Port: realPGW.LocalAddr().(*net.UDPAddr).Port}

	const seq = 777
	ch := make(chan message, 1)
	c.mu.Lock()
	c.pending[seq] = pendingTxn{ch: ch, peer: pgwAddr}
	c.mu.Unlock()

	send := func(payload byte) {
		t.Helper()
		msg := message{Type: msgCreateSessionResp, HasTEID: true, Sequence: seq, Payload: []byte{payload}}
		b, err := msg.encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := realPGW.WriteToUDP(b, c.conn.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	// First response: delivered into ch (capacity 1, now full). Nothing in
	// this test ever reads from ch — standing in for a consumer that hasn't
	// scheduled yet, the exact window the audit flagged.
	send(0xAA)
	time.Sleep(100 * time.Millisecond)

	// Second, duplicate response for the same sequence number. Without the
	// fix, readLoop blocks here forever trying to send into the full
	// channel. With the fix, the pending entry was already claimed (deleted)
	// by the first response, so this is dropped as "no pending match".
	send(0xBB)

	// Prove readLoop is still alive and processing by sending an unrelated
	// Echo Request and waiting for the Echo Response. If readLoop were
	// blocked on the line above, this would never arrive.
	echoReq := message{Type: msgEchoRequest, Sequence: 999, Payload: []byte{}}
	b, err := echoReq.encode()
	if err != nil {
		t.Fatalf("encode echo request: %v", err)
	}
	if _, err := realPGW.WriteToUDP(b, c.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send echo request: %v", err)
	}

	buf := make([]byte, 4096)
	_ = realPGW.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := realPGW.Read(buf)
	if err != nil {
		t.Fatalf("read loop appears blocked: did not receive Echo Response after duplicate response: %v", err)
	}
	resp, err := decodeMessage(buf[:n])
	if err != nil {
		t.Fatalf("decode echo response: %v", err)
	}
	if resp.Type != msgEchoResponse {
		t.Fatalf("response type = %d, want %d (Echo Response)", resp.Type, msgEchoResponse)
	}

	// The first (non-duplicate) response must still have been delivered.
	select {
	case got := <-ch:
		if len(got.Payload) != 1 || got.Payload[0] != 0xAA {
			t.Fatalf("delivered payload = %x, want the first response (0xAA)", got.Payload)
		}
	default:
		t.Fatal("first response was never delivered to the pending channel")
	}
}
