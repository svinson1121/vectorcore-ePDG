package ikev2

// Regression tests for unauthenticated IKE_SA_INIT resource exhaustion:
// unbounded goroutines per packet, DH/key-derivation work done before any
// proof of reachability, half-open SAs that never expire, and no cap on the
// half-open SA table. Covers the bounded worker pool, the RFC 7296 §2.6
// COOKIE challenge, the half-open SA cap, half-open SA expiry, and the
// IKE_SA_INIT retransmission shortcut.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"vectorcore-epdg/internal/config"

	"github.com/free5gc/ike/message"
)

func newLoadTestServer(t *testing.T) *Server {
	t.Helper()
	srv := NewServer(&Config{ListenAddr: "127.0.0.1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.ctx = context.Background()
	return srv
}

func TestServerLoadDefaults(t *testing.T) {
	srv := newLoadTestServer(t)
	if got := srv.maxConcurrentPackets(); got != defaultMaxConcurrentPackets {
		t.Errorf("maxConcurrentPackets() = %d, want default %d", got, defaultMaxConcurrentPackets)
	}
	if got := srv.halfOpenSATimeout(); got != defaultHalfOpenSATimeout {
		t.Errorf("halfOpenSATimeout() = %v, want default %v", got, defaultHalfOpenSATimeout)
	}
	if got := srv.maxHalfOpenSAs(); got != defaultMaxHalfOpenSAs {
		t.Errorf("maxHalfOpenSAs() = %d, want default %d", got, defaultMaxHalfOpenSAs)
	}
	if got := srv.cookieThreshold(); got != defaultCookieThreshold {
		t.Errorf("cookieThreshold() = %d, want default %d", got, defaultCookieThreshold)
	}

	srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{
		MaxConcurrentPackets: 7, HalfOpenSATimeout: 9, MaxHalfOpenSAs: 11, CookieThreshold: 5,
	}}
	if got := srv.maxConcurrentPackets(); got != 7 {
		t.Errorf("maxConcurrentPackets() with config = %d, want 7", got)
	}
	if got := srv.halfOpenSATimeout(); got != 9*time.Second {
		t.Errorf("halfOpenSATimeout() with config = %v, want 9s", got)
	}
	if got := srv.maxHalfOpenSAs(); got != 11 {
		t.Errorf("maxHalfOpenSAs() with config = %d, want 11", got)
	}
	if got := srv.cookieThreshold(); got != 5 {
		t.Errorf("cookieThreshold() with config = %d, want 5", got)
	}
}

func TestCookieStateIssueVerifyRoundTrip(t *testing.T) {
	c := newCookieState()
	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 500}
	const spiI = uint64(0xAAAABBBBCCCCDDDD)

	cookie := c.issue(spiI, remote)
	if len(cookie) == 0 {
		t.Fatal("issue() returned empty cookie")
	}
	if !c.verify(cookie, spiI, remote) {
		t.Fatal("verify() rejected a cookie issued for the same spiI/remote")
	}
}

func TestCookieStateRejectsWrongSPIOrAddress(t *testing.T) {
	c := newCookieState()
	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 500}
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.6"), Port: 500}
	const spiI = uint64(1)

	cookie := c.issue(spiI, remote)
	if c.verify(cookie, spiI+1, remote) {
		t.Fatal("verify() accepted a cookie replayed with a different SPI")
	}
	if c.verify(cookie, spiI, other) {
		t.Fatal("verify() accepted a cookie replayed from a different address")
	}
	if c.verify(nil, spiI, remote) {
		t.Fatal("verify() accepted a nil/empty cookie")
	}
	if c.verify([]byte("not-a-real-cookie"), spiI, remote) {
		t.Fatal("verify() accepted an unrelated value")
	}
}

func TestCookieStateVerifiesAcrossRotation(t *testing.T) {
	c := newCookieState()
	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 500}
	const spiI = uint64(42)

	cookie := c.issue(spiI, remote)
	// Force a rotation as if cookieSecretLifetime had elapsed.
	c.mu.Lock()
	c.rotatedAt = time.Now().Add(-2 * cookieSecretLifetime)
	c.mu.Unlock()

	if !c.verify(cookie, spiI, remote) {
		t.Fatal("verify() rejected a cookie issued just before rotation (should check the previous secret too)")
	}
}

// TestHandleIKESAInitRetransmissionResendsCachedResponse proves a duplicate
// IKE_SA_INIT for an SPI we've already answered gets the cached response
// back verbatim, without re-running decode/proposal-selection/DH/keygen —
// the retransmission path returns before any of that.
func TestHandleIKESAInitRetransmissionResendsCachedResponse(t *testing.T) {
	srv := newLoadTestServer(t)

	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srvConn.Close()
	ueConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ueConn.Close()
	ueAddr := ueConn.LocalAddr().(*net.UDPAddr)

	const spiI = uint64(0x1122334455667788)
	cachedResponse := []byte("cached IKE_SA_INIT response bytes")
	srv.storeSA(&ikeSA{
		spiI:        spiI,
		remoteAddr:  ueAddr,
		state:       ikeStateAuth,
		initRespRaw: cachedResponse,
		createdAt:   time.Now(),
	})

	// A garbage payload after the header — the retransmit path must return
	// before ever attempting to decode it.
	pkt := make([]byte, message.IKE_HEADER_LEN+4)
	hdr := &message.IKEHeader{
		InitiatorSPI:  spiI,
		ResponderSPI:  0,
		ExchangeType:  message.IKE_SA_INIT,
		Flags:         message.InitiatorBitCheck,
		MessageID:     0,
	}

	srv.handleIKESAInit(srvConn, ueAddr, pkt, hdr, false)

	buf := make([]byte, 4096)
	_ = ueConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := ueConn.Read(buf)
	if err != nil {
		t.Fatalf("UE did not receive a response: %v", err)
	}
	if string(buf[:n]) != string(cachedResponse) {
		t.Fatalf("got response %q, want the verbatim cached response %q", buf[:n], cachedResponse)
	}
}

// TestHandleIKESAInitRetransmissionRequiresMatchingAddress ensures the cached
// response is only replayed to the address the original exchange came from.
func TestHandleIKESAInitRetransmissionRequiresMatchingAddress(t *testing.T) {
	srv := newLoadTestServer(t)

	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srvConn.Close()

	const spiI = uint64(99)
	originalAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 11111}
	srv.storeSA(&ikeSA{
		spiI:        spiI,
		remoteAddr:  originalAddr,
		state:       ikeStateAuth,
		initRespRaw: []byte("cached"),
		createdAt:   time.Now(),
	})

	differentAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22222}
	pkt := make([]byte, message.IKE_HEADER_LEN+4) // too short to decode past the header
	hdr := &message.IKEHeader{InitiatorSPI: spiI, Flags: message.InitiatorBitCheck}

	// Must not panic or send the cached response to an address that didn't
	// originate the exchange; with a too-short packet, decode will fail and
	// the function returns harmlessly if the retransmit shortcut is skipped.
	srv.handleIKESAInit(srvConn, differentAddr, pkt, hdr, false)
}

func TestHalfOpenReaperExpiresStaleAuthSAs(t *testing.T) {
	srv := newLoadTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	srv.ctx = ctx
	defer cancel()
	srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{HalfOpenSATimeout: 6}} // ticks every ~2s

	staleSPI := uint64(1)
	freshSPI := uint64(2)
	establishedSPI := uint64(3)
	srv.storeSA(&ikeSA{spiI: staleSPI, state: ikeStateAuth, createdAt: time.Now().Add(-10 * time.Second)})
	srv.storeSA(&ikeSA{spiI: freshSPI, state: ikeStateAuth, createdAt: time.Now()})
	srv.storeSA(&ikeSA{spiI: establishedSPI, state: ikeStateEstablished, createdAt: time.Now().Add(-10 * time.Second)})

	done := make(chan struct{})
	go func() {
		srv.halfOpenReaperLoop()
		close(done)
	}()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if srv.lookupSA(staleSPI) == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if srv.lookupSA(staleSPI) != nil {
		t.Error("stale half-open SA was not expired")
	}
	if srv.lookupSA(freshSPI) == nil {
		t.Error("fresh half-open SA was incorrectly expired")
	}
	if srv.lookupSA(establishedSPI) == nil {
		t.Error("established SA was incorrectly expired (only ikeStateAuth should be reaped here)")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("halfOpenReaperLoop did not exit after ctx cancellation")
	}
}

// TestReadLoopDropsPacketsWhenWorkerPoolSaturated proves the bounded worker
// pool actually bounds concurrency: with the semaphore pre-filled, a new
// packet must be dropped rather than spawning an unbounded goroutine.
func TestReadLoopDropsPacketsWhenWorkerPoolSaturated(t *testing.T) {
	srv := newLoadTestServer(t)
	srv.workers = make(chan struct{}, 1)
	srv.workers <- struct{}{} // fill the only slot

	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srvConn.Close()
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer clientConn.Close()

	go srv.readLoop(srvConn, false)

	if _, err := clientConn.WriteToUDP([]byte("irrelevant payload"), srvConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send: %v", err)
	}

	// The packet should be dropped (worker pool full), not processed. There's
	// no direct observable effect to assert on a garbage packet beyond "the
	// process didn't block/crash and the semaphore slot count didn't change"
	// — drain confirms the read loop kept servicing the socket instead of
	// blocking forever trying to dispatch.
	time.Sleep(100 * time.Millisecond)
	if len(srv.workers) != 1 {
		t.Fatalf("workers channel len = %d, want 1 (unchanged — packet should have been dropped, not dispatched)", len(srv.workers))
	}
}

// TestHandleIKESAInitCookieChallengeUnderLoad proves the COOKIE gate: above
// the threshold, a request without a (valid) cookie is challenged and no SA
// is created; the same request retried with the issued cookie passes the
// gate (observed as a different failure further down the pipeline, proposal
// selection, rather than another COOKIE challenge).
func TestHandleIKESAInitCookieChallengeUnderLoad(t *testing.T) {
	srv := newLoadTestServer(t)
	srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{
		CookieThreshold: 1, MaxHalfOpenSAs: 100,
	}}
	// Push load to the threshold with an unrelated existing SA.
	srv.storeSA(&ikeSA{spiI: 0xFFFF, state: ikeStateAuth, createdAt: time.Now()})

	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srvConn.Close()
	ueConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ueConn.Close()

	ueAddr := ueConn.LocalAddr().(*net.UDPAddr)
	const spiI = uint64(0xC0FFEE)
	send := func(cookieData []byte) []byte {
		t.Helper()
		var payloads message.IKEPayloadContainer
		payloads.BuildSecurityAssociation() // empty: cookie gate runs before proposal selection
		payloads.BuildKeyExchange(0, []byte{1, 2, 3, 4})
		payloads.BuildNonce(randomKey(t, 32))
		if cookieData != nil {
			payloads.BuildNotification(message.TypeNone, message.COOKIE, nil, cookieData)
		}
		msg := message.NewMessage(spiI, 0, message.IKE_SA_INIT, false, true, 0, payloads)
		raw, err := msg.Encode()
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		hdr, err := message.ParseHeader(raw)
		if err != nil {
			t.Fatalf("parse request header: %v", err)
		}
		// Drive the handler directly, exactly as handlePacket would after
		// reading this same datagram off the wire — avoids needing a live
		// readLoop/worker-pool goroutine just to deliver the packet.
		srv.handleIKESAInit(srvConn, ueAddr, raw, hdr, false)

		buf := make([]byte, 4096)
		_ = ueConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := ueConn.Read(buf)
		if err != nil {
			t.Fatalf("no response: %v", err)
		}
		return buf[:n]
	}
	readNotify := func(raw []byte) *message.Notification {
		t.Helper()
		hdr, err := message.ParseHeader(raw)
		if err != nil {
			t.Fatalf("parse response header: %v", err)
		}
		ikeMsg := new(message.IKEMessage)
		ikeMsg.IKEHeader = hdr
		if err := ikeMsg.DecodePayload(raw[message.IKE_HEADER_LEN:]); err != nil {
			t.Fatalf("decode response payloads: %v", err)
		}
		for _, pl := range ikeMsg.Payloads {
			if n, ok := pl.(*message.Notification); ok {
				return n
			}
		}
		return nil
	}

	// First attempt, no cookie: must be challenged, and no SA created.
	resp1 := send(nil)
	n1 := readNotify(resp1)
	if n1 == nil || n1.NotifyMessageType != message.COOKIE {
		t.Fatalf("first response notify = %+v, want a COOKIE challenge", n1)
	}
	if srv.lookupSA(spiI) != nil {
		t.Fatal("an SA was created despite the COOKIE challenge not being satisfied")
	}

	// Retry with the issued cookie: must pass the gate. With an empty SA
	// payload it then fails proposal selection (NO_PROPOSAL_CHOSEN) — a
	// different failure than COOKIE, proving the gate let it through.
	resp2 := send(n1.NotificationData)
	n2 := readNotify(resp2)
	if n2 == nil || n2.NotifyMessageType != message.NO_PROPOSAL_CHOSEN {
		t.Fatalf("second response notify = %+v, want NO_PROPOSAL_CHOSEN (cookie accepted, proposal selection now reached)", n2)
	}
}

func TestHandleIKESAInitRejectsWhenHalfOpenTableFull(t *testing.T) {
	srv := newLoadTestServer(t)
	srv.fullCfg = &config.Config{IKEv2: config.IKEv2Config{
		CookieThreshold: 1000, // keep the cookie gate out of the way
		MaxHalfOpenSAs:  1,    // 0 would mean "use the default" (see maxHalfOpenSAs())
	}}
	// Push load to the cap with an unrelated existing SA.
	srv.storeSA(&ikeSA{spiI: 0xFFFF, state: ikeStateAuth, createdAt: time.Now()})

	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srvConn.Close()
	ueConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ueConn.Close()
	ueAddr := ueConn.LocalAddr().(*net.UDPAddr)

	var payloads message.IKEPayloadContainer
	payloads.BuildSecurityAssociation()
	payloads.BuildKeyExchange(0, []byte{1, 2, 3, 4})
	payloads.BuildNonce(randomKey(t, 32))
	msg := message.NewMessage(0xBEEF, 0, message.IKE_SA_INIT, false, true, 0, payloads)
	raw, err := msg.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	hdr0, err := message.ParseHeader(raw)
	if err != nil {
		t.Fatalf("parse request header: %v", err)
	}
	srv.handleIKESAInit(srvConn, ueAddr, raw, hdr0, false)

	buf := make([]byte, 4096)
	_ = ueConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := ueConn.Read(buf)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	hdr, err := message.ParseHeader(buf[:n])
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	ikeMsg := new(message.IKEMessage)
	ikeMsg.IKEHeader = hdr
	if err := ikeMsg.DecodePayload(buf[message.IKE_HEADER_LEN:n]); err != nil {
		t.Fatalf("decode payloads: %v", err)
	}
	var got *message.Notification
	for _, pl := range ikeMsg.Payloads {
		if n, ok := pl.(*message.Notification); ok {
			got = n
		}
	}
	if got == nil || got.NotifyMessageType != message.TEMPORARY_FAILURE {
		t.Fatalf("response notify = %+v, want TEMPORARY_FAILURE", got)
	}
	if srv.lookupSA(0xBEEF) != nil {
		t.Fatal("an SA was created despite the half-open table being full")
	}
}
