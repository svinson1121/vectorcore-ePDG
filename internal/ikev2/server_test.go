package ikev2

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func newTestServer(t *testing.T, listenAddrV6 string, ikePort, nattPort int) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(&Config{
		ListenAddr:   "127.0.0.1",
		ListenAddrV6: listenAddrV6,
		IKEPort:      ikePort,
		NATTPort:     nattPort,
	}, log)
	t.Cleanup(srv.Close)
	return srv
}

func TestListenAndServeIPv4OnlyByDefault(t *testing.T) {
	srv := newTestServer(t, "", 35500, 35501)
	if err := srv.ListenAndServe(context.Background()); err != nil {
		t.Fatalf("ListenAndServe() error = %v", err)
	}
	if srv.conn500 == nil || srv.conn4500 == nil {
		t.Fatal("v4 sockets not bound")
	}
	if srv.conn500v6 != nil || srv.conn4500v6 != nil {
		t.Fatal("v6 sockets bound even though ListenAddrV6 is empty")
	}
}

func TestListenAndServeDualStack(t *testing.T) {
	srv := newTestServer(t, "::1", 35502, 35503)
	if err := srv.ListenAndServe(context.Background()); err != nil {
		t.Fatalf("ListenAndServe() error = %v", err)
	}
	if srv.conn500 == nil || srv.conn4500 == nil {
		t.Fatal("v4 sockets not bound")
	}
	if srv.conn500v6 == nil || srv.conn4500v6 == nil {
		t.Fatal("v6 sockets not bound even though ListenAddrV6 is set")
	}

	// Confirm the v6 IKE port actually accepts and dispatches a packet (garbage
	// is fine — we're verifying the listener+readLoop path, not a real exchange).
	conn, err := net.Dial("udp6", "[::1]:35502")
	if err != nil {
		t.Fatalf("dial v6 ike port: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("not a real IKE packet")); err != nil {
		t.Fatalf("write to v6 ike port: %v", err)
	}

	// Confirm the v4 listener still works unaffected (dual-stack regression check).
	connV4, err := net.Dial("udp4", "127.0.0.1:35502")
	if err != nil {
		t.Fatalf("dial v4 ike port: %v", err)
	}
	defer connV4.Close()
	if _, err := connV4.Write([]byte("not a real IKE packet")); err != nil {
		t.Fatalf("write to v4 ike port: %v", err)
	}

	// Give the read loops a moment to process; absence of a panic/crash across
	// both families is the assertion here.
	time.Sleep(50 * time.Millisecond)
}

func TestCloseIsSafeWithoutListenAndServe(t *testing.T) {
	srv := newTestServer(t, "::1", 35504, 35505)
	srv.Close() // must not panic on nil conns
}
