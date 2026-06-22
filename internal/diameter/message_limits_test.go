package diameter

// Tests for audit finding #11: a Diameter peer could declare an arbitrarily
// large message length in the 4-byte prefix, forcing an allocation up to
// ~16 MiB before any of the rest of the message arrived, and (since no read
// deadline applied past the handshake) could then withhold the body
// indefinitely, blocking the reader forever.

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func encode24(length uint32) []byte {
	return []byte{Version, byte(length >> 16), byte(length >> 8), byte(length)}
}

func TestDecodeMessageRejectsOversizedLength(t *testing.T) {
	// Declare a length just above the cap. The reader has nothing past the
	// 4-byte prefix — if DecodeMessage tried to read the body before
	// checking the cap, this would fail with a short-read/EOF error instead
	// of the cap-rejection error, proving the check runs before allocation.
	r := bytes.NewReader(encode24(MaxMessageLen + 1))
	_, err := DecodeMessage(r)
	if err == nil {
		t.Fatal("DecodeMessage() with length > MaxMessageLen: want error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("DecodeMessage() error = %v, want a cap-rejection error (not a short-read error from attempting the body)", err)
	}
}

func TestDecodeMessageAcceptsLengthAtCap(t *testing.T) {
	// Exactly at the cap must still pass the cap check and reach the body
	// read (which then fails on EOF here, since no body bytes follow) —
	// proving the boundary is inclusive, not off-by-one.
	r := bytes.NewReader(encode24(MaxMessageLen))
	_, err := DecodeMessage(r)
	if err == nil {
		t.Fatal("DecodeMessage() with a missing body: want error, got nil")
	}
	if strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatal("DecodeMessage() rejected a length exactly at MaxMessageLen as if it exceeded it")
	}
}

// TestDecodeMessageBodyReadTimeout reproduces the indefinite-block half of
// the finding: a peer that sends a valid, in-budget length prefix and then
// never sends the rest of the message must not be able to stall the reader
// forever.
func TestDecodeMessageBodyReadTimeout(t *testing.T) {
	old := bodyReadTimeout
	bodyReadTimeout = 200 * time.Millisecond
	defer func() { bodyReadTimeout = old }()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Declare a message of HeaderLen+4 bytes but never send the body.
	go func() {
		_, _ = client.Write(encode24(HeaderLen + 4))
	}()

	done := make(chan error, 1)
	go func() {
		_, err := DecodeMessage(server)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("DecodeMessage() with a withheld body: want timeout error, got nil")
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("DecodeMessage() error = %v, want a net.Error timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DecodeMessage() did not return — body-withholding peer stalled the reader indefinitely")
	}
}

// TestDecodeMessageNoDeadlineWhileIdle confirms the fix doesn't regress
// normal idle behavior: with no message in flight at all (nothing written
// yet), DecodeMessage must not time out within the (very short, for test
// speed) bodyReadTimeout window — only an in-progress message's body is
// time-bounded, not the wait for the next message to begin.
func TestDecodeMessageNoDeadlineWhileIdle(t *testing.T) {
	old := bodyReadTimeout
	bodyReadTimeout = 50 * time.Millisecond
	defer func() { bodyReadTimeout = old }()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		_, err := DecodeMessage(server)
		done <- err
	}()

	// Outlast bodyReadTimeout several times over while sending nothing —
	// if DecodeMessage applied a deadline before any prefix bytes arrive,
	// this would time out.
	select {
	case err := <-done:
		t.Fatalf("DecodeMessage() returned during idle wait (no message started): %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// Now actually send a complete message and confirm it's still received.
	msg := Message{CommandCode: CommandDWR, AppID: 0}.Encode()
	go func() { _, _ = client.Write(msg) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DecodeMessage() error after idle period = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DecodeMessage() did not receive the message sent after the idle period")
	}
}
