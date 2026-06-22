package s2b

// Regression test for audit finding #13 (GTPv2-C half): decodeMessage used
// to accept sequence number 0 from the wire while message.encode rejected
// it (minSequence = 1) — an asymmetry that meant a decoded message couldn't
// always be re-encoded (e.g. for relay/retransmission), and let a peer hand
// the rest of this package a sequence value indistinguishable from the
// "unset" sentinel sequenceAllocator deliberately never produces.

import "testing"

func TestDecodeMessageRejectsZeroSequence(t *testing.T) {
	msg := message{Type: msgEchoRequest, Sequence: 1, Payload: []byte{}}
	encoded, err := msg.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Overwrite the 3-byte sequence field (octets 5-7, i.e. indices 4-6, of
	// the 8-byte no-TEID header) with zero.
	encoded[4], encoded[5], encoded[6] = 0, 0, 0

	_, err = decodeMessage(encoded)
	if err == nil {
		t.Fatal("decodeMessage() with sequence 0: want error, got nil")
	}
}

func TestMessageEncodeRejectsZeroSequence(t *testing.T) {
	msg := message{Type: msgEchoRequest, Sequence: 0, Payload: []byte{}}
	if _, err := msg.encode(); err == nil {
		t.Fatal("encode() with sequence 0: want error, got nil")
	}
}

func TestDecodeMessageAcceptsNonZeroSequence(t *testing.T) {
	msg := message{Type: msgEchoRequest, Sequence: 42, Payload: []byte{}}
	encoded, err := msg.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodeMessage(encoded)
	if err != nil {
		t.Fatalf("decodeMessage(): %v", err)
	}
	if decoded.Sequence != 42 {
		t.Fatalf("Sequence = %d, want 42", decoded.Sequence)
	}
}
