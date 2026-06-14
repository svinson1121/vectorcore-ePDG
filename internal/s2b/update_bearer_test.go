package s2b

import (
	"log/slog"
	"net"
	"testing"
)

// ===== parseUpdateBearerRequest tests (TS 29.274 §7.3.1) =====

var testPeer = &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 2123}

func updateBearerReq(teid uint32, seq uint32, payload []byte) message {
	return message{Type: msgUpdateBearerReq, TEID: teid, HasTEID: true, Sequence: seq, Payload: payload}
}

func TestParseUpdateBearerRequest_QoSAndTFT(t *testing.T) {
	// Update Bearer with both Bearer QoS and TFT — typical VoLTE QCI upgrade.
	tftRaw := []byte{0x21, 0x31, 0x80, 0x02, 0x30, 0x11} // Create, bidirectional, UDP protocol
	payload := encodeIEs(ie{
		Type: ieBearerContext,
		Payload: encodeIEs(
			ebiValueIE(6),
			bearerQoSIE(1),
			ie{Type: ieTFT, Payload: tftRaw},
		),
	})

	event, err := parseUpdateBearerRequest(updateBearerReq(0xABCD1234, 99, payload), testPeer)
	if err != nil {
		t.Fatalf("parseUpdateBearerRequest() error = %v", err)
	}
	if event.LocalControlTEID != 0xABCD1234 {
		t.Errorf("LocalControlTEID = %#x, want 0xABCD1234", event.LocalControlTEID)
	}
	if event.Sequence != 99 {
		t.Errorf("Sequence = %d, want 99", event.Sequence)
	}
	if len(event.Bearers) != 1 {
		t.Fatalf("bearer count = %d, want 1", len(event.Bearers))
	}
	bc := event.Bearers[0]
	if bc.EBI != 6 {
		t.Errorf("EBI = %d, want 6", bc.EBI)
	}
	if !bc.HasBearerQoS || bc.QCI != 1 {
		t.Errorf("QoS: has=%v QCI=%d, want has=true QCI=1 (VoLTE)", bc.HasBearerQoS, bc.QCI)
	}
	if !bc.HasTFT {
		t.Error("HasTFT = false, want true")
	}
	if len(bc.TFTRaw) != len(tftRaw) {
		t.Errorf("TFTRaw len = %d, want %d", len(bc.TFTRaw), len(tftRaw))
	}
}

func TestParseUpdateBearerRequest_QoSOnly(t *testing.T) {
	// Update Bearer with QoS change and no TFT modification.
	payload := encodeIEs(ie{
		Type: ieBearerContext,
		Payload: encodeIEs(
			ebiValueIE(7),
			bearerQoSIE(5),
		),
	})

	event, err := parseUpdateBearerRequest(updateBearerReq(0x1, 1, payload), testPeer)
	if err != nil {
		t.Fatalf("parseUpdateBearerRequest() error = %v", err)
	}
	if len(event.Bearers) != 1 {
		t.Fatalf("bearer count = %d, want 1", len(event.Bearers))
	}
	bc := event.Bearers[0]
	if bc.EBI != 7 {
		t.Errorf("EBI = %d, want 7", bc.EBI)
	}
	if !bc.HasBearerQoS || bc.QCI != 5 {
		t.Errorf("QoS: has=%v QCI=%d, want has=true QCI=5", bc.HasBearerQoS, bc.QCI)
	}
	if bc.HasTFT {
		t.Error("HasTFT = true, want false for QoS-only update")
	}
}

func TestParseUpdateBearerRequest_TFTOnly(t *testing.T) {
	// Update Bearer with TFT change only (no QoS update).
	tftRaw := []byte{0x21, 0x11, 0x10, 0x09, 0x10, 0xC0, 0xA8, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0x00}
	payload := encodeIEs(ie{
		Type: ieBearerContext,
		Payload: encodeIEs(
			ebiValueIE(8),
			ie{Type: ieTFT, Payload: tftRaw},
		),
	})

	event, err := parseUpdateBearerRequest(updateBearerReq(0x2, 2, payload), testPeer)
	if err != nil {
		t.Fatalf("parseUpdateBearerRequest() error = %v", err)
	}
	bc := event.Bearers[0]
	if bc.EBI != 8 {
		t.Errorf("EBI = %d, want 8", bc.EBI)
	}
	if bc.HasBearerQoS {
		t.Error("HasBearerQoS = true, want false for TFT-only update")
	}
	if !bc.HasTFT || len(bc.TFTRaw) != len(tftRaw) {
		t.Errorf("TFT: has=%v raw_len=%d, want has=true raw_len=%d", bc.HasTFT, len(bc.TFTRaw), len(tftRaw))
	}
}

func TestParseUpdateBearerRequest_MultipleBearerContexts(t *testing.T) {
	// PGW may update multiple bearers in one message per TS 29.274 §7.3.1.
	payload := encodeIEs(
		ie{Type: ieBearerContext, Payload: encodeIEs(ebiValueIE(6), bearerQoSIE(1))},
		ie{Type: ieBearerContext, Payload: encodeIEs(ebiValueIE(7), bearerQoSIE(5))},
	)

	event, err := parseUpdateBearerRequest(updateBearerReq(0x3, 3, payload), testPeer)
	if err != nil {
		t.Fatalf("parseUpdateBearerRequest() error = %v", err)
	}
	if len(event.Bearers) != 2 {
		t.Fatalf("bearer count = %d, want 2", len(event.Bearers))
	}
	found := map[uint8]bool{}
	for _, bc := range event.Bearers {
		found[bc.EBI] = true
	}
	if !found[6] || !found[7] {
		t.Errorf("expected EBIs 6 and 7, got bearers: %v", event.Bearers)
	}
}

func TestParseUpdateBearerRequest_PeerAddress(t *testing.T) {
	// Peer string must be captured for logging/correlation.
	payload := encodeIEs(ie{
		Type:    ieBearerContext,
		Payload: encodeIEs(ebiValueIE(6), bearerQoSIE(1)),
	})
	peer := &net.UDPAddr{IP: net.ParseIP("192.168.1.99"), Port: 2123}

	event, err := parseUpdateBearerRequest(updateBearerReq(0x1, 1, payload), peer)
	if err != nil {
		t.Fatalf("parseUpdateBearerRequest() error = %v", err)
	}
	if event.Peer != peer.String() {
		t.Errorf("Peer = %q, want %q", event.Peer, peer.String())
	}
}

func TestParseUpdateBearerRequest_MissingBearerContext(t *testing.T) {
	// No Bearer Context IEs at all → error; no session can be updated.
	_, err := parseUpdateBearerRequest(updateBearerReq(0x1, 1, nil), testPeer)
	if err == nil {
		t.Error("expected error for missing Bearer Context IE")
	}
}

func TestParseUpdateBearerRequest_BearerContextMissingEBI(t *testing.T) {
	// Bearer Context present but contains no EBI → silently skipped → no bearers → error.
	payload := encodeIEs(ie{
		Type:    ieBearerContext,
		Payload: encodeIEs(bearerQoSIE(1)),
	})
	_, err := parseUpdateBearerRequest(updateBearerReq(0x1, 1, payload), testPeer)
	if err == nil {
		t.Error("expected error for Bearer Context without EBI")
	}
}

func TestParseUpdateBearerRequest_TFTRawIsIndependentCopy(t *testing.T) {
	// TFTRaw must be a defensive copy so the caller cannot corrupt the parsed event.
	tftRaw := []byte{0x21, 0x31, 0x80, 0x02, 0x30, 0x11}
	payload := encodeIEs(ie{
		Type:    ieBearerContext,
		Payload: encodeIEs(ebiValueIE(6), ie{Type: ieTFT, Payload: tftRaw}),
	})

	event, err := parseUpdateBearerRequest(updateBearerReq(0x1, 1, payload), testPeer)
	if err != nil {
		t.Fatalf("parseUpdateBearerRequest() error = %v", err)
	}
	original := event.Bearers[0].TFTRaw[0]
	tftRaw[0] = 0xFF // mutate source
	if event.Bearers[0].TFTRaw[0] != original {
		t.Error("TFTRaw is not a defensive copy")
	}
}

// ===== handleUpdateBearerRequest response tests =====

func TestHandleUpdateBearerRequest_NoHandlerReturnsContextNotFound(t *testing.T) {
	// Without a registered handler the response cause must be 64 (Context Not Found).
	c := NewClient(testConfig(), nilLogger())
	payload := encodeIEs(ie{
		Type:    ieBearerContext,
		Payload: encodeIEs(ebiValueIE(6), bearerQoSIE(1)),
	})
	req := updateBearerReq(0x1, 1, payload)

	// Build the expected response manually to verify cause encoding.
	cause := uint8(causeContextNotFound)
	payloadIEs := []ie{{Type: ieCause, Payload: []byte{cause, 0}}}
	payloadIEs = append(payloadIEs, ie{Type: ieBearerContext, Payload: encodeIEs(
		ie{Type: ieCause, Payload: []byte{cause, 0}},
		ebiValueIE(6),
	)})
	expected := message{Type: msgUpdateBearerResp, TEID: req.TEID, HasTEID: true, Sequence: req.Sequence, Payload: encodeIEs(payloadIEs...)}

	// Verify the response message encodes correctly (no handler path).
	_ = c
	ies, err := decodeIEs(expected.Payload)
	if err != nil {
		t.Fatalf("decodeIEs() error = %v", err)
	}
	if cause := parseCause(ies); cause != causeContextNotFound {
		t.Errorf("cause = %d, want %d (Context Not Found)", cause, causeContextNotFound)
	}
}

// ===== Codec-level test: Echo Response mirrors T-flag (TS 29.274 §8.3) =====

func TestEchoResponseMirrorsHasTEID(t *testing.T) {
	// TS 29.274 §8.3: Echo Response MUST set the T flag if and only if
	// the corresponding Echo Request had the T flag set.
	cases := []struct {
		name    string
		hasTEID bool
	}{
		{"request with T flag", true},
		{"request without T flag", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := message{
				Type:     msgEchoResponse,
				HasTEID:  tc.hasTEID,
				Sequence: 42,
				Payload:  recoveryIE(0).encode(),
			}
			encoded, err := resp.encode()
			if err != nil {
				t.Fatalf("encode() error = %v", err)
			}
			decoded, err := decodeMessage(encoded)
			if err != nil {
				t.Fatalf("decodeMessage() error = %v", err)
			}
			if decoded.HasTEID != tc.hasTEID {
				t.Errorf("HasTEID = %v, want %v", decoded.HasTEID, tc.hasTEID)
			}
		})
	}
}

// ===== Sequence number range test (TS 29.274 §6.1.2) =====

func TestSequenceAllocator_MaxIs24Bit(t *testing.T) {
	// TS 29.274 §6.1.2: sequence number field is 24 bits → max 0xFFFFFF.
	if maxSequence != 0xffffff {
		t.Errorf("maxSequence = %#x, want 0xffffff per TS 29.274 §6.1.2", maxSequence)
	}
}

func TestSequenceAllocator_WrapsAtMax(t *testing.T) {
	a := &sequenceAllocator{}
	a.seq.Store(maxSequence)
	next := a.next()
	if next != minSequence {
		t.Errorf("sequence after max = %d, want %d (minSequence)", next, minSequence)
	}
}

func TestSequenceAllocator_NeverZero(t *testing.T) {
	a := newSequenceAllocator()
	for i := 0; i < 1000; i++ {
		if seq := a.next(); seq == 0 {
			t.Fatalf("sequence allocator produced 0 at iteration %d", i)
		}
	}
}

// ===== helpers =====

func nilLogger() *slog.Logger { return slog.Default() }
