package s2b

import (
	"net"
	"testing"
)

func FuzzDecodeMessage(f *testing.F) {
	seed, err := (message{
		Type:     msgCreateSessionReq,
		TEID:     0x01020304,
		HasTEID:  true,
		Sequence: 1,
		Payload:  encodeIEs(apnIE("ims"), ebiValueIE(5)),
	}).encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := decodeMessage(data)
		if err != nil {
			return
		}
		encoded, err := msg.encode()
		if err != nil {
			t.Fatalf("decoded message cannot be encoded: %v", err)
		}
		again, err := decodeMessage(encoded)
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if again.Type != msg.Type || again.TEID != msg.TEID ||
			again.HasTEID != msg.HasTEID || again.Sequence != msg.Sequence {
			t.Fatalf("round-trip mismatch: got %+v want %+v", again, msg)
		}
	})
}

func FuzzDecodeIEs(f *testing.F) {
	f.Add(encodeIEs(
		apnIE("ims.mnc001.mcc001.gprs"),
		fteidIE(0, ifaceS2BePDGGTPC, 0x01020304, net.ParseIP("192.0.2.1")),
	))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		ies, err := decodeIEs(data)
		if err != nil {
			return
		}
		encoded := encodeIEs(ies...)
		if _, err := decodeIEs(encoded); err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
	})
}

func FuzzS2BRequestParsers(f *testing.F) {
	peer := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: defaultGTPControlPort}
	f.Add([]byte{})
	f.Add(encodeIEs(ebiValueIE(5)))

	f.Fuzz(func(t *testing.T, data []byte) {
		req := message{TEID: 1, Sequence: 1, Payload: data}
		_, _ = parseCreateBearerRequest(req, peer)
		_, _ = parseDeleteBearerRequest(req, peer)
		_, _ = parseUpdateBearerRequest(req, peer)
	})
}
