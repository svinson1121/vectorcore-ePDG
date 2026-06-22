package diameter

import (
	"bytes"
	"testing"
)

func FuzzDecodeMessage(f *testing.F) {
	valid := Message{
		Flags:       FlagRequest | FlagProxiable,
		CommandCode: CommandDER,
		AppID:       16777264,
		HopByHop:    1,
		EndToEnd:    2,
		AVPs: []AVP{
			UTF8AVP(AVPSessionID, 0, "epdg.example;1"),
			OctetAVP(AVPEAPPayload, 0, FlagMandatory, []byte{2, 0, 0, 5, 1}),
		},
	}.Encode()
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{Version, 0, 0, HeaderLen})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := DecodeMessage(bytes.NewReader(data))
		if err != nil {
			return
		}
		encoded := msg.Encode()
		decoded, err := DecodeMessage(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if decoded.CommandCode != msg.CommandCode ||
			decoded.AppID != msg.AppID ||
			decoded.HopByHop != msg.HopByHop ||
			decoded.EndToEnd != msg.EndToEnd {
			t.Fatalf("round-trip header mismatch: got %+v want %+v", decoded, msg)
		}
	})
}

func FuzzDecodeAVPs(f *testing.F) {
	f.Add([]byte{})
	f.Add(UTF8AVP(AVPOriginHost, 0, "epdg.example").Encode())
	f.Add(GroupedAVP(AVPVendorSpecificApplicationID, 0,
		Uint32AVP(AVPVendorID, 0, Vendor3GPP),
		Uint32AVP(AVPAuthApplicationID, 0, 16777264),
	).Encode())

	f.Fuzz(func(t *testing.T, data []byte) {
		avps, err := DecodeAVPs(data)
		if err != nil {
			return
		}
		var encoded []byte
		for _, avp := range avps {
			encoded = append(encoded, avp.Encode()...)
		}
		if _, err := DecodeAVPs(encoded); err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
	})
}
