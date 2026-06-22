package pco

import "testing"

func FuzzDecode(f *testing.F) {
	seed, err := Encode(Request(true, true, true, true))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0x80, 0x00, 0x0d, 0x04, 8, 8, 8, 8})

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := Decode(data, false)
		if err != nil || decoded == nil || decoded.PCO == nil {
			return
		}
		encoded, err := Encode(*decoded.PCO)
		if err != nil {
			t.Fatalf("decoded PCO cannot be encoded: %v", err)
		}
		strict := len(decoded.Unsupported) == 0
		if _, err := Decode(encoded, strict); err != nil {
			t.Fatalf("round-trip strict decode failed: %v", err)
		}
	})
}
