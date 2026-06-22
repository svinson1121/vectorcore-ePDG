package swm

import "testing"

func FuzzParseEAP(f *testing.F) {
	f.Add([]byte{1, 7, 0, 5, 23})
	f.Add([]byte{3, 7, 0, 4})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseEAP(data)
	})
}
