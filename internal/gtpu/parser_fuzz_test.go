package gtpu

import "testing"

func FuzzParseGTPU(f *testing.F) {
	seed, err := encodePathMessage(gtpuMsgEchoRequest, 1, []byte{14, 0, 1, 0})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseGTPU(data)
	})
}

func FuzzParseTFT(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x21, 0x10, 0x01, 0x03, 0x30, 0x11})
	f.Add([]byte{0x21, 0x10, 0x01, 0x09, 0x10, 192, 0, 2, 1, 255, 255, 255, 255})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTFT(data)
	})
}
