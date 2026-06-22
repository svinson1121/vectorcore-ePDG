package ikev2

import (
	"testing"

	"github.com/free5gc/ike/message"
)

func FuzzParseAuthPayloads(f *testing.F) {
	f.Add(uint8(message.TypeNone), []byte{})
	f.Add(uint8(message.TypeEAP), []byte{0, 0, 0, 9, 1, 0, 0, 5, 1})

	f.Fuzz(func(t *testing.T, firstType uint8, plain []byte) {
		_, _ = parseAuthPayloads(firstType, plain)
	})
}

func FuzzParseChildSAPayloads(f *testing.F) {
	f.Add(uint8(message.TypeNone), []byte{})
	f.Add(uint8(message.TypeNiNr), []byte{0, 0, 0, 8, 1, 2, 3, 4})

	f.Fuzz(func(t *testing.T, firstType uint8, plain []byte) {
		_, _ = parseChildSAPayloads(firstType, plain)
	})
}
