package ikev2

import (
	"encoding/hex"
	"net"
	"testing"
)

// Known-good vectors computed independently in Python:
// SHA1(SPI_i | SPI_r | IP | Port) per RFC 7296 §3.10.1, big-endian SPIs and port.
func TestNatHashKnownVectors(t *testing.T) {
	const spiI = uint64(0x1122334455667788)
	const spiR = uint64(0x99aabbccddeeff00)
	const port = uint16(500)

	tests := []struct {
		name string
		ip   net.IP
		want string
	}{
		{"ipv4", net.ParseIP("203.0.113.5"), "66634ed05de49923629f4ad6e07617135d009792"},
		{"ipv6", net.ParseIP("2001:db8::1"), "e6636f2ec10936923f720265815e37f3ee1cc66d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := natHash(spiI, spiR, tt.ip, port)
			want, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatalf("bad test vector: %v", err)
			}
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("natHash() = %x, want %x", got, want)
			}
		})
	}
}

func TestNatHashBufferSizeMatchesFamily(t *testing.T) {
	v4 := natHash(1, 2, net.ParseIP("10.0.0.1"), 500)
	v6 := natHash(1, 2, net.ParseIP("fd00::1"), 500)
	if len(v4) != 20 || len(v6) != 20 {
		t.Fatalf("natHash() must always return a 20-byte SHA1 digest regardless of IP family, got v4=%d v6=%d", len(v4), len(v6))
	}
	// A v4 and v6 address that share no bytes in common must not hash identically,
	// and critically must not have had the port field corrupted by a fixed-size
	// buffer truncating the 16-byte v6 address.
	if hex.EncodeToString(v4) == hex.EncodeToString(v6) {
		t.Fatalf("natHash() produced identical digests for distinct v4/v6 addresses")
	}
}

func TestNatAddrBytes(t *testing.T) {
	if got := natAddrBytes(net.ParseIP("192.0.2.1")); len(got) != 4 {
		t.Fatalf("natAddrBytes(v4) length = %d, want 4", len(got))
	}
	if got := natAddrBytes(net.ParseIP("2001:db8::1")); len(got) != 16 {
		t.Fatalf("natAddrBytes(v6) length = %d, want 16", len(got))
	}
}
