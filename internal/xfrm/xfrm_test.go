package xfrm

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestResolveXFRMIPsMatchedV4(t *testing.T) {
	local, remote, err := resolveXFRMIPs(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	if err != nil {
		t.Fatalf("resolveXFRMIPs() error = %v", err)
	}
	if len(local) != net.IPv4len || len(remote) != net.IPv4len {
		t.Fatalf("resolveXFRMIPs() local=%d bytes remote=%d bytes, want %d", len(local), len(remote), net.IPv4len)
	}
}

func TestResolveXFRMIPsMatchedV6(t *testing.T) {
	local, remote, err := resolveXFRMIPs(net.ParseIP("fd00::1"), net.ParseIP("fd00::2"))
	if err != nil {
		t.Fatalf("resolveXFRMIPs() error = %v", err)
	}
	if len(local) != net.IPv6len || len(remote) != net.IPv6len {
		t.Fatalf("resolveXFRMIPs() local=%d bytes remote=%d bytes, want %d", len(local), len(remote), net.IPv6len)
	}
}

func TestResolveXFRMIPsMismatchedFamilies(t *testing.T) {
	if _, _, err := resolveXFRMIPs(net.ParseIP("10.0.0.1"), net.ParseIP("fd00::2")); err == nil {
		t.Fatal("resolveXFRMIPs() with mismatched families should error, got nil")
	}
	if _, _, err := resolveXFRMIPs(net.ParseIP("fd00::1"), net.ParseIP("10.0.0.2")); err == nil {
		t.Fatal("resolveXFRMIPs() with mismatched families should error, got nil")
	}
}

// TestBuildSAsCBCUsesAuthAndCrypt guards the pre-existing CBC+HMAC path
// (docs/ipsec-gaps.md backward-compatibility requirement): a non-empty
// IntAlgName must still produce separate Auth+Crypt and no Aead.
func TestBuildSAsCBCUsesAuthAndCrypt(t *testing.T) {
	p := ChildSAParams{
		EncKeyIn: make([]byte, 32), IntKeyIn: make([]byte, 32),
		EncKeyOut: make([]byte, 32), IntKeyOut: make([]byte, 32),
		EncAlgName: "cbc(aes)", IntAlgName: "hmac(sha256)", IntTruncBits: 128,
	}
	inbound, outbound := buildSAs(p, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	for _, tc := range []struct {
		name string
		sa   *netlink.XfrmState
	}{{"inbound", inbound}, {"outbound", outbound}} {
		if tc.sa.Aead != nil {
			t.Fatalf("%s: Aead set for a CBC proposal, want nil", tc.name)
		}
		if tc.sa.Auth == nil || tc.sa.Crypt == nil {
			t.Fatalf("%s: Auth/Crypt = %v/%v, want both set for a CBC proposal", tc.name, tc.sa.Auth, tc.sa.Crypt)
		}
	}
}

// TestBuildSAsGCMUsesAead verifies the AEAD path: an empty IntAlgName (the
// signal childAlgNames sends for AES-GCM, internal/ikev2/auth.go) must
// produce an Aead transform with the GCM_16 ICV length, and no Auth/Crypt.
func TestBuildSAsGCMUsesAead(t *testing.T) {
	p := ChildSAParams{
		EncKeyIn:   make([]byte, 36), // 32-byte AES-256 key + 4-byte GCM salt
		EncKeyOut:  make([]byte, 36),
		EncAlgName: "rfc4106(gcm(aes))", IntAlgName: "",
	}
	inbound, outbound := buildSAs(p, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	for _, tc := range []struct {
		name string
		sa   *netlink.XfrmState
	}{{"inbound", inbound}, {"outbound", outbound}} {
		if tc.sa.Auth != nil || tc.sa.Crypt != nil {
			t.Fatalf("%s: Auth/Crypt = %v/%v, want both nil for an AEAD proposal", tc.name, tc.sa.Auth, tc.sa.Crypt)
		}
		if tc.sa.Aead == nil {
			t.Fatalf("%s: Aead = nil, want set for an AEAD proposal", tc.name)
		}
		if tc.sa.Aead.Name != "rfc4106(gcm(aes))" {
			t.Fatalf("%s: Aead.Name = %q, want rfc4106(gcm(aes))", tc.name, tc.sa.Aead.Name)
		}
		if tc.sa.Aead.ICVLen != gcmICVLenBits {
			t.Fatalf("%s: Aead.ICVLen = %d, want %d (bits, per linux/xfrm.h alg_icv_len)", tc.name, tc.sa.Aead.ICVLen, gcmICVLenBits)
		}
	}
}
