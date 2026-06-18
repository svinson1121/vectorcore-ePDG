package xfrm

import (
	"net"
	"testing"
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
