package pco

import (
	"net"
	"testing"
)

func TestRequestEncodeDecode(t *testing.T) {
	req := Request(true, true, true)
	payload, err := Encode(req)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(payload, false)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded == nil || decoded.PCO == nil || !decoded.PCO.Extension {
		t.Fatalf("decoded PCO = %#v", decoded)
	}
	if got, want := len(decoded.PCO.Containers), 5; got != want {
		t.Fatalf("container count = %d, want %d", got, want)
	}
}

func TestDecodeKnownContainers(t *testing.T) {
	payload := []byte{
		0x80,
		0x00, 0x0d, 0x08, 8, 8, 8, 8, 8, 8, 4, 4,
		0x00, 0x0c, 0x04, 10, 0, 0, 31,
		0x00, 0x10, 0x02, 0x05, 0xdc,
	}
	decoded, err := Decode(payload, false)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded.DNSv4) != 2 || !decoded.DNSv4[0].Equal(net.ParseIP("8.8.8.8")) || !decoded.DNSv4[1].Equal(net.ParseIP("8.8.4.4")) {
		t.Fatalf("DNSv4 = %v", IPStrings(decoded.DNSv4))
	}
	if len(decoded.PCSCFv4) != 1 || !decoded.PCSCFv4[0].Equal(net.ParseIP("10.0.0.31")) {
		t.Fatalf("PCSCFv4 = %v", IPStrings(decoded.PCSCFv4))
	}
	if decoded.MTU == nil || *decoded.MTU != 1500 {
		t.Fatalf("MTU = %v", decoded.MTU)
	}
}

func TestUnknownContainersArePreserved(t *testing.T) {
	payload := []byte{0x80, 0x12, 0x34, 0x02, 0xaa, 0xbb}
	decoded, err := Decode(payload, false)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded.Unsupported) != 1 || decoded.Unsupported[0].ProtocolID != 0x1234 {
		t.Fatalf("unsupported = %#v", decoded.Unsupported)
	}
	if _, err := Decode(payload, true); err == nil {
		t.Fatal("strict Decode() succeeded with unknown container")
	}
}
