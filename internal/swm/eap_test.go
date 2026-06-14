package swm

import "testing"

func TestIdentityResponse(t *testing.T) {
	payload, err := IdentityResponse(7, "0311435300070580@nai.epc.mnc435.mcc311.3gppnetwork.org")
	if err != nil {
		t.Fatalf("IdentityResponse() error = %v", err)
	}
	if payload[0] != 2 || payload[1] != 7 || payload[4] != 1 {
		t.Fatalf("unexpected EAP identity response header: %x", payload[:5])
	}
	if got := int(payload[2])<<8 | int(payload[3]); got != len(payload) {
		t.Fatalf("EAP length = %d, want %d", got, len(payload))
	}
}

func TestParseEAPAKAChallenge(t *testing.T) {
	got := ParseEAP([]byte{1, 9, 0, 8, 23, 1, 0, 0})
	if got.State != eapStateRequest || got.Identifier != 9 || got.Description != "eap-aka challenge" {
		t.Fatalf("ParseEAP() = %#v", got)
	}
}

func TestParseEAPSuccess(t *testing.T) {
	got := ParseEAP([]byte{3, 9, 0, 4})
	if got.State != eapStateSuccess || got.Identifier != 9 {
		t.Fatalf("ParseEAP() = %#v", got)
	}
}
