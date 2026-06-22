package ikev2

// Tests for the TS 33.402 §8.2.2/8.2.3 + TS 23.003 §19.3 fix (audit finding
// #6): the ePDG must accept EAP-AKA pseudonym and fast re-authentication
// identities in IDi, not just permanent root NAIs, and must never mistake a
// pseudonym/fast-reauth identity's opaque AAA-assigned digits for an IMSI.

import (
	"testing"

	"github.com/free5gc/ike/message"
)

func idi(idType uint8, data string) *message.IdentificationInitiator {
	return &message.IdentificationInitiator{IDType: idType, IDData: []byte(data)}
}

func TestExtractNAIRootNAIEAPAKA(t *testing.T) {
	nai, imsi, err := extractNAI(idi(message.ID_FQDN, "0234150999999999@nai.epc.mnc015.mcc234.3gppnetwork.org"))
	if err != nil {
		t.Fatalf("extractNAI() error = %v", err)
	}
	if imsi != "234150999999999" {
		t.Fatalf("imsi = %q, want IMSI extracted from root NAI", imsi)
	}
	if nai != "0234150999999999@nai.epc.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("nai = %q, want full NAI preserved", nai)
	}
}

func TestExtractNAIRootNAIEAPAKAPrime(t *testing.T) {
	// TS 23.003 §19.3.2: '6' prefix for EAP-AKA' root NAI.
	_, imsi, err := extractNAI(idi(message.ID_FQDN, "6234150999999999@nai.epc.mnc015.mcc234.3gppnetwork.org"))
	if err != nil {
		t.Fatalf("extractNAI() error = %v", err)
	}
	if imsi != "234150999999999" {
		t.Fatalf("imsi = %q, want IMSI extracted from EAP-AKA' root NAI", imsi)
	}
}

// TestExtractNAIPseudonymNotRejected is the core regression test for finding
// #6: a pseudonym identity (TS 23.003 §19.3.5, '2' prefix for EAP-AKA) must
// be accepted — not rejected as a malformed NAI — and its digits must NOT be
// treated as an IMSI, since they're an AAA-assigned opaque value (the §19.3.5
// example shows the pseudonym digits differ entirely from the real IMSI).
func TestExtractNAIPseudonymNotRejected(t *testing.T) {
	raw := "258405627015@nai.epc.mnc015.mcc234.3gppnetwork.org"
	nai, imsi, err := extractNAI(idi(message.ID_FQDN, raw))
	if err != nil {
		t.Fatalf("extractNAI() error = %v, want pseudonym NAI accepted", err)
	}
	if nai != raw {
		t.Fatalf("nai = %q, want full pseudonym NAI forwarded to AAA unchanged", nai)
	}
	if imsi != "" {
		t.Fatalf("imsi = %q, want empty — pseudonym digits must not be parsed as an IMSI", imsi)
	}
}

func TestExtractNAIPseudonymEAPAKAPrimeNotRejected(t *testing.T) {
	// TS 23.003 §19.3.5: '7' prefix for EAP-AKA' pseudonym.
	raw := "758405627015@nai.epc.mnc015.mcc234.3gppnetwork.org"
	_, imsi, err := extractNAI(idi(message.ID_FQDN, raw))
	if err != nil {
		t.Fatalf("extractNAI() error = %v, want EAP-AKA' pseudonym accepted", err)
	}
	if imsi != "" {
		t.Fatalf("imsi = %q, want empty for pseudonym identity", imsi)
	}
}

func TestExtractNAIFastReauthNotRejected(t *testing.T) {
	// TS 23.003 §19.3.4 example: fast re-auth identity "358405627015", IMSI
	// is a different value (234150999999999) — confirms these must not be
	// conflated.
	raw := "4358405627015@nai.epc.mnc015.mcc234.3gppnetwork.org"
	nai, imsi, err := extractNAI(idi(message.ID_FQDN, raw))
	if err != nil {
		t.Fatalf("extractNAI() error = %v, want fast-reauth NAI accepted", err)
	}
	if nai != raw {
		t.Fatalf("nai = %q, want full fast-reauth NAI forwarded to AAA unchanged", nai)
	}
	if imsi != "" {
		t.Fatalf("imsi = %q, want empty — fast-reauth digits must not be parsed as an IMSI", imsi)
	}
}

func TestExtractNAIFastReauthEAPAKAPrimeNotRejected(t *testing.T) {
	// TS 23.003 §19.3.4: '8' prefix for EAP-AKA' fast re-authentication.
	raw := "8358405627015@aaa1.nai.epc.mnc015.mcc234.3gppnetwork.org"
	_, imsi, err := extractNAI(idi(message.ID_FQDN, raw))
	if err != nil {
		t.Fatalf("extractNAI() error = %v, want EAP-AKA' fast-reauth accepted", err)
	}
	if imsi != "" {
		t.Fatalf("imsi = %q, want empty for fast-reauth identity", imsi)
	}
}

func TestExtractNAIDecoratedNAINotRejected(t *testing.T) {
	// TS 23.003 §19.3.3: decorated NAI prepends "homerealm!" before the
	// username; the '@'-split local part used for IMSI detection should not
	// trip on this since the leading char won't be '0'/'6'.
	raw := "nai.epc.mnc015.mcc234.3gppnetwork.org!258405627015@nai.epc.mnc071.mcc610.3gppnetwork.org"
	_, imsi, err := extractNAI(idi(message.ID_FQDN, raw))
	if err != nil {
		t.Fatalf("extractNAI() error = %v, want decorated NAI accepted", err)
	}
	if imsi != "" {
		t.Fatalf("imsi = %q, want empty for decorated pseudonym NAI", imsi)
	}
}

func TestExtractNAIRejectsEmptyIDData(t *testing.T) {
	_, _, err := extractNAI(&message.IdentificationInitiator{IDType: message.ID_FQDN, IDData: nil})
	if err == nil {
		t.Fatal("extractNAI() with empty IDData: want error, got nil")
	}
}

func TestExtractNAIRejectsUnsupportedIDType(t *testing.T) {
	_, _, err := extractNAI(idi(message.ID_IPV4_ADDR, "192.0.2.1"))
	if err == nil {
		t.Fatal("extractNAI() with unsupported IDType: want error, got nil")
	}
}

func TestPermanentIMSIFromNAIRejectsShortAndLongDigitRuns(t *testing.T) {
	cases := []string{
		"0123@realm",                // 3 digits, below IMSI minimum length (6)
		"0123456789012345678@realm", // 18 digits, above IMSI maximum length (15)
		"0abc123456@realm",          // non-digit
		"@realm",                    // empty local part
	}
	for _, raw := range cases {
		if got := permanentIMSIFromNAI(raw); got != "" {
			t.Errorf("permanentIMSIFromNAI(%q) = %q, want empty", raw, got)
		}
	}
}
