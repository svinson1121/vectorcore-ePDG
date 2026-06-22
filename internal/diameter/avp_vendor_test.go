package diameter

// Regression test for audit finding #13 (Diameter half): DecodeAVPs used to
// accept the Vendor bit set together with Vendor-ID 0 — an invalid/reserved
// combination, since Vendor-ID 0 means "no vendor". AVP.Encode keys the
// vendor field's presence off VendorID != 0, so re-encoding such an AVP
// silently dropped the 4-byte vendor field while keeping the Vendor bit set,
// producing a wire-malformed AVP (Vendor bit set, no vendor field present).

import (
	"testing"
)

func TestDecodeAVPsRejectsVendorBitWithZeroVendorID(t *testing.T) {
	// Type=AVPOriginHost(264), Vendor bit set, Length=8 (no payload, no
	// vendor field present despite the bit), Vendor-ID=0.
	raw := []byte{
		0, 0, 1, 8, // AVP Code = 264
		FlagVendorAVP, 0, 0, 12, // Flags (V set), Length = 12
		0, 0, 0, 0, // Vendor-ID = 0
	}
	_, err := DecodeAVPs(raw)
	if err == nil {
		t.Fatal("DecodeAVPs() with Vendor bit set and Vendor-ID 0: want error, got nil")
	}
}

func TestDecodeAVPsAcceptsVendorBitWithNonZeroVendorID(t *testing.T) {
	avp := Uint32AVPFlags(AVPAuthApplicationID, Vendor3GPP, FlagMandatory|FlagVendorAVP, 16777264)
	encoded := avp.Encode()
	decoded, err := DecodeAVPs(encoded)
	if err != nil {
		t.Fatalf("DecodeAVPs() with a legitimate vendor AVP: error = %v", err)
	}
	if len(decoded) != 1 || decoded[0].VendorID != Vendor3GPP {
		t.Fatalf("decoded = %+v, want one AVP with VendorID %d", decoded, Vendor3GPP)
	}
}
