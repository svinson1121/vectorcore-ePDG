package ikev2

import (
	"testing"

	"github.com/free5gc/ike/message"
)

// buildIKEOffer constructs a single-proposal SecurityAssociation the way a
// real initiator would, offering exactly the given transforms (mirrors
// buildIKESAPayload's construction, used in reverse for tests). integ == nil
// omits the IntegrityAlgorithm transform entirely (a genuine AEAD offer).
func buildIKEOffer(dh dhGroup, encr *encrAlg, integ *integAlg, prf *prfAlg) *message.SecurityAssociation {
	sa := new(message.SecurityAssociation)
	p := sa.Proposals.BuildProposal(1, message.TypeIKE, nil)
	p.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, dh.TransformID(), nil, nil, nil)
	attrType := uint16(message.AttributeTypeKeyLength)
	keyBits := uint16(encr.keyBits)
	p.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, encr.id, &attrType, &keyBits, nil)
	if integ != nil {
		p.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, integ.id, nil, nil, nil)
	}
	p.PseudorandomFunction.BuildTransform(message.TypePseudorandomFunction, prf.id, nil, nil, nil)
	return sa
}

func TestSelectIKEProposalECDHGroups(t *testing.T) {
	tests := []struct {
		name string
		dh   dhGroup
	}{
		{"group 19 (P-256)", ecdh256Group},
		{"group 20 (P-384)", ecdh384Group},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := buildIKEOffer(tt.dh, encrAesCbc256, integSha256_128, prfSha256)
			got, _, err := selectIKEProposal(sa)
			if err != nil {
				t.Fatalf("selectIKEProposal() error = %v", err)
			}
			if got.dh.TransformID() != tt.dh.TransformID() {
				t.Fatalf("selected dh = %d, want %d", got.dh.TransformID(), tt.dh.TransformID())
			}
		})
	}
}

// TestSelectIKEProposalLegacyUnaffected guards against the ECDH additions
// regressing the pre-existing CBC/SHA1/MODP proposal set
// (docs/ipsec-gaps.md backward-compatibility requirement).
func TestSelectIKEProposalLegacyUnaffected(t *testing.T) {
	tests := []struct {
		name  string
		dh    dhGroup
		encr  *encrAlg
		integ *integAlg
		prf   *prfAlg
	}{
		{"modp14/cbc256/sha256", dhGroup14, encrAesCbc256, integSha256_128, prfSha256},
		{"modp15/cbc256/sha512", dhGroup15, encrAesCbc256, integSha512_256, prfSha512},
		{"modp14/cbc128/sha1", dhGroup14, encrAesCbc128, integSha1_96, prfSha1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := buildIKEOffer(tt.dh, tt.encr, tt.integ, tt.prf)
			got, _, err := selectIKEProposal(sa)
			if err != nil {
				t.Fatalf("selectIKEProposal() error = %v", err)
			}
			if got.dh.TransformID() != tt.dh.TransformID() || got.encr.id != tt.encr.id || got.integ.id != tt.integ.id {
				t.Fatalf("selectIKEProposal() = %+v, want dh=%d encr=%d integ=%d",
					got, tt.dh.TransformID(), tt.encr.id, tt.integ.id)
			}
		})
	}
}

func TestSelectIKEProposalNoMatch(t *testing.T) {
	// AES-CBC-256 paired with SHA1 integrity is not one of our supported
	// combinations (we always pair CBC-256 with SHA256/SHA512) — must be rejected.
	sa := buildIKEOffer(dhGroup14, encrAesCbc256, integSha1_96, prfSha1)
	if _, _, err := selectIKEProposal(sa); err == nil {
		t.Fatal("selectIKEProposal() with unsupported combination: want error, got nil")
	}
}

// TestSelectIKEProposalGCM covers docs/ipsec-gaps.md Gap 2: a genuine AEAD
// IKE SA offer (AES-GCM, no INTEG transform) must match an AEAD supported
// entry, for both key sizes and DH groups.
func TestSelectIKEProposalGCM(t *testing.T) {
	tests := []struct {
		name string
		dh   dhGroup
		encr *encrAlg
	}{
		{"gcm256/ecdh384", ecdh384Group, encrAesGcm16_256},
		{"gcm128/dh14", dhGroup14, encrAesGcm16_128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := buildIKEOffer(tt.dh, tt.encr, nil, prfSha256)
			got, _, err := selectIKEProposal(sa)
			if err != nil {
				t.Fatalf("selectIKEProposal() error = %v", err)
			}
			if got.integ != nil {
				t.Fatalf("selected proposal has integ = %+v, want nil for an AEAD match", got.integ)
			}
			if got.encr.id != tt.encr.id || got.encr.keyBits != tt.encr.keyBits {
				t.Fatalf("selected encr = %+v, want %+v", got.encr, tt.encr)
			}
		})
	}
}

// TestSelectIKEProposalGCMRejectsExtraInteg ensures an offer pairing IKE SA
// AES-GCM with a separate INTEG transform is rejected, not silently matched.
func TestSelectIKEProposalGCMRejectsExtraInteg(t *testing.T) {
	sa := buildIKEOffer(dhGroup14, encrAesGcm16_256, integSha256_128, prfSha256)
	if _, _, err := selectIKEProposal(sa); err == nil {
		t.Fatal("selectIKEProposal() with GCM+INTEG: want error, got nil")
	}
}

// buildESPOffer constructs a single-proposal SecurityAssociation the way a
// real initiator would for CHILD_SA negotiation. integ == nil omits the
// IntegrityAlgorithm transform entirely (a genuine AEAD offer); dh == nil
// omits the DiffieHellmanGroup transform (no PFS).
func buildESPOffer(dh dhGroup, encr *encrAlg, integ *integAlg) *message.SecurityAssociation {
	sa := new(message.SecurityAssociation)
	p := sa.Proposals.BuildProposal(1, message.TypeESP, []byte{1, 2, 3, 4})
	attrType := uint16(message.AttributeTypeKeyLength)
	keyBits := uint16(encr.keyBits)
	p.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, encr.id, &attrType, &keyBits, nil)
	if integ != nil {
		p.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, integ.id, nil, nil, nil)
	}
	if dh != nil {
		p.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, dh.TransformID(), nil, nil, nil)
	}
	return sa
}

// TestSelectESPProposalGCM covers docs/ipsec-gaps.md Gap 1: a genuine AEAD
// offer (AES-GCM, no INTEG transform) must match an AEAD supported entry,
// for both key sizes and with/without PFS.
func TestSelectESPProposalGCM(t *testing.T) {
	tests := []struct {
		name string
		dh   dhGroup
		encr *encrAlg
	}{
		{"gcm256/no-pfs", nil, encrAesGcm16_256},
		{"gcm128/no-pfs", nil, encrAesGcm16_128},
		{"gcm256/pfs-ecdh384", ecdh384Group, encrAesGcm16_256},
		{"gcm128/pfs-dh14", dhGroup14, encrAesGcm16_128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := buildESPOffer(tt.dh, tt.encr, nil)
			got, _, err := selectESPProposal(sa)
			if err != nil {
				t.Fatalf("selectESPProposal() error = %v", err)
			}
			if got.integ != nil {
				t.Fatalf("selected proposal has integ = %+v, want nil for an AEAD match", got.integ)
			}
			if got.encr.id != tt.encr.id || got.encr.keyBits != tt.encr.keyBits {
				t.Fatalf("selected encr = %+v, want %+v", got.encr, tt.encr)
			}
		})
	}
}

// TestSelectESPProposalGCMRejectsExtraInteg ensures an offer that pairs
// AES-GCM with a separate INTEG transform (malformed/non-compliant offer,
// since AEAD ciphers carry their own integrity check per RFC 5282 §3) is
// rejected rather than silently matched against a CBC entry or ignored.
func TestSelectESPProposalGCMRejectsExtraInteg(t *testing.T) {
	sa := buildESPOffer(nil, encrAesGcm16_256, integSha256_128)
	if _, _, err := selectESPProposal(sa); err == nil {
		t.Fatal("selectESPProposal() with GCM+INTEG: want error, got nil")
	}
}

// TestSelectESPProposalLegacyUnaffected guards the pre-existing CBC entries
// against regressions from the GCM/ECDH additions.
func TestSelectESPProposalLegacyUnaffected(t *testing.T) {
	tests := []struct {
		name  string
		dh    dhGroup
		encr  *encrAlg
		integ *integAlg
	}{
		{"cbc256/sha256/dh14", dhGroup14, encrAesCbc256, integSha256_128},
		{"cbc128/sha1/no-pfs", nil, encrAesCbc128, integSha1_96},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := buildESPOffer(tt.dh, tt.encr, tt.integ)
			got, _, err := selectESPProposal(sa)
			if err != nil {
				t.Fatalf("selectESPProposal() error = %v", err)
			}
			if got.encr.id != tt.encr.id || got.integ == nil || got.integ.id != tt.integ.id {
				t.Fatalf("selectESPProposal() = %+v, want encr=%d integ=%d", got, tt.encr.id, tt.integ.id)
			}
		})
	}
}
