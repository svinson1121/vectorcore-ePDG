package ikev2

// SA proposal negotiation — RFC 7296 §3.3.

import (
	"fmt"

	"github.com/free5gc/ike/message"
)

// negotiatedProposal holds the selected transform set for one IKE SA.
// integ is nil for AEAD ciphers (AES-GCM) — combined-mode encryption carries
// its own integrity check, so no separate INTEG transform is offered or
// expected, and SK_ai/SK_ar are zero-length (RFC 5282 §3.1).
type negotiatedProposal struct {
	dh    dhGroup
	encr  *encrAlg
	integ *integAlg
	prf   *prfAlg
}

// integKeyLen returns 0 for AEAD proposals (no separate integrity key)
// instead of nil-dereferencing p.integ.
func (p *negotiatedProposal) integKeyLen() int {
	if p.integ == nil {
		return 0
	}
	return p.integ.KeyLen()
}

// integID returns 0 for AEAD proposals, for safe logging of the negotiated
// transform without nil-dereferencing p.integ.
func (p *negotiatedProposal) integID() uint16 {
	if p.integ == nil {
		return 0
	}
	return p.integ.id
}

// supportedIKEProposals lists our IKE SA proposals in preference order,
// matching the production swanctl config vectorcore-epdg-ims, plus AES-GCM
// (docs/ipsec-gaps.md Gap 2 — combined-mode, integ is nil) ahead of AES-CBC,
// and ECDH groups 19/20 (Gaps 3/4) ahead of the legacy MODP entries. All
// legacy entries are unchanged and kept for backward compatibility with
// handsets that don't offer GCM/ECDH.
var supportedIKEProposals = []negotiatedProposal{
	{ecdh384Group, encrAesGcm16_256, nil, prfSha256},
	{ecdh256Group, encrAesGcm16_256, nil, prfSha256},
	{dhGroup14, encrAesGcm16_256, nil, prfSha256},
	{ecdh384Group, encrAesGcm16_128, nil, prfSha256},
	{ecdh256Group, encrAesGcm16_128, nil, prfSha256},
	{dhGroup14, encrAesGcm16_128, nil, prfSha256},
	{ecdh384Group, encrAesCbc256, integSha256_128, prfSha256},
	{ecdh256Group, encrAesCbc256, integSha256_128, prfSha256},
	{ecdh384Group, encrAesCbc256, integSha512_256, prfSha512},
	{ecdh256Group, encrAesCbc256, integSha512_256, prfSha512},
	{dhGroup14, encrAesCbc256, integSha256_128, prfSha256},
	{dhGroup15, encrAesCbc256, integSha256_128, prfSha256},
	{dhGroup14, encrAesCbc256, integSha512_256, prfSha512},
	{dhGroup15, encrAesCbc256, integSha512_256, prfSha512},
	{dhGroup14, encrAesCbc128, integSha1_96, prfSha1},
}

// selectIKEProposal walks the initiator's SA payload and returns the first
// proposal+DH transform combination we support.
func selectIKEProposal(sa *message.SecurityAssociation) (*negotiatedProposal, uint8, error) {
	for _, prop := range sa.Proposals {
		if prop.ProtocolID != message.TypeIKE {
			continue
		}
		selected := matchIKEProposal(prop)
		if selected != nil {
			return selected, prop.ProposalNumber, nil
		}
	}
	return nil, 0, fmt.Errorf("ikev2: no acceptable IKE proposal")
}

func matchIKEProposal(prop *message.Proposal) *negotiatedProposal {
	for _, supported := range supportedIKEProposals {
		if !hasDH(prop, supported.dh.TransformID()) {
			continue
		}
		if !hasEncr(prop, supported.encr.id, supported.encr.keyBits) {
			continue
		}
		if supported.integ == nil {
			// AEAD: initiator must not offer a separate INTEG transform.
			if len(prop.IntegrityAlgorithm) != 0 {
				continue
			}
		} else if !hasInteg(prop, supported.integ.id) {
			continue
		}
		if !hasPRF(prop, supported.prf.id) {
			continue
		}
		match := supported
		return &match
	}
	return nil
}

func hasDH(prop *message.Proposal, id uint16) bool {
	for _, t := range prop.DiffieHellmanGroup {
		if t.TransformID == id {
			return true
		}
	}
	return false
}

func hasEncr(prop *message.Proposal, id uint16, keyBits int) bool {
	for _, t := range prop.EncryptionAlgorithm {
		if t.TransformID != id {
			continue
		}
		if t.AttributePresent && t.AttributeType == message.AttributeTypeKeyLength {
			if int(t.AttributeValue) == keyBits {
				return true
			}
		}
	}
	return false
}

func hasInteg(prop *message.Proposal, id uint16) bool {
	for _, t := range prop.IntegrityAlgorithm {
		if t.TransformID == id {
			return true
		}
	}
	return false
}

func hasPRF(prop *message.Proposal, id uint16) bool {
	for _, t := range prop.PseudorandomFunction {
		if t.TransformID == id {
			return true
		}
	}
	return false
}

// buildIKESAPayload constructs the SA response payload with a single proposal
// reflecting the negotiated transforms.
func buildIKESAPayload(prop *negotiatedProposal, propNum uint8, spi []byte) *message.SecurityAssociation {
	sa := new(message.SecurityAssociation)
	p := message.Proposal{
		ProposalNumber: propNum,
		ProtocolID:     message.TypeIKE,
		SPI:            spi,
	}

	// DH
	p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, &message.Transform{
		TransformType: message.TypeDiffieHellmanGroup,
		TransformID:   prop.dh.TransformID(),
	})
	// Encryption
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, &message.Transform{
		TransformType:    message.TypeEncryptionAlgorithm,
		TransformID:      prop.encr.id,
		AttributePresent: true,
		AttributeFormat:  message.AttributeFormatUseTV,
		AttributeType:    message.AttributeTypeKeyLength,
		AttributeValue:   uint16(prop.encr.keyBits),
	})
	// Integrity (omitted entirely for AEAD proposals — RFC 5282 §3)
	if prop.integ != nil {
		p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, &message.Transform{
			TransformType: message.TypeIntegrityAlgorithm,
			TransformID:   prop.integ.id,
		})
	}
	// PRF
	p.PseudorandomFunction = append(p.PseudorandomFunction, &message.Transform{
		TransformType: message.TypePseudorandomFunction,
		TransformID:   prop.prf.id,
	})

	sa.Proposals = append(sa.Proposals, &p)
	return sa
}

// ────────────────────────────────────────────────────────────────────────────
// ESP / CHILD SA proposal selection
// ────────────────────────────────────────────────────────────────────────────

// childProposal holds the selected transforms for a CHILD SA (ESP).
// integ is nil for AEAD ciphers (AES-GCM) — combined-mode encryption carries
// its own integrity check, so no separate INTEG transform is offered or
// expected (RFC 5282 §3). For non-AEAD ciphers (AES-CBC) integ is always set.
type childProposal struct {
	encr  *encrAlg
	integ *integAlg
	dh    dhGroup // PFS; nil if no PFS
}

// integKeyLen returns 0 for AEAD proposals (no separate integrity key)
// instead of nil-dereferencing c.integ.
func (c *childProposal) integKeyLen() int {
	if c.integ == nil {
		return 0
	}
	return c.integ.KeyLen()
}

// integID returns 0 for AEAD proposals, for safe logging of the negotiated
// transform without nil-dereferencing c.integ.
func (c *childProposal) integID() uint16 {
	if c.integ == nil {
		return 0
	}
	return c.integ.id
}

// dhID returns 0 when no PFS was negotiated, for safe logging of the
// negotiated transform without nil-dereferencing c.dh.
func (c *childProposal) dhID() uint16 {
	if c.dh == nil {
		return 0
	}
	return c.dh.TransformID()
}

// supportedESPProposals in preference order (swanctl esp_proposals), plus
// AES-GCM (docs/ipsec-gaps.md Gap 1) ahead of AES-CBC, and ECDH groups 19/20
// PFS entries ahead of the legacy MODP ones (Gaps 3/4). PFS variants listed
// first within each cipher; no-PFS (nil dh) fallbacks follow for UEs that do
// not include a DH transform in their CHILD_SA proposal. All pre-existing
// CBC entries are unchanged for backward compatibility.
var supportedESPProposals = []childProposal{
	{encrAesGcm16_256, nil, ecdh384Group},
	{encrAesGcm16_256, nil, ecdh256Group},
	{encrAesGcm16_256, nil, dhGroup14},
	{encrAesGcm16_128, nil, ecdh384Group},
	{encrAesGcm16_128, nil, ecdh256Group},
	{encrAesGcm16_128, nil, dhGroup14},
	{encrAesGcm16_256, nil, nil},
	{encrAesGcm16_128, nil, nil},
	{encrAesCbc256, integSha256_128, ecdh384Group},
	{encrAesCbc256, integSha256_128, ecdh256Group},
	{encrAesCbc256, integSha512_256, ecdh384Group},
	{encrAesCbc256, integSha512_256, ecdh256Group},
	{encrAesCbc256, integSha256_128, dhGroup14},
	{encrAesCbc256, integSha256_128, dhGroup15},
	{encrAesCbc256, integSha512_256, dhGroup14},
	{encrAesCbc256, integSha512_256, dhGroup15},
	{encrAesCbc128, integSha1_96, dhGroup14},
	{encrAesCbc256, integSha256_128, nil},
	{encrAesCbc256, integSha512_256, nil},
	{encrAesCbc128, integSha1_96, nil},
}

func selectESPProposal(sa *message.SecurityAssociation) (*childProposal, uint8, error) {
	for _, prop := range sa.Proposals {
		if prop.ProtocolID != message.TypeESP {
			continue
		}
		selected := matchESPProposal(prop)
		if selected != nil {
			return selected, prop.ProposalNumber, nil
		}
	}
	return nil, 0, fmt.Errorf("ikev2: no acceptable ESP proposal")
}

func matchESPProposal(prop *message.Proposal) *childProposal {
	for _, supported := range supportedESPProposals {
		if !hasEncr(prop, supported.encr.id, supported.encr.keyBits) {
			continue
		}
		if supported.integ == nil {
			// AEAD: initiator must not offer a separate INTEG transform.
			if len(prop.IntegrityAlgorithm) != 0 {
				continue
			}
		} else if !hasInteg(prop, supported.integ.id) {
			continue
		}
		if supported.dh != nil && !hasDH(prop, supported.dh.TransformID()) {
			continue
		}
		match := supported
		return &match
	}
	return nil
}
