package ikev2

// SA proposal negotiation — RFC 7296 §3.3.

import (
	"fmt"

	"github.com/free5gc/ike/message"
)

// negotiatedProposal holds the selected transform set for one IKE SA.
type negotiatedProposal struct {
	dh    *dhGroup
	encr  *encrAlg
	integ *integAlg
	prf   *prfAlg
}

// supportedIKEProposals lists our IKE SA proposals in preference order,
// matching the production swanctl config vectorcore-epdg-ims.
var supportedIKEProposals = []negotiatedProposal{
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
		if !hasInteg(prop, supported.integ.id) {
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
	// Integrity
	p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, &message.Transform{
		TransformType: message.TypeIntegrityAlgorithm,
		TransformID:   prop.integ.id,
	})
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
type childProposal struct {
	encr  *encrAlg
	integ *integAlg
	dh    *dhGroup // PFS; nil if no PFS
}

// supportedESPProposals in preference order (swanctl esp_proposals).
// PFS variants listed first; no-PFS (nil dh) fallbacks follow for UEs that
// do not include a DH transform in their CHILD_SA proposal.
var supportedESPProposals = []childProposal{
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
		if !hasInteg(prop, supported.integ.id) {
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
