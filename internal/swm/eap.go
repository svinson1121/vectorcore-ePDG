package swm

import "fmt"

type eapState string

const (
	eapStateUnknown eapState = "unknown"
	eapStateRequest eapState = "request"
	eapStateSuccess eapState = "success"
	eapStateFailure eapState = "failure"
	eapStateInvalid eapState = "invalid"
)

type EAPInfo struct {
	State       eapState
	Description string
	Identifier  byte
}

func IdentityResponse(identifier byte, identity string) ([]byte, error) {
	if identity == "" {
		return nil, fmt.Errorf("EAP identity is required")
	}
	length := 5 + len(identity)
	if length > 0xffff {
		return nil, fmt.Errorf("EAP identity too long")
	}
	payload := make([]byte, length)
	payload[0] = 2
	payload[1] = identifier
	payload[2] = byte(length >> 8)
	payload[3] = byte(length)
	payload[4] = 1
	copy(payload[5:], identity)
	return payload, nil
}

func ParseEAP(payload []byte) EAPInfo {
	if len(payload) < 4 {
		return EAPInfo{State: eapStateInvalid, Description: "short header"}
	}
	code := payload[0]
	identifier := payload[1]
	length := int(payload[2])<<8 | int(payload[3])
	if length < 4 || length > len(payload) {
		return EAPInfo{State: eapStateInvalid, Identifier: identifier, Description: "invalid length"}
	}
	switch code {
	case 1:
		if length < 5 {
			return EAPInfo{State: eapStateInvalid, Identifier: identifier, Description: "request missing type"}
		}
		return EAPInfo{State: eapStateRequest, Identifier: identifier, Description: eapRequestDescription(payload[4:length])}
	case 3:
		return EAPInfo{State: eapStateSuccess, Identifier: identifier, Description: "success"}
	case 4:
		return EAPInfo{State: eapStateFailure, Identifier: identifier, Description: "failure"}
	default:
		return EAPInfo{State: eapStateUnknown, Identifier: identifier, Description: fmt.Sprintf("code %d", code)}
	}
}

func eapRequestDescription(data []byte) string {
	if len(data) == 0 {
		return "request"
	}
	switch data[0] {
	case 1:
		return "identity request"
	case 23:
		if len(data) >= 2 {
			return "eap-aka " + eapAKASubtype(data[1])
		}
		return "eap-aka request"
	case 50:
		if len(data) >= 2 {
			return "eap-aka-prime " + eapAKASubtype(data[1])
		}
		return "eap-aka-prime request"
	default:
		return fmt.Sprintf("request type %d", data[0])
	}
}

func eapAKASubtype(subtype byte) string {
	switch subtype {
	case 1:
		return "challenge"
	case 2:
		return "authentication rejection"
	case 4:
		return "synchronization failure"
	case 5:
		return "identity"
	case 12:
		return "client error"
	default:
		return fmt.Sprintf("subtype %d", subtype)
	}
}
