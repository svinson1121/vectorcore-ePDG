package session

import "vectorcore-epdg/internal/pco"

type PCOState struct {
	RequestPCO   *pco.PCO
	ResponsePCO  *pco.Decoded
	RequestAPCO  *pco.PCO
	ResponseAPCO *pco.Decoded
}
