package session

import "fmt"

var allowedTransitions = map[State]map[State]bool{
	StateNew: {
		StateEAPAuthenticating: true,
		StateFailed:            true,
	},
	StateEAPAuthenticating: {
		StateEAPAuthenticated: true,
		StateFailed:           true,
		StateCleaningUp:       true,
	},
	StateEAPAuthenticated: {
		StateS2BCreateSessionSent: true,
		StateFailed:               true,
		StateCleaningUp:           true,
	},
	StateS2BCreateSessionSent: {
		StateS2BAccepted: true,
		StateFailed:      true,
		StateCleaningUp:  true,
	},
	StateS2BAccepted: {
		StateGTPUInstalling: true,
		StateCleaningUp:     true,
		StateFailed:         true,
	},
	StateGTPUInstalling: {
		StateDatapathInstalling: true,
		StateCleaningUp:         true,
		StateFailed:             true,
	},
	StateDatapathInstalling: {
		StateActive:     true,
		StateCleaningUp: true,
		StateFailed:     true,
	},
	StateActive: {
		StateCleaningUp: true,
		StateFailed:     true,
	},
	StateCleaningUp: {
		StateDeleted: true,
		StateFailed:  true,
	},
	StateFailed: {
		StateCleaningUp: true,
		StateDeleted:    true,
	},
}

// Transition must be called with s.Lock held — it's normally one of several
// field updates a caller makes within a single critical section.
func (s *Session) Transition(next State) error {
	if s.State == next {
		return nil
	}
	if !allowedTransitions[s.State][next] {
		return fmt.Errorf("invalid session transition %s -> %s", s.State, next)
	}
	s.State = next
	return nil
}

// CanActivate must be called with s.RLock (or Lock) held.
func (s *Session) CanActivate() bool {
	return s.State == StateDatapathInstalling &&
		len(s.MSK) == 64 &&
		s.APNProfile != nil &&
		s.S2B != nil &&
		s.S2B.PAA != "" &&
		s.S2B.PGWControlTEID != 0 &&
		s.S2B.PGWUserTEID != 0 &&
		s.S2B.EBI != 0 &&
		s.Datapath != nil &&
		s.Datapath.BridgeVerified &&
		s.Datapath.IPsecPAAAligned
}
