package session

import (
	"net"
	"sync"
	"time"
)

type State string

const (
	StateNew                  State = "New"
	StateEAPAuthenticating    State = "EAPAuthenticating"
	StateEAPAuthenticated     State = "EAPAuthenticated"
	StateS2BCreateSessionSent State = "S2bCreateSessionSent"
	StateS2BAccepted          State = "S2bAccepted"
	StateGTPUInstalling       State = "GTPUInstalling"
	StateDatapathInstalling   State = "DatapathInstalling"
	StateActive               State = "Active"
	StateCleaningUp           State = "CleaningUp"
	StateFailed               State = "Failed"
	StateDeleted              State = "Deleted"
)

// Session is shared by pointer across IKEv2, S2b/GTP-U callbacks, cleanup,
// and the admin API, each running on its own goroutine. mu guards every
// field below except ID, CreatedAt, and UpdatedAt, which are set once in New
// and never reassigned, so they're safe to read without locking.
//
// Convention: whoever is about to read or write a field takes the lock for
// exactly that access (Lock/RLock as appropriate) and releases it before any
// blocking call to another package — including a call that itself takes a
// *Session, since those callees lock for their own field accesses rather
// than assuming a caller-held lock. This avoids deadlock from nested
// locking and keeps the critical sections short.
type Session struct {
	mu sync.RWMutex

	ID               string
	IMSI             string
	NAI              string
	APN              string
	IkeSPII          uint64
	IkeSPIR          uint64
	OuterIP          string // UE's NAT'd outer IP:port, set at IKE_SA_INIT / MOBIKE update
	ESPInboundSPI    uint32 // ePDG's inbound ESP SPI
	ESPOutboundSPI   uint32 // peer's inbound ESP SPI (our outbound SPI)
	SWMSessionID     string
	HandoverComplete bool
	State            State
	CreatedAt        time.Time
	UpdatedAt        time.Time
	EAPPayload       []byte
	MSK              []byte
	APNProfile       *APNProfile
	S2B              *S2BContext
	PCO              *PCOState
	Datapath         *DatapathContext
	FailureCode      string
	FailureText      string
}

// Lock/Unlock/RLock/RUnlock expose Session's internal mutex so callers can
// bracket a group of related field reads/writes (e.g. setting several
// fields and transitioning state together) in one critical section, rather
// than requiring a setter method per field.
func (s *Session) Lock()    { s.mu.Lock() }
func (s *Session) Unlock()  { s.mu.Unlock() }
func (s *Session) RLock()   { s.mu.RLock() }
func (s *Session) RUnlock() { s.mu.RUnlock() }

// View is a point-in-time, lock-free copy of a Session's fields, safe to
// read without further synchronization. It deliberately has no mutex of its
// own (unlike Session) so it can be freely copied and returned by value.
type View struct {
	ID               string
	IMSI             string
	NAI              string
	APN              string
	IkeSPII          uint64
	IkeSPIR          uint64
	OuterIP          string
	ESPInboundSPI    uint32
	ESPOutboundSPI   uint32
	SWMSessionID     string
	HandoverComplete bool
	State            State
	CreatedAt        time.Time
	UpdatedAt        time.Time
	EAPPayload       []byte
	MSK              []byte
	APNProfile       *APNProfile
	S2B              *S2BContext
	PCO              *PCOState
	Datapath         *DatapathContext
	FailureCode      string
	FailureText      string
}

// Snapshot returns a View of s. Pointer-typed sub-structs are copied so the
// result is independent of concurrent mutation through s.
func (s *Session) Snapshot() View {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := View{
		ID:               s.ID,
		IMSI:             s.IMSI,
		NAI:              s.NAI,
		APN:              s.APN,
		IkeSPII:          s.IkeSPII,
		IkeSPIR:          s.IkeSPIR,
		OuterIP:          s.OuterIP,
		ESPInboundSPI:    s.ESPInboundSPI,
		ESPOutboundSPI:   s.ESPOutboundSPI,
		SWMSessionID:     s.SWMSessionID,
		HandoverComplete: s.HandoverComplete,
		State:            s.State,
		CreatedAt:        s.CreatedAt,
		UpdatedAt:        s.UpdatedAt,
		EAPPayload:       append([]byte(nil), s.EAPPayload...),
		MSK:              append([]byte(nil), s.MSK...),
		FailureCode:      s.FailureCode,
		FailureText:      s.FailureText,
	}
	if s.APNProfile != nil {
		ap := *s.APNProfile
		out.APNProfile = &ap
	}
	if s.S2B != nil {
		sb := *s.S2B
		out.S2B = &sb
	}
	if s.PCO != nil {
		p := *s.PCO
		out.PCO = &p
	}
	if s.Datapath != nil {
		d := *s.Datapath
		out.Datapath = &d
	}
	return out
}

type APNProfile struct {
	APN          string
	AMBRUplink   uint64
	AMBRDownlink uint64
}

type S2BContext struct {
	PAA              string
	PGWControlTEID   uint32
	PGWControlIP     net.IP // from Create Session Response F-TEID IE; used for DeleteSession routing
	PGWUserTEID      uint32
	PGWUserIP        net.IP
	LocalControlTEID uint32
	LocalUserTEID    uint32
	EBI              uint8
	PGWRecovery      uint8
}

type DatapathContext struct {
	UEInnerIP              string
	RouteInstalled         bool
	UplinkRuleInstalled    bool
	UplinkDefaultInstalled bool
	RouteTableID           int
	RulePriority           int
	BridgeVerified         bool
	IPsecPAAAligned        bool
}

func New(id string) *Session {
	now := time.Now()
	return &Session{
		ID:        id,
		State:     StateNew,
		CreatedAt: now,
		UpdatedAt: now,
	}
}
