package session

import "time"

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
	StateReauthenticating     State = "Reauthenticating"
	StateCleaningUp           State = "CleaningUp"
	StateFailed               State = "Failed"
	StateDeleted              State = "Deleted"
)

type Session struct {
	ID           string
	IMSI         string
	NAI          string
	APN          string
	IkeSPII      uint64
	IkeSPIR      uint64
	ChildSPII    uint64
	ChildSPIR    uint64
	SWMSessionID     string
	HandoverComplete bool
	State            State
	CreatedAt    time.Time
	UpdatedAt    time.Time
	EAPPayload   []byte
	MSK          []byte
	APNProfile   *APNProfile
	S2B          *S2BContext
	PCO          *PCOState
	Datapath     *DatapathContext
	Reauth       *ReauthContext
	FailureCode  string
	FailureText  string
}

type APNProfile struct {
	APN          string
	AMBRUplink   uint64
	AMBRDownlink uint64
}

type S2BContext struct {
	PAA              string
	PGWControlTEID   uint32
	PGWUserTEID      uint32
	LocalControlTEID uint32
	LocalUserTEID    uint32
	EBI              uint8
	PGWRecovery      uint8
}

type DatapathContext struct {
	UEInnerIP              string
	GTPInterface           string
	RouteInstalled         bool
	UplinkRuleInstalled    bool
	UplinkDefaultInstalled bool
	RouteTableID           int
	RulePriority           int
	BridgeVerified         bool
	IPsecPAAAligned        bool
}

type ReauthContext struct {
	InProgress        bool
	IncomingSessionID string
	OldSessionID      string
	OldPAA            string
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
