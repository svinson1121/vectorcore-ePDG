package ikev2

// IKE SA state.

import (
	"net"
	"sync"
	"time"
)

type ikeState int

const (
	ikeStateInit ikeState = iota
	ikeStateAuth
	ikeStateEstablished
	ikeStateDeleting
)

// ikeSA holds per-IKE-SA state from IKE_SA_INIT through lifetime.
type ikeSA struct {
	mu sync.Mutex

	// SPIs
	spiI uint64
	spiR uint64

	// Remote endpoint (may change on NAT-T migration)
	remoteAddr *net.UDPAddr
	// True when both IKE and ESP traffic use port 4500 (NAT detected).
	natT bool

	// Nonces
	nonceI []byte
	nonceR []byte

	// Negotiated crypto
	proposal *negotiatedProposal
	saKey    *ikeSAKey

	// DH state. dhPriv is opaque: *big.Int for MODP groups, *ecdh.PrivateKey
	// for ECDH groups — only ever passed back into the same dhGroup.
	dhPriv any
	dhPub  []byte // our public value sent in KE response

	// Raw IKE_SA_INIT messages (needed for AUTH payload computation).
	initReqRaw  []byte
	initRespRaw []byte

	state     ikeState
	createdAt time.Time
	lastSeen  time.Time

	// DPD (Dead Peer Detection) state for ePDG-initiated probes.
	ourMsgID  uint32    // counter for INFORMATIONAL requests we send (under mu)
	dpdMsgID  uint32    // message ID of the outstanding probe (0 = none pending)
	dpdSentAt time.Time // when the probe was sent (zero = no probe pending)

	// IKE_AUTH EAP-AKA round state (under mu).
	eapRound            int    // 0 = first IKE_AUTH not yet seen
	swmSessionID        string // Diameter session ID across EAP rounds
	imsi                string
	nai                 string
	apn                 string
	msk                 []byte // set on EAP-AKA success
	eapChallengeMsgID   uint32 // message ID of the round1 IKE_AUTH we responded to
	eapChallengePayload []byte // cached EAP challenge bytes; retransmit if UE resends round1

	// MOBIKE (RFC 4555) state (under mu).
	mobikeEnabled bool   // negotiated in IKE_AUTH; permits UPDATE_SA_ADDRESSES handling
	cookie2       []byte // pending return-routability challenge; nil when no migration in progress

	// VoLTE→VoWiFi handover (3GPP TS 24.302 §8.2.3).
	// Non-nil when UE sent a non-zero INTERNAL_IP4_ADDRESS in CFG_REQUEST,
	// requesting the PGW hand over an existing PDN connection.
	handoverIP net.IP

	// CHILD SA state (populated in first IKE_AUTH, used in final round).
	espProp     *childProposal
	espPropNum  uint8
	peerESPSPI  uint32 // UE's inbound ESP SPI from SAi2
	localESPSPI uint32 // ePDG's inbound ESP SPI for SAr2
	cpWantsIP   bool   // UE requested INTERNAL_IP4_ADDRESS via CFG_REQUEST

	// Pending CHILD SA during rekey window (RFC 7296 §2.8): populated after we send
	// our CREATE_CHILD_SA response, cleared when UE sends DELETE for old or new SPI.
	pendingESPProp     *childProposal
	pendingESPPropNum  uint8
	pendingPeerESPSPI  uint32 // peer's inbound SPI for the new CHILD SA
	pendingLocalESPSPI uint32 // our inbound SPI for the new CHILD SA
	pendingNonceI      []byte // initiator nonce from the rekey exchange
	pendingNonceR      []byte // responder nonce from the rekey exchange

	// IDi payload bytes for AUTH computation: [IDType | 0x00 | 0x00 | 0x00 | IDData].
	idiAuthBytes []byte

	sessionID string // key in session.Manager

	// localIP is the ePDG's outer IP used as the XFRM SA endpoint.
	// Derived at IKE_SA_INIT time from routing toward remoteAddr.
	localIP net.IP
}
