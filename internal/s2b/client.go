package s2b

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/pco"
)

type CreateSessionRequest struct {
	IMSI         string
	APN          string
	AMBRUplink   uint64
	AMBRDownlink uint64
	Handover     bool // set Indication IE HI bit (VoLTE→VoWiFi handover, TS 29.274 §8.12)
}

type CreateSessionResult struct {
	PAA              net.IP
	PGWControlTEID   uint32
	PGWUserTEID      uint32
	LocalControlTEID uint32
	LocalUserTEID    uint32
	EBI              uint8
	PGWRecovery      uint8
	PGWControlIP     net.IP
	PGWUserIP        net.IP
	RequestPCO       *pco.PCO
	ResponsePCO      *pco.Decoded
	RequestAPCO      *pco.PCO
	ResponseAPCO     *pco.Decoded
}

type DeleteSessionEvent struct {
	LocalControlTEID uint32
	Sequence         uint32
	Peer             string
	IsHandover       bool // HI bit from Indication IE (TS 29.274 §8.12 octet 3 bit 1); false if IE absent
}

type CreateBearerEvent struct {
	LocalControlTEID uint32
	Sequence         uint32
	Peer             string
	LinkedDefaultEBI uint8
	TopLevelEBIs     []CreateBearerEBI
	BearerContexts   []CreateBearerContext
	Bearers          []CreateBearerContext
	EBI              uint8
	PGWUserTEID      uint32
	PGWUserIP        net.IP
	QCI              uint8
	TFTRaw           []byte
}

type CreateBearerEBI struct {
	PayloadHex  string
	RawIEHex    string
	Offset      int
	Length      int
	Instance    uint8
	EBI         uint8
	HasEBI      bool
	DecodeError string
}

type CreateBearerContext struct {
	Index           int
	Instance        uint8
	RawIEHex        string
	PayloadHex      string
	Length          int
	EBI             uint8
	HasEBI          bool
	UnassignedEBI   bool
	EBIPayloadHex   string
	EBIRawIEHex     string
	EBIChildOffset  int
	EBILength       int
	EBIInstance     uint8
	EBIDecodeError  string
	PGWUserTEID     uint32
	PGWUserIP       net.IP
	PGWFTEIDInst    uint8
	PGWFTEIDIface   uint8
	PGWFTEIDRawHex  string
	QCI             uint8
	HasBearerQoS    bool
	BearerQoSRawLen int
	TFTRaw          []byte
	ChargingID      uint32
	HasChargingID   bool
	RawChildIETypes []uint8
}

type CreateBearerResult struct {
	Accepted       bool
	Cause          uint8
	LocalUserTEID  uint32
	LocalUserIP    net.IP
	Bearers        []CreateBearerBearerResult
	PGWControlTEID uint32 // if non-zero, used as TEID in the CBR response header
}

type CreateBearerBearerResult struct {
	EBI           uint8
	Accepted      bool
	Cause         uint8
	LocalUserTEID uint32
	LocalUserIP   net.IP
	QCI           uint8
	PGWUserTEID   uint32
	PGWUserIP     net.IP
	ChargingID    uint32
	HasChargingID bool
}

type createBearerResponseCacheEntry struct {
	Encoded   []byte
	BearerEBI []uint8
	Expires   time.Time
}

type DeleteBearerEvent struct {
	LocalControlTEID uint32
	Sequence         uint32
	Peer             string
	EBIs             []uint8
	IsHandover       bool // true when Cause = Access changed from Non-3GPP to 3GPP (10) or Reactivation Requested (8)
}

type UpdateBearerEvent struct {
	LocalControlTEID uint32
	Sequence         uint32
	Peer             string
	Bearers          []UpdateBearerContext
}

type UpdateBearerContext struct {
	EBI          uint8
	QCI          uint8
	HasBearerQoS bool
	TFTRaw       []byte
	HasTFT       bool
}

// UpdateBearerResult is returned by the UpdateBearerHandler.
// PGWControlTEID must be set to the PGW's S2b control TEID so the response header is addressed correctly.
type UpdateBearerResult struct {
	Cause          uint8
	PGWControlTEID uint32
}

// DeleteBearerResult is returned by the DeleteBearerHandler.
// PGWControlTEID must be set to the PGW's S2b control TEID so the response header is addressed correctly.
type DeleteBearerResult struct {
	Cause          uint8
	PGWControlTEID uint32
}

type DeleteSessionCauseError struct {
	Cause uint8
}

func (e *DeleteSessionCauseError) Error() string {
	return fmt.Sprintf("S2b Delete Session rejected cause=%d", e.Cause)
}

func (e *DeleteSessionCauseError) CauseName() string {
	switch e.Cause {
	case causeContextNotFound:
		return "Context Not Found"
	default:
		return "unknown"
	}
}

func IsContextNotFound(err error) bool {
	var causeErr *DeleteSessionCauseError
	return errors.As(err, &causeErr) && causeErr.Cause == causeContextNotFound
}

func DeleteCause(err error) (uint8, string, bool) {
	var causeErr *DeleteSessionCauseError
	if errors.As(err, &causeErr) {
		return causeErr.Cause, causeErr.CauseName(), true
	}
	return 0, "", false
}

type Client struct {
	cfg config.Config
	log *slog.Logger

	conn *net.UDPConn
	peer *net.UDPAddr
	seq  *sequenceAllocator

	localControl atomic.Uint32
	localUser    atomic.Uint32

	mu                  sync.Mutex
	pending             map[uint32]chan message
	createBearerCache   map[string]createBearerResponseCacheEntry
	deleteHandler       func(context.Context, DeleteSessionEvent)
	createBearerHandler func(context.Context, CreateBearerEvent) CreateBearerResult
	deleteBearerHandler func(context.Context, DeleteBearerEvent) DeleteBearerResult
	updateBearerHandler func(context.Context, UpdateBearerEvent) UpdateBearerResult
}

func NewClient(cfg config.Config, log *slog.Logger) *Client {
	c := &Client{
		cfg:               cfg,
		log:               log,
		seq:               newSequenceAllocatorWithMax(cfg.GTP.MaxSequence),
		pending:           make(map[uint32]chan message),
		createBearerCache: make(map[string]createBearerResponseCacheEntry),
	}
	c.localControl.Store(randUint32())
	c.localUser.Store(randUint32())
	return c
}

func (c *Client) SetDeleteSessionHandler(handler func(context.Context, DeleteSessionEvent)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteHandler = handler
}

func (c *Client) SetCreateBearerHandler(handler func(context.Context, CreateBearerEvent) CreateBearerResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.createBearerHandler = handler
}

func (c *Client) SetDeleteBearerHandler(handler func(context.Context, DeleteBearerEvent) DeleteBearerResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteBearerHandler = handler
}

func (c *Client) SetUpdateBearerHandler(handler func(context.Context, UpdateBearerEvent) UpdateBearerResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateBearerHandler = handler
}

func (c *Client) Start(ctx context.Context) error {
	localIP := net.ParseIP(c.cfg.GTP.LocalGTPC)
	if localIP == nil {
		return fmt.Errorf("invalid local GTP-C IP %q", c.cfg.GTP.LocalGTPC)
	}
	local := &net.UDPAddr{IP: localIP, Port: defaultGTPControlPort}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return err
	}
	peerIP := net.ParseIP(c.cfg.GTP.PGWGTPC)
	if peerIP == nil {
		_ = conn.Close()
		return fmt.Errorf("invalid PGW GTP-C IP %q", c.cfg.GTP.PGWGTPC)
	}
	c.conn = conn
	c.peer = &net.UDPAddr{IP: peerIP, Port: defaultGTPControlPort}
	c.log.Info("S2b GTPv2-C client listening", "local_addr", local.String(), "pgw_addr", c.peer.String())
	go c.readLoop(ctx)
	return nil
}

func (c *Client) Stop() error {
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *Client) CreateSession(ctx context.Context, req CreateSessionRequest) (*CreateSessionResult, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("S2b GTPv2-C client is not started")
	}
	if req.IMSI == "" {
		return nil, fmt.Errorf("S2b Create Session requires IMSI")
	}
	if req.APN == "" {
		return nil, fmt.Errorf("S2b Create Session requires APN")
	}
	ulKbps, dlKbps, err := gtpAMBR(req.AMBRUplink, req.AMBRDownlink)
	if err != nil {
		return nil, err
	}
	localControl := c.nextTEID(&c.localControl)
	localUser := c.nextTEID(&c.localUser)
	seq := c.seq.next()
	payload := c.createSessionPayload(req, ulKbps, dlKbps, localControl, localUser)
	msg := message{Type: msgCreateSessionReq, TEID: 0, HasTEID: true, Sequence: seq, Payload: payload}
	c.log.Info("S2b Create Session Request sent",
		"imsi", req.IMSI,
		"apn", req.APN,
		"handover", req.Handover,
		"pgw_gtpc", c.cfg.GTP.PGWGTPC,
		"local_gtpc", c.cfg.GTP.LocalGTPC,
		"local_gtpu", c.cfg.GTP.LocalGTPU,
		"local_control_teid", localControl,
		"local_user_teid", localUser,
		"ebi", defaultEBI,
		"rat_type", "wlan",
		"ambr_ul_kbps", ulKbps,
		"ambr_dl_kbps", dlKbps,
		"seq", seq,
		"pco_enabled", c.cfg.PCO.Enabled,
		"pco_request_dns", c.cfg.PCO.RequestDNS,
		"pco_request_pcscf", c.cfg.PCO.RequestPCSCF,
		"pco_request_mtu", c.cfg.PCO.RequestMTU,
		"apco_included", c.cfg.PCO.IncludeAPCO,
	)
	deadline, hasDeadline := ctx.Deadline()
	timeout := ""
	if hasDeadline {
		timeout = time.Until(deadline).String()
	}
	c.log.Info("S2b Create Session waiting for response",
		"imsi", req.IMSI,
		"apn", req.APN,
		"seq", seq,
		"local_control_teid", localControl,
		"local_user_teid", localUser,
		"timeout", timeout,
	)
	resp, err := c.transaction(ctx, msg, msgCreateSessionResp)
	if err != nil {
		c.log.Error("S2b Create Session failed",
			"imsi", req.IMSI,
			"apn", req.APN,
			"seq", seq,
			"local_control_teid", localControl,
			"local_user_teid", localUser,
			"step", "wait_response",
			"error", err,
		)
		return nil, err
	}
	result, err := c.parseCreateSessionResponse(resp, localControl, localUser)
	if err != nil {
		c.log.Error("S2b Create Session failed",
			"imsi", req.IMSI,
			"apn", req.APN,
			"seq", seq,
			"local_control_teid", localControl,
			"local_user_teid", localUser,
			"step", "parse_response",
			"error", err,
		)
		return nil, err
	}
	c.log.Info("S2b Create Session Response received",
		"imsi", req.IMSI,
		"apn", req.APN,
		"paa", result.PAA.String(),
		"pgw_control_teid", result.PGWControlTEID,
		"pgw_user_teid", result.PGWUserTEID,
		"local_user_teid", result.LocalUserTEID,
		"ebi", result.EBI,
		"pgw_recovery", result.PGWRecovery,
	)
	c.logPCO("S2b PCO", req.IMSI, req.APN, result.ResponsePCO)
	c.logPCO("S2b APCO", req.IMSI, req.APN, result.ResponseAPCO)
	return result, nil
}

func (c *Client) Echo(ctx context.Context) (uint8, error) {
	resp, err := c.transaction(ctx, message{
		Type:     msgEchoRequest,
		Sequence: c.seq.next(),
		Payload:  recoveryIE(uint8(c.cfg.GTP.Recovery)).encode(),
	}, msgEchoResponse)
	if err != nil {
		return 0, err
	}
	ies, err := decodeIEs(resp.Payload)
	if err != nil {
		return 0, err
	}
	return parseRecovery(ies), nil
}

func (c *Client) DeleteSession(ctx context.Context, pgwControlTEID, localControlTEID, localUserTEID uint32, ebi uint8) error {
	fteidTEID := localControlTEID
	if fteidTEID == 0 {
		fteidTEID = localUserTEID
	}
	payload := encodeIEs(
		uint8IE(ieEBI, ebi),
		fteidIE(0, ifaceS2BePDGGTPC, fteidTEID, net.ParseIP(c.cfg.GTP.LocalGTPC)),
	)
	resp, err := c.transaction(ctx, message{
		Type:     msgDeleteSessionReq,
		TEID:     pgwControlTEID,
		HasTEID:  true,
		Sequence: c.seq.next(),
		Payload:  payload,
	}, msgDeleteSessionResp)
	if err != nil {
		return err
	}
	ies, err := decodeIEs(resp.Payload)
	if err != nil {
		return err
	}
	if cause := parseCause(ies); cause != causeRequestAccepted {
		return &DeleteSessionCauseError{Cause: cause}
	}
	c.log.Info("S2b Delete Session Response received",
		"pgw_control_teid", pgwControlTEID,
		"local_control_teid", localControlTEID,
		"local_user_teid", localUserTEID,
		"ebi", ebi,
		"cause", causeRequestAccepted,
	)
	return nil
}

func (c *Client) createSessionPayload(req CreateSessionRequest, ulKbps, dlKbps, localControl, localUser uint32) []byte {
	localGTPC := net.ParseIP(c.cfg.GTP.LocalGTPC)
	localGTPU := net.ParseIP(c.cfg.GTP.LocalGTPU)
	bearer := ie{Type: ieBearerContext, Payload: encodeIEs(
		bearerQoSIE(defaultBearerQCI),
		uint8IE(ieEBI, defaultEBI),
		fteidIE(5, ifaceS2BePDGGTPU, localUser, localGTPU),
	)}
	ies := []ie{
		bcdIE(ieIMSI, req.IMSI),
		servingNetworkIE(c.cfg.EPDG.MCC, c.cfg.EPDG.MNC),
		uint8IE(ieRATType, ratTypeWLAN),
		fteidIE(0, ifaceS2BePDGGTPC, localControl, localGTPC),
		apnIE(req.APN),
		uint8IE(ieSelectionMode, 0),
		paaIPv4RequestIE(),
		ambrIE(ulKbps, dlKbps),
		bearer,
		recoveryIE(uint8(c.cfg.GTP.Recovery)),
	}
	if req.Handover {
		// TS 29.274 §8.12: Indication IE, octet 3 bit 1 = HI (Handover Indication).
		ies = append(ies, ie{Type: ieIndication, Payload: []byte{0x00, 0x00, 0x02}})
	}
	ies = append(ies, c.requestPCOIEs()...)
	return encodeIEs(ies...)
}

func (c *Client) parseCreateSessionResponse(resp message, localControl, localUser uint32) (*CreateSessionResult, error) {
	ies, err := decodeIEs(resp.Payload)
	if err != nil {
		return nil, err
	}
	if cause := parseCause(ies); cause != causeRequestAccepted {
		return nil, fmt.Errorf("S2b Create Session rejected cause=%d", cause)
	}
	result := &CreateSessionResult{
		PAA:              parsePAA(ies),
		LocalControlTEID: localControl,
		LocalUserTEID:    localUser,
		EBI:              defaultEBI,
		PGWRecovery:      parseRecovery(ies),
		PGWControlIP:     net.ParseIP(c.cfg.GTP.PGWGTPC),
		PGWUserIP:        net.ParseIP(c.cfg.GTP.PGWGTPU),
	}
	result.RequestPCO, result.RequestAPCO = c.requestPCO()
	if result.ResponsePCO, err = c.parsePCOIE(ies, iePCO); err != nil {
		return nil, err
	}
	if result.ResponseAPCO, err = c.parsePCOIE(ies, ieAPCO); err != nil {
		return nil, err
	}
	if result.PAA == nil {
		return nil, fmt.Errorf("S2b Create Session Response missing IPv4 PAA")
	}
	if _, teid, ip, ok := findFTEIDByInterface(ies, ifaceS2BPGWGTPC, 1, 0); ok {
		result.PGWControlTEID = teid
		if ip != nil {
			result.PGWControlIP = ip
		}
	}
	for _, top := range ies {
		if top.Type != ieBearerContext {
			continue
		}
		children, err := decodeIEs(top.Payload)
		if err != nil {
			continue
		}
		if ebi, ok := findIE(children, ieEBI, 0); ok && len(ebi.Payload) > 0 {
			result.EBI = ebi.Payload[0]
		}
		if _, teid, ip, ok := findFTEIDByInterface(children, ifaceS2BPGWGTPU, 2, 5); ok {
			result.PGWUserTEID = teid
			if ip != nil {
				result.PGWUserIP = ip
			}
		}
	}
	if result.PGWControlTEID == 0 {
		return nil, fmt.Errorf("S2b Create Session Response missing PGW control TEID")
	}
	if result.PGWUserTEID == 0 {
		return nil, fmt.Errorf("S2b Create Session Response missing PGW user TEID")
	}
	return result, nil
}

func (c *Client) requestPCOIEs() []ie {
	request, apco := c.requestPCO()
	if request == nil && apco == nil {
		return nil
	}
	var ies []ie
	if request != nil {
		if payload, err := pco.Encode(*request); err == nil {
			ies = append(ies, ie{Type: iePCO, Payload: payload})
		}
	}
	if apco != nil {
		if payload, err := pco.Encode(*apco); err == nil {
			ies = append(ies, ie{Type: ieAPCO, Payload: payload})
		}
	}
	return ies
}

func (c *Client) requestPCO() (*pco.PCO, *pco.PCO) {
	if !c.cfg.PCO.Enabled || (!c.cfg.PCO.RequestDNS && !c.cfg.PCO.RequestPCSCF && !c.cfg.PCO.RequestMTU) {
		return nil, nil
	}
	req := pco.Request(c.cfg.PCO.RequestDNS, c.cfg.PCO.RequestPCSCF, c.cfg.PCO.RequestMTU)
	if len(req.Containers) == 0 {
		return nil, nil
	}
	if c.cfg.PCO.IncludeAPCO {
		apcoReq := req
		return &req, &apcoReq
	}
	return &req, nil
}

func (c *Client) parsePCOIE(ies []ie, typ uint8) (*pco.Decoded, error) {
	if !c.cfg.PCO.Enabled {
		return nil, nil
	}
	raw, ok := findIE(ies, typ, 0)
	if !ok {
		return nil, nil
	}
	decoded, err := pco.Decode(raw.Payload, c.cfg.PCO.StrictDecode)
	if err != nil {
		if c.cfg.PCO.StrictDecode {
			return nil, fmt.Errorf("S2b PCO/APCO IE %d strict decode failed: %w", typ, err)
		}
		c.log.Warn("S2b PCO decode failed", "ie_type", typ, "error", err)
		return nil, nil
	}
	return decoded, nil
}

func (c *Client) logPCO(label, imsi, apn string, decoded *pco.Decoded) {
	if decoded == nil || decoded.PCO == nil {
		c.log.Info(label+" absent", "imsi", imsi, "apn", apn)
		return
	}
	mtu := any(nil)
	if decoded.MTU != nil {
		mtu = *decoded.MTU
	}
	c.log.Info(label+" received",
		"imsi", imsi,
		"apn", apn,
		"container_count", len(decoded.PCO.Containers),
		"protocol_ids", pco.ProtocolIDs(decoded.PCO.Containers),
		"known_dns_v4", pco.IPStrings(decoded.DNSv4),
		"known_dns_v6", pco.IPStrings(decoded.DNSv6),
		"known_pcscf_v4", pco.IPStrings(decoded.PCSCFv4),
		"known_pcscf_v6", pco.IPStrings(decoded.PCSCFv6),
		"mtu", mtu,
		"unsupported_count", len(decoded.Unsupported),
	)
	if len(decoded.PCSCFv4) > 0 || len(decoded.PCSCFv6) > 0 {
		c.log.Info(label+" P-CSCF queued for SWu delivery",
			"imsi", imsi,
			"apn", apn,
			"pcscf_v4", pco.IPStrings(decoded.PCSCFv4),
			"pcscf_v6", pco.IPStrings(decoded.PCSCFv6),
		)
	}
	if decoded.MTU != nil {
		c.log.Info(label+" MTU stored but not delivered over SWu", "imsi", imsi, "apn", apn, "mtu", *decoded.MTU)
	}
}

func findFTEIDByInterface(ies []ie, wantIface uint8, fallbackInstances ...uint8) (uint8, uint32, net.IP, bool) {
	for _, e := range ies {
		if e.Type != ieFTEID {
			continue
		}
		iface, teid, ip, ok := parseFTEID(e)
		if ok && iface == wantIface {
			return iface, teid, ip, true
		}
	}
	for _, instance := range fallbackInstances {
		if e, ok := findIE(ies, ieFTEID, instance); ok {
			iface, teid, ip, parsed := parseFTEID(e)
			if parsed {
				return iface, teid, ip, true
			}
		}
	}
	return 0, 0, nil, false
}

func findAnyFTEID(ies []ie) (uint8, uint32, net.IP, bool) {
	for _, e := range ies {
		if e.Type != ieFTEID {
			continue
		}
		iface, teid, ip, ok := parseFTEID(e)
		if ok {
			return iface, teid, ip, true
		}
	}
	return 0, 0, nil, false
}

func ieTypesFromPayload(payload []byte) []uint8 {
	ies, err := decodeIEs(payload)
	if err != nil {
		return nil
	}
	return ieTypes(ies)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func lenHexBytes(s string) int {
	return len(s) / 2
}

const (
	t3Response = 3 * time.Second
	n3Requests = 3
)

func (c *Client) transaction(ctx context.Context, req message, expected uint8) (message, error) {
	encoded, err := req.encode()
	if err != nil {
		return message{}, fmt.Errorf("encode GTPv2-C request type=%d seq=%d: %w", req.Type, req.Sequence, err)
	}
	ch := make(chan message, 1)
	c.mu.Lock()
	c.pending[req.Sequence] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, req.Sequence)
		c.mu.Unlock()
	}()
	for attempt := 1; attempt <= n3Requests; attempt++ {
		if _, err := c.conn.WriteToUDP(encoded, c.peer); err != nil {
			return message{}, fmt.Errorf("send GTPv2-C request type=%d seq=%d peer=%s: %w", req.Type, req.Sequence, c.peer.String(), err)
		}
		if attempt > 1 {
			c.log.Warn("S2b GTPv2-C request retransmitted",
				"request_type", req.Type,
				"seq", req.Sequence,
				"attempt", attempt,
				"max_attempts", n3Requests,
			)
		}
		c.log.Debug("S2b GTPv2-C transaction waiting for response",
			"request_type", req.Type,
			"expected_type", expected,
			"seq", req.Sequence,
			"teid", req.TEID,
			"attempt", attempt,
		)
		select {
		case resp := <-ch:
			if resp.Type != expected {
				c.log.Warn("S2b pending response not matched",
					"incoming_type", resp.Type,
					"incoming_seq", resp.Sequence,
					"expected_type", expected,
					"expected_seq", req.Sequence,
					"reason", "type_mismatch",
				)
				return message{}, fmt.Errorf("expected GTPv2-C message %d, got %d", expected, resp.Type)
			}
			return resp, nil
		case <-time.After(t3Response):
			if ctx.Err() != nil {
				return message{}, fmt.Errorf("wait for GTPv2-C response type=%d seq=%d: %w", expected, req.Sequence, ctx.Err())
			}
		case <-ctx.Done():
			return message{}, fmt.Errorf("wait for GTPv2-C response type=%d seq=%d: %w", expected, req.Sequence, ctx.Err())
		}
	}
	return message{}, fmt.Errorf("GTPv2-C no response after %d retransmissions type=%d seq=%d peer=%s", n3Requests, req.Type, req.Sequence, c.peer.String())
}

func (c *Client) readLoop(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, peer, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			c.log.Warn("S2b GTPv2-C read failed", "error", err)
			continue
		}
		msg, err := decodeMessage(buf[:n])
		if err != nil {
			c.log.Warn("S2b GTPv2-C decode failed", "peer", peer.String(), "error", err)
			continue
		}
		c.mu.Lock()
		ch := c.pending[msg.Sequence]
		pendingMatch := ch != nil
		c.mu.Unlock()
		dispatch := "ignored"
		if msg.Type == msgEchoRequest {
			c.log.Debug("S2b GTPv2-C message received", "peer", peer.String(), "type", msg.Type, "seq", msg.Sequence, "teid", msg.TEID, "pending_match", pendingMatch, "dispatch", "echo_request")
			c.handleEchoRequest(msg, peer)
			continue
		}
		if msg.Type == msgDeleteSessionReq {
			c.log.Debug("S2b GTPv2-C message received", "peer", peer.String(), "type", msg.Type, "seq", msg.Sequence, "teid", msg.TEID, "pending_match", pendingMatch, "dispatch", "delete_session")
			c.handleDeleteSessionRequest(ctx, msg, peer)
			continue
		}
		if msg.Type == msgCreateBearerReq {
			c.log.Debug("S2b GTPv2-C message received", "peer", peer.String(), "type", msg.Type, "seq", msg.Sequence, "teid", msg.TEID, "pending_match", pendingMatch, "dispatch", "create_bearer")
			c.handleCreateBearerRequest(ctx, msg, peer)
			continue
		}
		if msg.Type == msgDeleteBearerReq {
			c.log.Debug("S2b GTPv2-C message received", "peer", peer.String(), "type", msg.Type, "seq", msg.Sequence, "teid", msg.TEID, "pending_match", pendingMatch, "dispatch", "delete_bearer")
			c.handleDeleteBearerRequest(ctx, msg, peer)
			continue
		}
		if msg.Type == msgUpdateBearerReq {
			c.log.Debug("S2b GTPv2-C message received", "peer", peer.String(), "type", msg.Type, "seq", msg.Sequence, "teid", msg.TEID, "pending_match", pendingMatch, "dispatch", "update_bearer")
			c.handleUpdateBearerRequest(ctx, msg, peer)
			continue
		}
		if ch != nil {
			dispatch = "pending_response"
			c.log.Debug("S2b GTPv2-C message received", "peer", peer.String(), "type", msg.Type, "seq", msg.Sequence, "teid", msg.TEID, "pending_match", true, "dispatch", dispatch)
			ch <- msg
			continue
		}
		c.log.Debug("S2b GTPv2-C message received", "peer", peer.String(), "type", msg.Type, "seq", msg.Sequence, "teid", msg.TEID, "pending_match", false, "dispatch", dispatch)
		c.log.Debug("S2b GTPv2-C message ignored", "type", msg.Type, "seq", msg.Sequence, "teid", msg.TEID, "peer", peer.String(), "reason", "no_pending_request")
	}
}

func (c *Client) handleDeleteSessionRequest(ctx context.Context, req message, peer *net.UDPAddr) {
	resp := message{
		Type:     msgDeleteSessionResp,
		TEID:     req.TEID,
		HasTEID:  true,
		Sequence: req.Sequence,
		Payload:  ie{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}}.encode(),
	}
	encoded, err := resp.encode()
	if err != nil {
		c.log.Warn("S2b Delete Session Response encode failed", "error", err)
		return
	}
	if _, err := c.conn.WriteToUDP(encoded, peer); err != nil {
		c.log.Warn("S2b Delete Session Response send failed", "peer", peer.String(), "error", err)
		return
	}
	c.log.Info("PGW Delete Session Request received",
		"peer", peer.String(),
		"local_control_teid", req.TEID,
		"seq", req.Sequence,
	)
	c.mu.Lock()
	handler := c.deleteHandler
	c.mu.Unlock()
	if handler != nil {
		event := DeleteSessionEvent{LocalControlTEID: req.TEID, Sequence: req.Sequence, Peer: peer.String()}
		if ies, err := decodeIEs(req.Payload); err == nil {
			if ind, ok := findIEAnyInstance(ies, ieIndication); ok && len(ind.Payload) >= 3 {
				event.IsHandover = ind.Payload[2]&0x02 != 0
			}
		}
		go handler(ctx, event)
	}
}

func (c *Client) handleEchoRequest(req message, peer *net.UDPAddr) {
	resp := message{
		Type:     msgEchoResponse,
		HasTEID:  req.HasTEID,
		Sequence: req.Sequence,
		Payload:  recoveryIE(uint8(c.cfg.GTP.Recovery)).encode(),
	}
	encoded, err := resp.encode()
	if err != nil {
		c.log.Warn("S2b Echo Response encode failed", "error", err)
		return
	}
	if _, err := c.conn.WriteToUDP(encoded, peer); err != nil {
		c.log.Warn("S2b Echo Response send failed", "peer", peer.String(), "error", err)
		return
	}
	c.log.Debug("S2b Echo Request handled", "peer", peer.String(), "seq", req.Sequence, "recovery", c.cfg.GTP.Recovery)
}

func (c *Client) handleCreateBearerRequest(ctx context.Context, req message, peer *net.UDPAddr) {
	cacheKey := createBearerCacheKey(peer, req)
	if cached, ok := c.cachedCreateBearerResponse(cacheKey); ok {
		if _, err := c.conn.WriteToUDP(cached.Encoded, peer); err != nil {
			c.log.Warn("S2b Create Bearer cached response send failed", "peer", peer.String(), "seq", req.Sequence, "teid", req.TEID, "error", err)
			return
		}
		c.log.Info("S2b Create Bearer duplicate request detected",
			"peer", peer.String(),
			"teid", fmt.Sprintf("0x%08x", req.TEID),
			"seq", req.Sequence,
			"action", "resend_cached_response",
			"bearers", cached.BearerEBI,
		)
		return
	}
	c.log.Info("S2b Create Bearer Request received",
		"peer", peer.String(),
		"seq", req.Sequence,
		"local_control_teid", req.TEID,
		"payload_hex", hex.EncodeToString(req.Payload),
	)
	event, err := parseCreateBearerRequest(req, peer)
	if err != nil {
		for _, topEBI := range event.TopLevelEBIs {
			c.log.Info("S2b Create Bearer top-level EBI found",
				"payload_hex", topEBI.PayloadHex,
				"decoded_ebi", topEBI.EBI,
				"has_ebi", topEBI.HasEBI,
				"error", topEBI.DecodeError,
			)
		}
		for _, bearer := range event.BearerContexts {
			c.log.Info("S2b Create Bearer Bearer Context raw",
				"bearer_context_index", bearer.Index,
				"instance", bearer.Instance,
				"length", bearer.Length,
				"raw_ie_hex", bearer.RawIEHex,
				"payload_hex", bearer.PayloadHex,
				"child_ie_types", bearer.RawChildIETypes,
			)
		}
		for _, bearer := range event.BearerContexts {
			c.log.Info("S2b Create Bearer EBI child IE raw",
				"bearer_context_index", bearer.Index,
				"child_offset", bearer.EBIChildOffset,
				"raw_ie_hex", bearer.EBIRawIEHex,
				"type", ieEBI,
				"length", bearer.EBILength,
				"instance", bearer.EBIInstance,
				"computed_payload_hex", bearer.EBIPayloadHex,
				"payload_len", lenHexBytes(bearer.EBIPayloadHex),
				"decoded_ebi", bearer.EBI,
				"has_ebi", bearer.HasEBI,
			)
			if bearer.EBIDecodeError != "" && !bearer.UnassignedEBI {
				c.log.Warn("S2b Create Bearer EBI decode failed",
					"bearer_context_index", bearer.Index,
					"child_offset", bearer.EBIChildOffset,
					"raw_ie_hex", bearer.EBIRawIEHex,
					"payload_len", lenHexBytes(bearer.EBIPayloadHex),
					"payload_hex", bearer.EBIPayloadHex,
					"error", bearer.EBIDecodeError,
				)
			}
		}
		c.log.Warn("S2b Create Bearer Request parse failed",
			"peer", peer.String(),
			"seq", req.Sequence,
			"local_control_teid", req.TEID,
			"error", err,
			"response_sent", true,
			"cause", causeContextNotFound,
		)
		c.sendBearerResponse(peer, message{Type: msgCreateBearerResp, TEID: req.TEID, HasTEID: true, Sequence: req.Sequence, Payload: ie{Type: ieCause, Payload: []byte{causeContextNotFound, 0}}.encode()})
		return
	}
	c.log.Info("S2b Create Bearer top-level IE summary", "top_level_ie_types", ieTypesFromPayload(req.Payload))
	for _, topEBI := range event.TopLevelEBIs {
		c.log.Info("S2b Create Bearer top-level EBI found",
			"payload_hex", topEBI.PayloadHex,
			"decoded_ebi", topEBI.EBI,
			"has_ebi", topEBI.HasEBI,
			"error", topEBI.DecodeError,
		)
	}
	for _, bearer := range event.BearerContexts {
		c.log.Info("S2b Create Bearer Bearer Context found",
			"bearer_context_index", bearer.Index,
			"instance", bearer.Instance,
			"child_ie_types", bearer.RawChildIETypes,
		)
		c.log.Info("S2b Create Bearer Bearer Context raw",
			"bearer_context_index", bearer.Index,
			"instance", bearer.Instance,
			"length", bearer.Length,
			"raw_ie_hex", bearer.RawIEHex,
			"payload_hex", bearer.PayloadHex,
			"child_ie_types", bearer.RawChildIETypes,
		)
		c.log.Info("S2b Create Bearer EBI child IE raw",
			"bearer_context_index", bearer.Index,
			"child_offset", bearer.EBIChildOffset,
			"raw_ie_hex", bearer.EBIRawIEHex,
			"type", ieEBI,
			"length", bearer.EBILength,
			"instance", bearer.EBIInstance,
			"computed_payload_hex", bearer.EBIPayloadHex,
			"payload_len", lenHexBytes(bearer.EBIPayloadHex),
			"decoded_ebi", bearer.EBI,
			"has_ebi", bearer.HasEBI,
		)
		if bearer.EBIDecodeError != "" && !bearer.UnassignedEBI {
			c.log.Warn("S2b Create Bearer EBI decode failed",
				"bearer_context_index", bearer.Index,
				"child_offset", bearer.EBIChildOffset,
				"raw_ie_hex", bearer.EBIRawIEHex,
				"payload_len", lenHexBytes(bearer.EBIPayloadHex),
				"payload_hex", bearer.EBIPayloadHex,
				"error", bearer.EBIDecodeError,
			)
		}
		if !bearer.HasEBI || bearer.PGWUserTEID == 0 {
			continue
		}
		c.log.Info("S2b Create Bearer F-TEID parsed",
			"ebi", bearer.EBI,
			"interface_type", ifaceS2BPGWGTPU,
			"teid", bearer.PGWUserTEID,
			"ipv4", ipString(bearer.PGWUserIP),
			"pgw_fteid_instance", bearer.PGWFTEIDInst,
			"pgw_fteid_iface", bearer.PGWFTEIDIface,
			"pgw_fteid_raw_hex", bearer.PGWFTEIDRawHex,
		)
		c.log.Info("S2b Create Bearer QoS parsed",
			"ebi", bearer.EBI,
			"qci", bearer.QCI,
			"has_bearer_qos", bearer.HasBearerQoS,
		)
		c.log.Info("S2b Create Bearer TFT parsed",
			"ebi", bearer.EBI,
			"raw_len", len(bearer.TFTRaw),
		)
	}
	c.mu.Lock()
	handler := c.createBearerHandler
	c.mu.Unlock()
	result := CreateBearerResult{Cause: causeContextNotFound}
	if handler != nil {
		result = handler(ctx, event)
	}
	if result.Cause == 0 {
		result.Cause = causeRequestAccepted
	}
	bearerResults := result.Bearers
	if len(bearerResults) == 0 {
		bearerResults = []CreateBearerBearerResult{{
			EBI:           event.EBI,
			Accepted:      result.Accepted,
			Cause:         result.Cause,
			LocalUserTEID: result.LocalUserTEID,
			LocalUserIP:   result.LocalUserIP,
			QCI:           event.QCI,
		}}
	}
	result.Bearers = bearerResults
	// Propagate QCI from CBR request bearer contexts to response bearers by position.
	for i := range result.Bearers {
		if result.Bearers[i].QCI == 0 && i < len(event.Bearers) {
			result.Bearers[i].QCI = event.Bearers[i].QCI
		}
	}
	resp := c.createBearerResponseMessage(req, result)
	bearerEBIs := createBearerResultEBIs(bearerResults)
	const logFTEIDIface = ifaceS2BePDGGTPU
	const logFTEIDInstance = uint8(8)
	payloadIEs, _ := decodeIEs(resp.Payload)
	for i, top := range payloadIEs {
		if top.Type != ieBearerContext {
			continue
		}
		children, err := decodeIEs(top.Payload)
		if err != nil {
			continue
		}
		ebi := uint8(0)
		if ebiIE, ok := findIE(children, ieEBI, 0); ok {
			ebi, _ = parseEBI(ebiIE.Payload)
		}
		cause := uint8(0)
		if causeIE, ok := findIE(children, ieCause, 0); ok && len(causeIE.Payload) > 0 {
			cause = causeIE.Payload[0]
		}
		var fteidTEID uint32
		var fteidIP net.IP
		var fteidFoundInstance uint8
		fteidPresent := false
		if fteid, ok := findIE(children, ieFTEID, logFTEIDInstance); ok {
			fteidFoundInstance = fteid.Instance
			_, fteidTEID, fteidIP, fteidPresent = parseFTEID(fteid)
		}
		c.log.Info("S2b Create Bearer Response F-TEID semantic",
			"semantic", "s2b_epdg_data_teid",
			"ie_type", ieFTEID,
			"ie_instance", logFTEIDInstance,
			"interface_type", logFTEIDIface,
		)
		c.log.Info("S2b Create Bearer Response bearer context encoded",
			"seq", req.Sequence,
			"bearer_index", i-1,
			"ebi", ebi,
			"cause", cause,
			"fteid_ie_present", fteidPresent,
			"fteid_ie_instance", fteidFoundInstance,
			"fteid_interface_type", logFTEIDIface,
			"fteid_interface_name", fteidInterfaceName(logFTEIDIface),
			"fteid_teid", fteidTEID,
			"fteid_ipv4", ipString(fteidIP),
			"raw_bearer_context_hex", hex.EncodeToString(top.encode()),
		)
	}
	encoded, err := resp.encode()
	if err != nil {
		c.log.Warn("S2b bearer response encode failed", "type", resp.Type, "error", err)
		return
	}
	c.cacheCreateBearerResponse(cacheKey, encoded, bearerEBIs)
	c.log.Info("S2b Create Bearer Response encoded",
		"peer", peer.String(),
		"seq", req.Sequence,
		"teid", fmt.Sprintf("0x%08x", resp.TEID),
		"response_hex", hex.EncodeToString(encoded),
		"bearers", bearerEBIs,
	)
	if _, err := c.conn.WriteToUDP(encoded, peer); err != nil {
		c.log.Warn("S2b bearer response send failed", "type", resp.Type, "peer", peer.String(), "error", err)
		return
	}
	c.log.Info("S2b Create Bearer Response sent",
		"peer", peer.String(),
		"local_control_teid", event.LocalControlTEID,
		"bearer_ebis", bearerEBIs,
		"cause", result.Cause,
		"local_rx_teid", result.LocalUserTEID,
		"bearer_count", len(bearerResults),
	)
	c.log.Info("PGW Create Bearer Request handled",
		"peer", peer.String(),
		"local_control_teid", event.LocalControlTEID,
		"ebi", event.EBI,
		"pgw_user_teid", event.PGWUserTEID,
		"local_user_teid", result.LocalUserTEID,
		"qci", event.QCI,
		"cause", result.Cause,
	)
}

func (c *Client) handleDeleteBearerRequest(ctx context.Context, req message, peer *net.UDPAddr) {
	event, err := parseDeleteBearerRequest(req, peer)
	if err != nil {
		c.log.Warn("S2b Delete Bearer Request parse failed", "peer", peer.String(), "seq", req.Sequence, "error", err)
		c.sendBearerResponse(peer, message{Type: msgDeleteBearerResp, TEID: req.TEID, HasTEID: true, Sequence: req.Sequence, Payload: ie{Type: ieCause, Payload: []byte{causeContextNotFound, 0}}.encode()})
		return
	}
	c.mu.Lock()
	handler := c.deleteBearerHandler
	c.mu.Unlock()
	result := DeleteBearerResult{Cause: causeContextNotFound}
	if handler != nil {
		result = handler(ctx, event)
	}
	if result.Cause == 0 {
		result.Cause = causeRequestAccepted
	}
	// TS 29.274 §6.1.1: response TEID must be the PGW's control TEID, not ePDG's own local TEID.
	teid := req.TEID
	if result.PGWControlTEID != 0 {
		teid = result.PGWControlTEID
	}
	var children []ie
	children = append(children, ie{Type: ieCause, Payload: []byte{result.Cause, 0}})
	for _, ebi := range event.EBIs {
		children = append(children, ebiValueIE(ebi))
	}
	resp := message{
		Type:     msgDeleteBearerResp,
		TEID:     teid,
		HasTEID:  true,
		Sequence: req.Sequence,
		Payload: encodeIEs(
			ie{Type: ieCause, Payload: []byte{result.Cause, 0}},
			ie{Type: ieBearerContext, Payload: encodeIEs(children...)},
		),
	}
	c.sendBearerResponse(peer, resp)
	c.log.Info("PGW Delete Bearer Request handled",
		"peer", peer.String(),
		"local_control_teid", event.LocalControlTEID,
		"ebis", event.EBIs,
		"cause", result.Cause,
	)
}

func (c *Client) handleUpdateBearerRequest(ctx context.Context, req message, peer *net.UDPAddr) {
	event, err := parseUpdateBearerRequest(req, peer)
	if err != nil {
		c.log.Warn("S2b Update Bearer Request parse failed", "peer", peer.String(), "seq", req.Sequence, "error", err)
		c.sendBearerResponse(peer, message{Type: msgUpdateBearerResp, TEID: req.TEID, HasTEID: true, Sequence: req.Sequence, Payload: ie{Type: ieCause, Payload: []byte{causeContextNotFound, 0}}.encode()})
		return
	}
	c.mu.Lock()
	handler := c.updateBearerHandler
	c.mu.Unlock()
	result := UpdateBearerResult{Cause: causeContextNotFound}
	if handler != nil {
		result = handler(ctx, event)
	}
	if result.Cause == 0 {
		result.Cause = causeRequestAccepted
	}
	// TS 29.274 §6.1.1: response TEID must be the PGW's control TEID, not ePDG's own local TEID.
	teid := req.TEID
	if result.PGWControlTEID != 0 {
		teid = result.PGWControlTEID
	}
	payloadIEs := []ie{ie{Type: ieCause, Payload: []byte{result.Cause, 0}}}
	for _, bc := range event.Bearers {
		children := []ie{
			{Type: ieCause, Payload: []byte{result.Cause, 0}},
			ebiValueIE(bc.EBI),
		}
		payloadIEs = append(payloadIEs, ie{Type: ieBearerContext, Payload: encodeIEs(children...)})
	}
	resp := message{
		Type:     msgUpdateBearerResp,
		TEID:     teid,
		HasTEID:  true,
		Sequence: req.Sequence,
		Payload:  encodeIEs(payloadIEs...),
	}
	c.sendBearerResponse(peer, resp)
	c.log.Info("PGW Update Bearer Request handled",
		"peer", peer.String(),
		"local_control_teid", event.LocalControlTEID,
		"bearer_count", len(event.Bearers),
		"cause", result.Cause,
	)
}

func parseUpdateBearerRequest(req message, peer *net.UDPAddr) (UpdateBearerEvent, error) {
	ies, err := decodeIEs(req.Payload)
	if err != nil {
		return UpdateBearerEvent{}, err
	}
	event := UpdateBearerEvent{LocalControlTEID: req.TEID, Sequence: req.Sequence, Peer: peer.String()}
	for _, top := range ies {
		if top.Type != ieBearerContext {
			continue
		}
		children, err := decodeIEs(top.Payload)
		if err != nil {
			return event, err
		}
		bc := UpdateBearerContext{}
		for _, child := range children {
			switch child.Type {
			case ieEBI:
				if ebi, err := parseEBI(child.Payload); err == nil {
					bc.EBI = ebi
				}
			case ieBearerQoS:
				bc.HasBearerQoS = true
				if len(child.Payload) > 1 {
					bc.QCI = child.Payload[1]
				}
			case ieTFT:
				bc.TFTRaw = append([]byte(nil), child.Payload...)
				bc.HasTFT = true
			}
		}
		if bc.EBI != 0 {
			event.Bearers = append(event.Bearers, bc)
		}
	}
	if len(event.Bearers) == 0 {
		return event, fmt.Errorf("Update Bearer Request missing Bearer Context with valid EBI")
	}
	return event, nil
}

func (c *Client) sendBearerResponse(peer *net.UDPAddr, resp message) {
	encoded, err := resp.encode()
	if err != nil {
		c.log.Warn("S2b bearer response encode failed", "type", resp.Type, "error", err)
		return
	}
	if _, err := c.conn.WriteToUDP(encoded, peer); err != nil {
		c.log.Warn("S2b bearer response send failed", "type", resp.Type, "peer", peer.String(), "error", err)
	}
}

func (c *Client) createBearerResponseMessage(req message, result CreateBearerResult) message {
	if result.Cause == 0 {
		result.Cause = causeRequestAccepted
	}
	bearerResults := result.Bearers
	if len(bearerResults) == 0 {
		bearerResults = []CreateBearerBearerResult{{
			EBI:           0,
			Accepted:      result.Accepted,
			Cause:         result.Cause,
			LocalUserTEID: result.LocalUserTEID,
			LocalUserIP:   result.LocalUserIP,
		}}
	}
	payloadIEs := []ie{ie{Type: ieCause, Payload: []byte{result.Cause, 0}}}
	for _, br := range bearerResults {
		// Cisco StarOS 21.28 ePDG Admin Guide §16c: bearer context order is
		// EBI → Cause → S2b-U ePDG F-TEID → S2b-U PGW F-TEID (echo from request).
		// StarOS validates for the echoed PGW F-TEID and reports
		// "SGW Data TEID (Bearer Context) missing" when it is absent.
		cause := br.Cause
		if cause == 0 {
			cause = result.Cause
		}
		children := []ie{ebiValueIE(br.EBI), {Type: ieCause, Payload: []byte{cause, 0}}}
		if br.Accepted && br.LocalUserTEID != 0 {
			ip := br.LocalUserIP
			if ip == nil {
				ip = net.ParseIP(c.cfg.GTP.LocalGTPU)
			}
			// TS 29.274 Table 7.2.4-2: S2b-U ePDG GTP-U at instance=8, iface=31.
			children = append(children, fteidIE(8, ifaceS2BePDGGTPU, br.LocalUserTEID, ip))
			// TS 29.274 Table 7.2.4-2: S2b-U PGW GTP-U echo at instance=9, iface=33.
			if br.PGWUserTEID != 0 {
				pgwIP := br.PGWUserIP
				if pgwIP == nil {
					pgwIP = net.ParseIP(c.cfg.GTP.PGWGTPU)
				}
				children = append(children, fteidIE(9, ifaceS2BPGWGTPU, br.PGWUserTEID, pgwIP))
			}
			// Cisco ePDG admin guide §16c: CBR response bearer context is
			// (EBI, Cause, S2b-U ePDG F-TEID, S2b-U PGW F-TEID) — QoS omitted.
			// Echo the Charging ID from the CBR request. StarOS uses it to match
			// response bearer contexts to their request counterparts.
			if br.HasChargingID {
				cid := make([]byte, 4)
				binary.BigEndian.PutUint32(cid, br.ChargingID)
				children = append(children, ie{Type: ieChargingID, Payload: cid})
			}
		}
		// StarOS qvpc-si sends all CBR request bearer contexts at instance=0 and
		// rejects any response BC at instance≠0 as "unexpected". Use instance=0 for all.
		payloadIEs = append(payloadIEs, ie{Type: ieBearerContext, Instance: 0, Payload: encodeIEs(children...)})
	}
	// Recovery IE is standard in GTPv2-C responses (TS 29.274 Table 7.2.4-1).
	payloadIEs = append(payloadIEs, recoveryIE(uint8(c.cfg.GTP.Recovery)))
	// TS 29.274 §6.1.1: response TEID = PGW's control TEID so StarOS routes
	// the message to the right session. The CBR request carried ePDG's local TEID
	// in the header; the response must address the PGW's TEID instead.
	teid := req.TEID
	if result.PGWControlTEID != 0 {
		teid = result.PGWControlTEID
	}
	return message{
		Type:     msgCreateBearerResp,
		TEID:     teid,
		HasTEID:  true,
		Sequence: req.Sequence,
		Payload:  encodeIEs(payloadIEs...),
	}
}

func createBearerResultEBIs(results []CreateBearerBearerResult) []uint8 {
	ebis := make([]uint8, 0, len(results))
	for _, result := range results {
		ebis = append(ebis, result.EBI)
	}
	return ebis
}

func createBearerCacheKey(peer *net.UDPAddr, req message) string {
	return fmt.Sprintf("%s|%d|%d|%d", peer.String(), req.TEID, req.Sequence, req.Type)
}

func (c *Client) cachedCreateBearerResponse(key string) (createBearerResponseCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeExpiredCreateBearerCacheLocked(time.Now())
	entry, ok := c.createBearerCache[key]
	if !ok {
		return createBearerResponseCacheEntry{}, false
	}
	return entry, true
}

func (c *Client) cacheCreateBearerResponse(key string, encoded []byte, ebis []uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.purgeExpiredCreateBearerCacheLocked(now)
	c.createBearerCache[key] = createBearerResponseCacheEntry{
		Encoded:   append([]byte(nil), encoded...),
		BearerEBI: append([]uint8(nil), ebis...),
		Expires:   now.Add(60 * time.Second),
	}
}

func (c *Client) purgeExpiredCreateBearerCacheLocked(now time.Time) {
	for key, entry := range c.createBearerCache {
		if now.After(entry.Expires) {
			delete(c.createBearerCache, key)
		}
	}
}

func fteidInterfaceName(iface uint8) string {
	switch iface {
	case ifaceS5S8SGWGTPU:
		return "s5s8_sgw_gtpu"
	case ifaceS5S8PGWGTPU:
		return "s5s8_pgw_gtpu"
	case ifaceS2BePDGGTPU:
		return "s2b_epdg_gtpu"
	case ifaceS2BPGWGTPU:
		return "s2b_pgw_gtpu"
	default:
		return fmt.Sprintf("interface_%d", iface)
	}
}

func parseCreateBearerRequest(req message, peer *net.UDPAddr) (CreateBearerEvent, error) {
	ies, err := decodeIEsWithRaw(req.Payload)
	if err != nil {
		return CreateBearerEvent{}, err
	}
	event := CreateBearerEvent{LocalControlTEID: req.TEID, Sequence: req.Sequence, Peer: peer.String()}
	hasBearerContext := false
	var summaries []string
	bearerContextIndex := 0
	for _, top := range ies {
		if top.Type == ieEBI {
			topEBI := CreateBearerEBI{
				PayloadHex: hex.EncodeToString(top.Payload),
				RawIEHex:   hex.EncodeToString(top.Raw),
				Offset:     top.Offset,
				Length:     top.Length,
				Instance:   top.Instance,
			}
			if ebi, err := parseEBI(top.Payload); err == nil {
				topEBI.EBI = ebi
				topEBI.HasEBI = true
				if event.LinkedDefaultEBI == 0 {
					event.LinkedDefaultEBI = ebi
				}
			} else {
				topEBI.DecodeError = err.Error()
			}
			event.TopLevelEBIs = append(event.TopLevelEBIs, topEBI)
		}
		if top.Type != ieBearerContext {
			continue
		}
		hasBearerContext = true
		children, err := decodeIEsWithRaw(top.Payload)
		if err != nil {
			return event, err
		}
		ctx := CreateBearerContext{
			Index:           bearerContextIndex,
			Instance:        top.Instance,
			RawIEHex:        hex.EncodeToString(top.Raw),
			PayloadHex:      hex.EncodeToString(top.Payload),
			Length:          top.Length,
			RawChildIETypes: ieTypesFromDecoded(children),
		}
		bearerContextIndex++
		for _, child := range children {
			switch child.Type {
			case ieEBI:
				ctx.EBIPayloadHex = hex.EncodeToString(child.Payload)
				ctx.EBIRawIEHex = hex.EncodeToString(child.Raw)
				ctx.EBIChildOffset = child.Offset
				ctx.EBILength = child.Length
				ctx.EBIInstance = child.Instance
				if ebi, err := parseEBI(child.Payload); err == nil {
					ctx.EBI = ebi
					ctx.HasEBI = true
				} else {
					ctx.EBIDecodeError = err.Error()
					if len(child.Payload) == 1 && child.Payload[0] == 0 {
						ctx.UnassignedEBI = true
					}
				}
			case ieFTEID:
				if iface, teid, ip, ok := parseFTEID(child.ie); ok {
					ctx.PGWUserTEID = teid
					ctx.PGWUserIP = ip
					ctx.PGWFTEIDInst = child.Instance
					ctx.PGWFTEIDIface = iface
					ctx.PGWFTEIDRawHex = hex.EncodeToString(child.Raw)
				}
			case ieBearerQoS:
				ctx.HasBearerQoS = true
				ctx.BearerQoSRawLen = len(child.Payload)
				if len(child.Payload) > 1 {
					ctx.QCI = child.Payload[1]
				}
			case ieTFT:
				ctx.TFTRaw = append([]byte(nil), child.Payload...)
			case ieChargingID:
				if len(child.Payload) >= 4 {
					ctx.ChargingID = binary.BigEndian.Uint32(child.Payload[:4])
					ctx.HasChargingID = true
				}
			}
		}
		event.BearerContexts = append(event.BearerContexts, ctx)
		summaries = append(summaries, fmt.Sprintf("{index=%d instance=%d child_ie_types=%v ebi_raw_ie_hex=%s ebi_child_offset=%d ebi_payload_hex=%s parsed_ebi=%d has_ebi=%t unassigned_ebi=%t ebi_error=%q}", ctx.Index, ctx.Instance, ctx.RawChildIETypes, ctx.EBIRawIEHex, ctx.EBIChildOffset, ctx.EBIPayloadHex, ctx.EBI, ctx.HasEBI, ctx.UnassignedEBI, ctx.EBIDecodeError))
		if (ctx.HasEBI || ctx.UnassignedEBI) && ctx.PGWUserTEID != 0 {
			event.Bearers = append(event.Bearers, ctx)
		}
	}
	if len(event.Bearers) > 0 {
		first := event.Bearers[0]
		event.EBI = first.EBI
		event.PGWUserTEID = first.PGWUserTEID
		event.PGWUserIP = first.PGWUserIP
		event.QCI = first.QCI
		event.TFTRaw = append([]byte(nil), first.TFTRaw...)
	}
	if event.EBI == 0 {
		if len(event.Bearers) > 0 && event.LinkedDefaultEBI != 0 {
			return event, nil
		}
		if hasInvalidBearerContextEBI(event.BearerContexts) {
			return event, fmt.Errorf("Create Bearer Request EBI present but invalid/undecodable has_bearer_context=%t top_level_ie_types=%v bearer_contexts=%v", hasBearerContext, ieTypesFromDecoded(ies), summaries)
		}
		return event, fmt.Errorf("Create Bearer Request missing EBI has_bearer_context=%t top_level_ie_types=%v bearer_contexts=%v", hasBearerContext, ieTypesFromDecoded(ies), summaries)
	}
	if event.PGWUserTEID == 0 {
		return event, fmt.Errorf("Create Bearer Request missing PGW S2b-U F-TEID has_bearer_context=%t top_level_ie_types=%v bearer_contexts=%v", hasBearerContext, ieTypesFromDecoded(ies), summaries)
	}
	return event, nil
}

func hasInvalidBearerContextEBI(contexts []CreateBearerContext) bool {
	for _, ctx := range contexts {
		if ctx.EBIRawIEHex != "" && !ctx.HasEBI && !ctx.UnassignedEBI {
			return true
		}
	}
	return false
}

func parseDeleteBearerRequest(req message, peer *net.UDPAddr) (DeleteBearerEvent, error) {
	ies, err := decodeIEs(req.Payload)
	if err != nil {
		return DeleteBearerEvent{}, err
	}
	event := DeleteBearerEvent{LocalControlTEID: req.TEID, Sequence: req.Sequence, Peer: peer.String()}
	for _, e := range ies {
		if e.Type == ieCause && len(e.Payload) > 0 {
			// TS 29.274 Table 8.4-1: cause 10 = Access changed from Non-3GPP to 3GPP (VoWiFi→VoLTE).
			// Cause 8 (Reactivation Requested) kept as fallback for non-compliant PGW implementations.
			event.IsHandover = e.Payload[0] == causeAccessChangedTo3GPP || e.Payload[0] == causeReactivationRequested
		}
		if e.Type == ieEBI {
			if ebi, err := parseEBI(e.Payload); err == nil {
				event.EBIs = append(event.EBIs, ebi)
			}
		}
		if e.Type != ieBearerContext {
			continue
		}
		children, err := decodeIEs(e.Payload)
		if err != nil {
			return event, err
		}
		if ebiIE, ok := findIEAnyInstance(children, ieEBI); ok {
			if ebi, err := parseEBI(ebiIE.Payload); err == nil {
				event.EBIs = append(event.EBIs, ebi)
			}
		}
	}
	if len(event.EBIs) == 0 {
		return event, fmt.Errorf("Delete Bearer Request missing EBI")
	}
	return event, nil
}

func (c *Client) nextTEID(counter *atomic.Uint32) uint32 {
	for {
		next := counter.Add(1)
		if next != 0 {
			return next
		}
	}
}

func gtpAMBR(ulBps, dlBps uint64) (uint32, uint32, error) {
	if ulBps == 0 || dlBps == 0 {
		return 0, 0, fmt.Errorf("S2b Create Session requires APN AMBR from SWm")
	}
	ul := (ulBps + 999) / 1000
	dl := (dlBps + 999) / 1000
	if ul > math.MaxUint32 || dl > math.MaxUint32 {
		return 0, 0, fmt.Errorf("APN AMBR out of GTPv2-C range")
	}
	return uint32(ul), uint32(dl), nil
}
