package swm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/diameter"

	"github.com/ishidawataru/sctp"
)

const (
	diameterSuccess        uint32 = 2001
	diameterLimitedSuccess uint32 = 2002
)

type EAPState string

const (
	EAPStateChallenge EAPState = "challenge"
	EAPStateSuccess   EAPState = "success"
	EAPStateFailure   EAPState = "failure"
)

type EAPRequest struct {
	SessionID  string
	IMSI       string
	NAI        string
	APN        string
	EAPPayload []byte
}

type EAPResult struct {
	SessionID  string
	ResultCode uint32
	State      EAPState
	Allowed    bool
	IMSI       string
	NAI        string
	APN        string
	Reason     string
	EAPPayload []byte
	MSK        []byte
	APNProfile *APNProfile
}

type APNProfile struct {
	APN          string
	AMBRUplink   uint32
	AMBRDownlink uint32
	AMBRPresent  bool
}

type Client struct {
	cfg config.Config
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.RWMutex
	conn     net.Conn
	pending  map[uint32]chan diameterResponse
	openedCh chan struct{}
	writeMu  sync.Mutex
	nextHop  atomic.Uint32
	nextEnd  atomic.Uint32
}

type diameterResponse struct {
	msg diameter.Message
	err error
}

func NewClient(cfg config.Config, log *slog.Logger) *Client {
	c := &Client{
		cfg:      cfg,
		log:      log,
		pending:  make(map[uint32]chan diameterResponse),
		openedCh: make(chan struct{}),
	}
	c.nextHop.Store(uint32(time.Now().UnixNano()))
	c.nextEnd.Store(uint32(time.Now().Unix()))
	return c
}

func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.cancel != nil {
		c.mu.Unlock()
		return c.waitOpen(ctx)
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.mu.Unlock()
	c.log.Info("SWm Diameter client starting",
		"peer_addr", c.peerAddr(),
		"proto", c.cfg.SWM.Proto,
		"origin_host", c.cfg.SWM.OriginHost,
		"origin_realm", c.cfg.SWM.OriginRealm,
		"application_id", config.SWMApplicationID,
	)
	go c.connectLoop()
	return c.waitOpen(ctx)
}

func (c *Client) Stop() error {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.failPendingLocked(errors.New("SWm client stopped"))
	c.mu.Unlock()
	c.log.Info("SWm Diameter client stopped", "peer_addr", c.peerAddr())
	return nil
}

func (c *Client) ExchangeEAP(ctx context.Context, req EAPRequest) (*EAPResult, error) {
	if req.IMSI == "" {
		return nil, fmt.Errorf("SWm EAP exchange requires IMSI")
	}
	if req.APN == "" {
		return nil, fmt.Errorf("SWm EAP exchange requires APN")
	}
	if len(req.EAPPayload) == 0 {
		return nil, fmt.Errorf("SWm EAP exchange requires EAP payload")
	}
	if err := c.waitOpen(ctx); err != nil {
		return nil, err
	}
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("%s;%d", c.cfg.SWM.OriginHost, time.Now().UnixNano())
	}
	msg := c.newDER(sessionID, req.IMSI, req.APN, req.EAPPayload)
	c.log.Info("SWm DER sent",
		"session_id", sessionID,
		"imsi", req.IMSI,
		"nai", req.NAI,
		"apn", req.APN,
		"eap_payload_len", len(req.EAPPayload),
		"eap_id", eapID(req.EAPPayload),
	)
	answer, err := c.sendRequest(ctx, msg)
	if err != nil {
		return nil, err
	}
	return c.eapResult(req, sessionID, answer), nil
}

func (c *Client) connectLoop() {
	backoff := time.Second
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		conn, err := c.dial(c.ctx)
		if err != nil {
			c.log.Warn("SWm Diameter peer connect failed", "peer_addr", c.peerAddr(), "proto", c.cfg.SWM.Proto, "error", err)
			c.sleep(backoff)
			backoff = minDuration(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		if err := c.handshake(conn); err != nil {
			_ = conn.Close()
			c.log.Warn("SWm Diameter handshake failed", "peer_addr", c.peerAddr(), "error", err)
			c.sleep(backoff)
			continue
		}
		c.mu.Lock()
		c.conn = conn
		close(c.openedCh)
		c.openedCh = make(chan struct{})
		c.mu.Unlock()
		c.log.Info("SWm Diameter peer ready", "peer_addr", c.peerAddr())

		errCh := make(chan error, 1)
		go c.readLoop(conn, errCh)
		go c.watchdogLoop(conn)
		select {
		case <-c.ctx.Done():
			_ = conn.Close()
			return
		case err := <-errCh:
			_ = conn.Close()
			c.mu.Lock()
			if c.conn == conn {
				c.conn = nil
			}
			c.failPendingLocked(err)
			c.mu.Unlock()
			c.log.Warn("SWm Diameter peer disconnected", "peer_addr", c.peerAddr(), "error", err)
		}
	}
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	proto := strings.ToLower(strings.TrimSpace(c.cfg.SWM.Proto))
	if proto == "" {
		proto = "sctp"
	}
	switch proto {
	case "tcp":
		dialer := net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(ctx, "tcp", c.peerAddr())
	case "sctp":
		return c.dialSCTP(ctx)
	default:
		return nil, fmt.Errorf("unsupported SWm proto %q", c.cfg.SWM.Proto)
	}
}

func (c *Client) dialSCTP(ctx context.Context) (net.Conn, error) {
	raddr, err := sctp.ResolveSCTPAddr("sctp", c.peerAddr())
	if err != nil {
		return nil, err
	}
	var laddr *sctp.SCTPAddr
	if c.cfg.SWM.LocalAddr != "" {
		laddr, err = sctp.ResolveSCTPAddr("sctp", net.JoinHostPort(c.cfg.SWM.LocalAddr, "0"))
		if err != nil {
			return nil, err
		}
	}
	type result struct {
		conn *sctp.SCTPConn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := sctp.DialSCTP("sctp", laddr, raddr)
		ch <- result{conn: conn, err: err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		return res.conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("SCTP dial timeout")
	}
}

func (c *Client) handshake(conn net.Conn) error {
	localIP := c.localIPv4(conn)
	cer := c.newRequest(diameter.CommandCER, 0, false, []diameter.AVP{
		diameter.UTF8AVP(diameter.AVPOriginHost, 0, c.cfg.SWM.OriginHost),
		diameter.UTF8AVP(diameter.AVPOriginRealm, 0, c.cfg.SWM.OriginRealm),
		diameter.Uint32AVP(diameter.AVPOriginStateID, 0, uint32(time.Now().Unix())),
		diameter.AddressAVP(diameter.AVPHostIPAddress, localIP),
		diameter.Uint32AVP(diameter.AVPVendorID, 0, 0),
		diameter.UTF8AVPFlags(diameter.AVPProductName, 0, 0, "VectorCore ePDG"),
		diameter.Uint32AVPFlags(diameter.AVPFirmwareRevision, 0, 0, diameter.FirmwareRevOne),
		diameter.Uint32AVP(diameter.AVPInbandSecurityID, 0, diameter.InbandNoSec),
		diameter.Uint32AVP(diameter.AVPAuthApplicationID, 0, config.SWMApplicationID),
		diameter.Uint32AVP(diameter.AVPSupportedVendorID, 0, diameter.Vendor3GPP),
		diameter.Uint32AVP(diameter.AVPSupportedVendorID, 0, diameter.VendorETSI),
		diameter.GroupedAVP(diameter.AVPVendorSpecificApplicationID, 0,
			diameter.Uint32AVP(diameter.AVPVendorID, 0, config.SWMVendorID),
			diameter.Uint32AVP(diameter.AVPAuthApplicationID, 0, config.SWMApplicationID),
		),
	})
	if _, err := conn.Write(cer.Encode()); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	cea, err := diameter.DecodeMessage(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("peer closed or rejected CER before CEA: %w", err)
	}
	if cea.CommandCode != diameter.CommandCER || cea.IsRequest() {
		return fmt.Errorf("expected CEA, got command=%d request=%t", cea.CommandCode, cea.IsRequest())
	}
	rc, _ := diameter.AVPUint32(cea.AVPs, diameter.AVPResultCode, 0)
	c.log.Info("SWm CEA received", "peer_addr", c.peerAddr(), "diameter_result_code", rc)
	if rc != diameterSuccess && rc != diameterLimitedSuccess {
		return fmt.Errorf("CEA result code %d", rc)
	}
	return nil
}

func (c *Client) localIPv4(conn net.Conn) [4]byte {
	var out [4]byte
	if ip4 := net.ParseIP(c.cfg.SWM.LocalAddr).To4(); ip4 != nil {
		copy(out[:], ip4)
		return out
	}
	switch addr := conn.LocalAddr().(type) {
	case *net.TCPAddr:
		if ip4 := addr.IP.To4(); ip4 != nil {
			copy(out[:], ip4)
			return out
		}
	case *sctp.SCTPAddr:
		if len(addr.IPAddrs) > 0 {
			if ip4 := addr.IPAddrs[0].IP.To4(); ip4 != nil {
				copy(out[:], ip4)
				return out
			}
		}
	}
	copy(out[:], []byte{127, 0, 0, 1})
	return out
}

func (c *Client) readLoop(conn net.Conn, errCh chan<- error) {
	for {
		msg, err := diameter.DecodeMessage(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				errCh <- io.EOF
				return
			}
			errCh <- err
			return
		}
		if msg.IsRequest() {
			c.handleRequest(conn, msg)
			continue
		}
		c.mu.Lock()
		ch := c.pending[msg.HopByHop]
		delete(c.pending, msg.HopByHop)
		c.mu.Unlock()
		if ch != nil {
			ch <- diameterResponse{msg: msg}
		}
	}
}

func (c *Client) handleRequest(conn net.Conn, req diameter.Message) {
	switch req.CommandCode {
	case diameter.CommandDWR:
		resp := c.newAnswer(req, []diameter.AVP{
			diameter.UTF8AVP(diameter.AVPOriginHost, 0, c.cfg.SWM.OriginHost),
			diameter.UTF8AVP(diameter.AVPOriginRealm, 0, c.cfg.SWM.OriginRealm),
			diameter.Uint32AVP(diameter.AVPResultCode, 0, diameterSuccess),
		})
		c.writeMu.Lock()
		_, _ = conn.Write(resp.Encode())
		c.writeMu.Unlock()
	default:
		c.log.Warn("SWm inbound Diameter request ignored", "command_code", req.CommandCode, "application_id", req.AppID)
	}
}

func (c *Client) watchdogLoop(conn net.Conn) {
	ticker := time.NewTicker(c.watchdogInterval())
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			req := c.newRequest(diameter.CommandDWR, 0, false, []diameter.AVP{
				diameter.UTF8AVP(diameter.AVPOriginHost, 0, c.cfg.SWM.OriginHost),
				diameter.UTF8AVP(diameter.AVPOriginRealm, 0, c.cfg.SWM.OriginRealm),
			})
			ctx, cancel := context.WithTimeout(c.ctx, c.watchdogTimeout())
			ans, err := c.sendRequestOnConn(ctx, conn, req)
			cancel()
			if err != nil {
				c.log.Warn("SWm Diameter watchdog failed", "peer_addr", c.peerAddr(), "error", err)
				_ = conn.Close()
				return
			}
			rc, _ := diameter.AVPUint32(ans.AVPs, diameter.AVPResultCode, 0)
			c.log.Debug("SWm Diameter watchdog success", "peer_addr", c.peerAddr(), "diameter_result_code", rc)
		}
	}
}

// TerminateSession sends STR with Termination-Cause = DIAMETER_LOGOUT (1).
func (c *Client) TerminateSession(ctx context.Context, sessionID string) error {
	return c.terminateSessionWithCause(ctx, sessionID, 1)
}

// TerminateSessionHandover sends STR with Termination-Cause = DIAMETER_USER_MOVED (8).
func (c *Client) TerminateSessionHandover(ctx context.Context, sessionID string) error {
	return c.terminateSessionWithCause(ctx, sessionID, 8)
}

func (c *Client) terminateSessionWithCause(ctx context.Context, sessionID string, cause uint32) error {
	if err := c.waitOpen(ctx); err != nil {
		return fmt.Errorf("SWm STR: peer not open: %w", err)
	}
	msg := c.newSTR(sessionID, cause)
	c.log.Info("SWm STR sent", "session_id", sessionID, "cause", cause)
	_, err := c.sendRequest(ctx, msg)
	if err != nil {
		return fmt.Errorf("SWm STR: %w", err)
	}
	return nil
}

func (c *Client) newSTR(sessionID string, cause uint32) diameter.Message {
	avps := []diameter.AVP{
		diameter.UTF8AVP(diameter.AVPSessionID, 0, sessionID),
		diameter.Uint32AVP(diameter.AVPAuthApplicationID, 0, config.SWMApplicationID),
		diameter.UTF8AVP(diameter.AVPOriginHost, 0, c.cfg.SWM.OriginHost),
		diameter.UTF8AVP(diameter.AVPOriginRealm, 0, c.cfg.SWM.OriginRealm),
		diameter.UTF8AVP(diameter.AVPDestinationRealm, 0, c.cfg.SWM.DestinationRealm),
		diameter.Uint32AVP(diameter.AVPTerminationCause, 0, cause),
	}
	if c.cfg.SWM.DestinationHost != "" {
		avps = append(avps, diameter.UTF8AVP(diameter.AVPDestinationHost, 0, c.cfg.SWM.DestinationHost))
	}
	return c.newRequest(diameter.CommandSTR, config.SWMApplicationID, true, avps)
}

func (c *Client) newDER(sessionID, imsi, apn string, eapPayload []byte) diameter.Message {
	avps := []diameter.AVP{
		diameter.UTF8AVP(diameter.AVPSessionID, 0, sessionID),
		diameter.Uint32AVP(diameter.AVPAuthApplicationID, 0, config.SWMApplicationID),
		diameter.UTF8AVP(diameter.AVPOriginHost, 0, c.cfg.SWM.OriginHost),
		diameter.UTF8AVP(diameter.AVPOriginRealm, 0, c.cfg.SWM.OriginRealm),
		diameter.UTF8AVP(diameter.AVPDestinationRealm, 0, c.cfg.SWM.DestinationRealm),
		diameter.Uint32AVP(diameter.AVPAuthRequestType, 0, 1),
		diameter.UTF8AVP(diameter.AVPUserName, 0, imsi),
		diameter.UTF8AVP(diameter.AVPServiceSelection, 0, apn),
		diameter.OctetAVP(diameter.AVPEAPPayload, 0, diameter.FlagMandatory, eapPayload),
	}
	if c.cfg.SWM.DestinationHost != "" {
		avps = append(avps, diameter.UTF8AVP(diameter.AVPDestinationHost, 0, c.cfg.SWM.DestinationHost))
	}
	return c.newRequest(diameter.CommandDER, config.SWMApplicationID, true, avps)
}

func (c *Client) eapResult(req EAPRequest, sessionID string, answer diameter.Message) *EAPResult {
	resultCode, ok := diameter.AVPUint32(answer.AVPs, diameter.AVPResultCode, 0)
	if !ok {
		resultCode, ok = diameter.ExperimentalResultCode(answer.AVPs)
	}
	if !ok {
		resultCode = 0
	}
	state := EAPStateFailure
	allowed := false
	reason := resultReason(resultCode)
	var responsePayload []byte
	if eapPayload, ok := diameter.FindAVP(answer.AVPs, diameter.AVPEAPPayload, 0); ok {
		responsePayload = append([]byte(nil), eapPayload.Data...)
		eap := ParseEAP(eapPayload.Data)
		switch eap.State {
		case eapStateRequest:
			state = EAPStateChallenge
			reason = eap.Description
		case eapStateSuccess:
			state = EAPStateSuccess
			allowed = resultCode == diameterSuccess || resultCode == diameterLimitedSuccess
			reason = "eap success"
		case eapStateFailure:
			reason = "eap failure"
		default:
			reason = "invalid or unsupported eap payload: " + eap.Description
		}
	} else if resultCode == diameterSuccess || resultCode == diameterLimitedSuccess {
		state = EAPStateSuccess
		allowed = true
	}
	var msk []byte
	if state == EAPStateSuccess && allowed {
		if key, ok := diameter.FindAVP(answer.AVPs, diameter.AVPEAPMasterSessionKey, 0); ok && len(key.Data) == 64 {
			msk = append([]byte(nil), key.Data...)
		}
	}
	profile := parseAPNProfile(answer.AVPs, req.APN)
	c.log.Info("SWm DEA received",
		"session_id", sessionID,
		"imsi", req.IMSI,
		"nai", req.NAI,
		"apn", req.APN,
		"diameter_result_code", resultCode,
		"eap_state", state,
		"allowed", allowed,
		"reason", reason,
		"eap_payload_len", len(responsePayload),
		"msk_present", len(msk) == 64,
		"msk_len", len(msk),
		"apn_profile_present", profile != nil,
		"apn_ambr_present", profile != nil && profile.AMBRPresent,
		"apn_ambr_ul_bps", apnAMBRUL(profile),
		"apn_ambr_dl_bps", apnAMBRDL(profile),
	)
	return &EAPResult{
		SessionID:  sessionID,
		ResultCode: resultCode,
		State:      state,
		Allowed:    allowed,
		IMSI:       req.IMSI,
		NAI:        req.NAI,
		APN:        req.APN,
		Reason:     reason,
		EAPPayload: responsePayload,
		MSK:        msk,
		APNProfile: profile,
	}
}

func parseAPNProfile(avps []diameter.AVP, requested string) *APNProfile {
	if p := parseAPNProfileFromAVPs(avps, requested); p != nil {
		return p
	}
	for _, a := range avps {
		if a.Code != diameter.AVPNon3GPPUserData || a.VendorID != diameter.Vendor3GPP {
			continue
		}
		children, err := diameter.DecodeAVPs(a.Data)
		if err != nil {
			continue
		}
		if p := parseAPNProfileFromAVPs(children, requested); p != nil {
			return p
		}
	}
	return nil
}

func parseAPNProfileFromAVPs(avps []diameter.AVP, requested string) *APNProfile {
	for _, a := range avps {
		if a.Code != diameter.AVPAPNConfiguration || a.VendorID != diameter.Vendor3GPP {
			continue
		}
		children, err := diameter.DecodeAVPs(a.Data)
		if err != nil {
			continue
		}
		apn := diameter.AVPString(children, diameter.AVPServiceSelection, 0)
		if apn != "" && requested != "" && !strings.EqualFold(apn, requested) {
			continue
		}
		p := &APNProfile{APN: apn}
		if ambr, ok := diameter.FindAVP(children, diameter.AVPAMBR, diameter.Vendor3GPP); ok {
			if ambrChildren, err := diameter.DecodeAVPs(ambr.Data); err == nil {
				if ul, ok := avpUint32AnyVendor(ambrChildren, diameter.AVPMaxRequestedBandwidthUL, 0, diameter.Vendor3GPP); ok {
					p.AMBRUplink = ul
					p.AMBRPresent = true
				}
				if dl, ok := avpUint32AnyVendor(ambrChildren, diameter.AVPMaxRequestedBandwidthDL, 0, diameter.Vendor3GPP); ok {
					p.AMBRDownlink = dl
					p.AMBRPresent = true
				}
			}
		}
		return p
	}
	return nil
}

func avpUint32AnyVendor(avps []diameter.AVP, code uint32, vendors ...uint32) (uint32, bool) {
	for _, vendor := range vendors {
		if value, ok := diameter.AVPUint32(avps, code, vendor); ok {
			return value, true
		}
	}
	return 0, false
}

func apnAMBRUL(profile *APNProfile) any {
	if profile == nil || !profile.AMBRPresent {
		return nil
	}
	return profile.AMBRUplink
}

func apnAMBRDL(profile *APNProfile) any {
	if profile == nil || !profile.AMBRPresent {
		return nil
	}
	return profile.AMBRDownlink
}

func (c *Client) sendRequest(ctx context.Context, req diameter.Message) (diameter.Message, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return diameter.Message{}, fmt.Errorf("SWm Diameter peer is not open")
	}
	return c.sendRequestOnConn(ctx, conn, req)
}

func (c *Client) sendRequestOnConn(ctx context.Context, conn net.Conn, req diameter.Message) (diameter.Message, error) {
	ch := make(chan diameterResponse, 1)
	c.mu.Lock()
	c.pending[req.HopByHop] = ch
	c.mu.Unlock()
	c.writeMu.Lock()
	_, err := conn.Write(req.Encode())
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, req.HopByHop)
		c.mu.Unlock()
		return diameter.Message{}, err
	}
	select {
	case resp := <-ch:
		return resp.msg, resp.err
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, req.HopByHop)
		c.mu.Unlock()
		return diameter.Message{}, ctx.Err()
	}
}

func (c *Client) newRequest(command, appID uint32, proxiable bool, avps []diameter.AVP) diameter.Message {
	flags := diameter.FlagRequest
	if proxiable {
		flags |= diameter.FlagProxiable
	}
	return diameter.Message{
		Flags:       flags,
		CommandCode: command,
		AppID:       appID,
		HopByHop:    c.nextHop.Add(1),
		EndToEnd:    c.nextEnd.Add(1),
		AVPs:        avps,
	}
}

func (c *Client) newAnswer(req diameter.Message, avps []diameter.AVP) diameter.Message {
	return diameter.Message{
		Flags:       req.Flags &^ diameter.FlagRequest,
		CommandCode: req.CommandCode,
		AppID:       req.AppID,
		HopByHop:    req.HopByHop,
		EndToEnd:    req.EndToEnd,
		AVPs:        avps,
	}
}

func (c *Client) waitOpen(ctx context.Context) error {
	c.mu.RLock()
	if c.conn != nil {
		c.mu.RUnlock()
		return nil
	}
	opened := c.openedCh
	c.mu.RUnlock()
	select {
	case <-opened:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timed out waiting for SWm Diameter peer")
	}
}

func (c *Client) failPendingLocked(err error) {
	for hop, ch := range c.pending {
		delete(c.pending, hop)
		ch <- diameterResponse{err: err}
	}
}

func (c *Client) sleep(d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-c.ctx.Done():
	case <-timer.C:
	}
}

func (c *Client) peerAddr() string {
	return fmt.Sprintf("%s:%d", c.cfg.SWM.PeerAddr, c.cfg.SWM.PeerPort)
}

func (c *Client) watchdogInterval() time.Duration {
	if c.cfg.SWM.WatchdogIntervalSeconds > 0 {
		return time.Duration(c.cfg.SWM.WatchdogIntervalSeconds) * time.Second
	}
	return 30 * time.Second
}

func (c *Client) watchdogTimeout() time.Duration {
	if c.cfg.SWM.WatchdogTimeoutSeconds > 0 {
		return time.Duration(c.cfg.SWM.WatchdogTimeoutSeconds) * time.Second
	}
	return 10 * time.Second
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func resultReason(code uint32) string {
	switch code {
	case diameterSuccess:
		return "diameter success"
	case diameterLimitedSuccess:
		return "diameter limited success"
	case 5001:
		return "user unknown"
	case 5003:
		return "authorization rejected"
	case 0:
		return "missing result code"
	default:
		return fmt.Sprintf("diameter result code %d", code)
	}
}

func eapID(payload []byte) any {
	if len(payload) >= 2 {
		return payload[1]
	}
	return nil
}
