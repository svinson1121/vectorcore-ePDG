package gtpu

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/session"
)

const (
	gtpuVersionPT      byte  = 0x30
	gtpuFlagE          byte  = 0x04
	gtpuFlagS          byte  = 0x02
	gtpuFlagPN         byte  = 0x01
	gtpuMsgEchoRequest uint8 = 1
	gtpuMsgEchoResp    uint8 = 2
	gtpuMsgTPDU        uint8 = 255

	tunDevice = "/dev/net/tun"
	tunSetIFF = 0x400454ca
	iffTun    = 0x0001
	iffNoPI   = 0x1000
)

type Manager struct {
	cfg config.Config
	log *slog.Logger

	udp    *net.UDPConn
	tun    *os.File
	nfq    *nfqueueConn
	rawFd  int
	tunMtu int

	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu                 sync.RWMutex
	sessionsByID       map[string]*Session
	sessionsByPAA      map[string]*Session
	bearersByLocalTEID map[uint32]*BearerRef
	routesBySessionID  map[string]*routeState
	stats              DataplaneStats
	stopOnce           sync.Once
	loopMu             sync.Mutex
	runningLoops       map[string]bool

	pathMu      sync.Mutex
	pathsByPeer map[string]*pathState
	echoSeq     uint16
}

type Session struct {
	ID               string
	IMSI             string
	APN              string
	PAA              net.IP
	LocalGTPUIP      net.IP
	PGWGTPUIP        net.IP
	DefaultEBI       uint8
	Bearers          map[uint8]*Bearer
	PGWControlTEID   uint32
	LocalControlTEID uint32
}

type Bearer struct {
	EBI          uint8
	LocalRXTEID  uint32
	RemoteTXTEID uint32
	PGWGTPUIP    net.IP
	LocalGTPUIP  net.IP
	QoS          BearerQoS
	TFT          *TFT
	Counters     BearerCounters
	State        BearerState
}

type BearerQoS struct {
	QCI uint8
}

type TFT struct {
	Filters []PacketFilter
}

type PacketFilter struct {
	ID             uint8
	Precedence     uint8
	Direction      uint8 // 0x01=uplink, 0x02=downlink, 0x03=bidirectional
	RemoteIPv4     net.IP
	RemoteIPv4Mask net.IPMask
	LocalIPv4      net.IP
	LocalIPv4Mask  net.IPMask
	Protocol       uint8
	HasProtocol    bool
	LocalPortLo    uint16
	LocalPortHi    uint16
	HasLocalPort   bool
	RemotePortLo   uint16
	RemotePortHi   uint16
	HasRemotePort  bool
}

type pathState struct {
	lastSentAt     time.Time
	lastResponseAt time.Time
	missedEchoes   int
	alive          bool
}

type BearerState string

const (
	BearerActive BearerState = "active"
)

type BearerCounters struct {
	UplinkPackets      uint64
	UplinkBytes        uint64
	DownlinkPackets    uint64
	DownlinkBytes      uint64
	LastUplinkPacket   time.Time
	LastDownlinkPacket time.Time
	TFTMatchCount      uint64
}

type BearerRef struct {
	SessionID string
	BearerEBI uint8
}

type DataplaneStats struct {
	UplinkPacketsIn                uint64
	UplinkPacketsGTPUOut           uint64
	DownlinkGTPUIn                 uint64
	DownlinkPacketsOut             uint64
	DroppedNoSession               uint64
	DroppedNoBearer                uint64
	DroppedBadTEID                 uint64
	DroppedBadPeer                 uint64
	DroppedUnsupported             uint64
	DroppedMalformed               uint64
	NFQueuePacketsReceived         uint64
	NFQueuePacketsEncapsulated     uint64
	NFQueuePacketsDroppedNoSession uint64
	NFQueuePacketsDroppedBadPacket uint64
	NFQueuePacketsDroppedSendError uint64
	NFQueueVerdictDrop             uint64
	NFQueueVerdictAccept           uint64
}

type routeState struct {
	hostRouteInstalled    bool
	ruleInstalled         bool
	defaultRouteInstalled bool
	rulePriority          int
	tableID               int
}

type rollbackState struct {
	m                   *Manager
	sessionID           string
	paa                 net.IP
	mainRouteRemoved    bool
	policyRuleRemoved   bool
	tableRouteRemoved   bool
	nfqueueRuleRemoved  bool
	bearerStateRemoved  bool
	sessionStateRemoved bool
	ran                 bool
	errs                []error
	actions             []func()
}

type tunIfReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_pad  [22]byte
}

func NewManager(cfg config.Config, log *slog.Logger) *Manager {
	return &Manager{
		cfg:                cfg,
		log:                log,
		rawFd:              -1,
		tunMtu:             cfg.GTP.MTU,
		sessionsByID:       make(map[string]*Session),
		sessionsByPAA:      make(map[string]*Session),
		bearersByLocalTEID: make(map[uint32]*BearerRef),
		routesBySessionID:  make(map[string]*routeState),
		runningLoops:       make(map[string]bool),
		pathsByPeer:        make(map[string]*pathState),
	}
}

func (m *Manager) Start(ctx context.Context) error {
	localIP := net.ParseIP(m.cfg.GTP.LocalGTPU)
	if localIP == nil {
		return fmt.Errorf("invalid local GTP-U IP %q", m.cfg.GTP.LocalGTPU)
	}
	if m.tunMtu == 0 {
		m.tunMtu = 1400
	}
	m.log.Info("userspace GTP-U dataplane starting",
		"local_addr", localIP.String(),
		"local_port", m.cfg.GTP.LocalPort,
		"packet_interface", m.cfg.GTP.TunName,
		"mtu", m.tunMtu,
	)
	tun, err := createTUN(m.cfg.GTP.TunName)
	if err != nil {
		return err
	}
	m.tun = tun
	if err := m.configureTUN(); err != nil {
		_ = tun.Close()
		m.tun = nil
		return err
	}
	if err := m.detectOrCleanupStaleRoutes(); err != nil {
		_ = tun.Close()
		m.tun = nil
		return err
	}
	if err := m.setupNFQueueRules(); err != nil {
		_ = tun.Close()
		m.tun = nil
		return err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: m.cfg.GTP.LocalPort})
	if err != nil {
		_ = tun.Close()
		m.tun = nil
		return fmt.Errorf("listen userspace GTP-U UDP %s:%d: %w", localIP.String(), m.cfg.GTP.LocalPort, err)
	}
	m.udp = udp
	m.log.Info("userspace GTP-U UDP socket listening", "addr", udp.LocalAddr().String())
	nfq, err := openNFQueue(m.cfg.GTP.UplinkCapture.QueueNum, m.log)
	if err != nil {
		_ = udp.Close()
		_ = tun.Close()
		m.udp = nil
		m.tun = nil
		return err
	}
	m.nfq = nfq
	m.log.Info("NFQUEUE uplink capture starting",
		"queue_num", m.cfg.GTP.UplinkCapture.QueueNum,
		"fail_closed", m.cfg.GTP.UplinkCapture.FailClosed,
	)
	rawFd, err := openRawSocket()
	if err != nil {
		_ = nfq.Close()
		_ = udp.Close()
		_ = tun.Close()
		m.nfq = nil
		m.udp = nil
		m.tun = nil
		return fmt.Errorf("open raw IPv4 injection socket: %w", err)
	}
	m.rawFd = rawFd
	m.log.Info("userspace GTP-U raw injection socket ready")
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.wg.Add(3)
	go m.nfqueueReadLoop(runCtx)
	go m.udpReadLoop(runCtx)
	go m.pathEchoLoop(runCtx)
	return nil
}

func (m *Manager) Stop() error {
	var errs []error
	m.log.Info("GTP-U dataplane stop requested", "active_sessions", m.activeSessionCount())
	m.stopOnce.Do(func() {
		if m.cancel != nil {
			m.cancel()
		}
		m.log.Info("NFQUEUE rules cleanup started", "active_rules", m.activeSessionCount())
		m.cleanupNFQueueRulesForActiveSessions()
		m.log.Info("NFQUEUE rules cleanup complete")
		if m.nfq != nil {
			m.log.Info("NFQUEUE handle closing", "queue_num", m.cfg.GTP.UplinkCapture.QueueNum)
			errs = append(errs, m.nfq.Close())
		}
		if m.udp != nil {
			m.log.Info("GTP-U UDP socket closing", "addr", m.udp.LocalAddr().String())
			errs = append(errs, m.udp.Close())
		}
		if m.tun != nil {
			errs = append(errs, m.tun.Close())
		}
		if m.rawFd >= 0 {
			errs = append(errs, unix.Close(m.rawFd))
			m.rawFd = -1
		}
	})
	m.wg.Wait()
	m.log.Info("GTP-U dataplane goroutines stopped")
	m.log.Info("userspace GTP-U dataplane stopped", "packet_interface", m.cfg.GTP.TunName)
	return errors.Join(errs...)
}

func (m *Manager) cleanupNFQueueRulesForActiveSessions() {
	var paas []net.IP
	m.mu.RLock()
	for _, sess := range m.sessionsByID {
		if sess.PAA != nil {
			paas = append(paas, append(net.IP(nil), sess.PAA...))
		}
	}
	m.mu.RUnlock()
	for _, paa := range paas {
		if err := m.removeNFQueueRule(paa); err != nil {
			m.log.Warn("NFQUEUE uplink rule remove failed during stop", "paa", paa.String(), "error", err)
		}
	}
}

func (m *Manager) markLoop(name string, running bool) {
	m.loopMu.Lock()
	defer m.loopMu.Unlock()
	if running {
		m.runningLoops[name] = true
		return
	}
	delete(m.runningLoops, name)
}

func (m *Manager) HasBearer(sessionID string, ebi uint8) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess := m.sessionsByID[sessionID]
	if sess == nil {
		return false
	}
	return sess.Bearers[ebi] != nil
}

func (m *Manager) AddSession(ctx context.Context, sess *session.Session) error {
	const (
		stepValidateInput        = "validate_input"
		stepInstallNFQueueRule   = "install_nfqueue_rule"
		stepInstallDefaultBearer = "install_default_bearer"
		stepFinalizeDatapath     = "finalize_datapath"
	)
	if sess == nil || sess.S2B == nil {
		return fmt.Errorf("%s: userspace GTP-U session requires S2b context", stepValidateInput)
	}
	paa := net.ParseIP(sess.S2B.PAA)
	if paa == nil || paa.To4() == nil {
		return fmt.Errorf("%s: userspace GTP-U session requires IPv4 PAA, got %q", stepValidateInput, sess.S2B.PAA)
	}
	pgw := net.ParseIP(m.cfg.GTP.PGWGTPU)
	if pgw == nil || pgw.To4() == nil {
		return fmt.Errorf("%s: invalid PGW GTP-U IP %q", stepValidateInput, m.cfg.GTP.PGWGTPU)
	}
	local := net.ParseIP(m.cfg.GTP.LocalGTPU)
	if local == nil || local.To4() == nil {
		return fmt.Errorf("%s: invalid local GTP-U IP %q", stepValidateInput, m.cfg.GTP.LocalGTPU)
	}
	b := &Bearer{
		EBI:          sess.S2B.EBI,
		LocalRXTEID:  sess.S2B.LocalUserTEID,
		RemoteTXTEID: sess.S2B.PGWUserTEID,
		PGWGTPUIP:    pgw,
		LocalGTPUIP:  local,
		State:        BearerActive,
	}
	ds := &Session{
		ID:               sess.ID,
		IMSI:             sess.IMSI,
		APN:              sess.APN,
		PAA:              paa,
		LocalGTPUIP:      local,
		PGWGTPUIP:        pgw,
		DefaultEBI:       sess.S2B.EBI,
		PGWControlTEID:   sess.S2B.PGWControlTEID,
		LocalControlTEID: sess.S2B.LocalControlTEID,
		Bearers:          map[uint8]*Bearer{sess.S2B.EBI: b},
	}
	m.log.Info("userspace GTP-U session add started",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"paa", paa.String(),
		"ebi", b.EBI,
		"local_rx_teid", b.LocalRXTEID,
		"remote_tx_teid", b.RemoteTXTEID,
		"pgw_gtpu", pgw.String(),
		"uplink_capture", m.cfg.GTP.UplinkCapture.Mode,
		"queue_num", m.cfg.GTP.UplinkCapture.QueueNum,
	)
	rb := newRollbackState(m, sess.ID, paa)
	committed := false
	fail := func(step string, err error) error {
		m.log.Error("userspace GTP-U session add failed",
			"session_id", sess.ID,
			"paa", paa.String(),
			"step", step,
			"error", err,
			"rollback_started", true,
		)
		rb.run()
		return fmt.Errorf("%s: %w", step, err)
	}
	defer func() {
		if !committed {
			rb.run()
		}
	}()
	m.log.Info("userspace GTP-U default bearer install started",
		"session_id", sess.ID,
		"ebi", b.EBI,
		"local_rx_teid", b.LocalRXTEID,
		"remote_tx_teid", b.RemoteTXTEID,
	)
	m.mu.Lock()
	if _, exists := m.bearersByLocalTEID[b.LocalRXTEID]; exists {
		m.mu.Unlock()
		return fail(stepInstallDefaultBearer, fmt.Errorf("local GTP-U RX TEID collision: %d", b.LocalRXTEID))
	}
	m.sessionsByID[ds.ID] = ds
	m.sessionsByPAA[paa.String()] = ds
	m.bearersByLocalTEID[b.LocalRXTEID] = &BearerRef{SessionID: ds.ID, BearerEBI: b.EBI}
	m.mu.Unlock()
	rb.add(func() { rb.removeSessionState(sess.ID, paa.String()) })
	if err := m.installNFQueueRule(sess.ID, paa); err != nil {
		return fail(stepInstallNFQueueRule, err)
	}
	rb.add(func() { rb.removeNFQueueRule(paa) })
	sess.Datapath = &session.DatapathContext{
		UEInnerIP:              paa.String(),
		GTPInterface:           m.cfg.GTP.TunName,
		RouteInstalled:         false,
		UplinkRuleInstalled:    true,
		UplinkDefaultInstalled: false,
		BridgeVerified:         true,
		IPsecPAAAligned:        true,
	}
	if sess.Datapath == nil {
		return fail(stepFinalizeDatapath, fmt.Errorf("datapath context not set"))
	}
	committed = true
	m.log.Info("userspace GTP-U default bearer installed",
		"session_id", sess.ID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"paa", paa.String(),
		"ebi", b.EBI,
		"local_rx_teid", b.LocalRXTEID,
		"remote_tx_teid", b.RemoteTXTEID,
		"pgw_gtpu", pgw.String(),
	)
	m.log.Info("userspace GTP-U session add complete",
		"session_id", sess.ID,
		"paa", paa.String(),
		"ebi", b.EBI,
	)
	return nil
}

func (m *Manager) RemoveSession(ctx context.Context, sess *session.Session) error {
	if sess == nil {
		return nil
	}
	var state *routeState
	var paa net.IP
	m.mu.Lock()
	ds := m.sessionsByID[sess.ID]
	if ds != nil {
		for ebi, b := range ds.Bearers {
			delete(m.bearersByLocalTEID, b.LocalRXTEID)
			m.log.Info("userspace GTP-U bearer removed", "session_id", sess.ID, "ebi", ebi)
		}
		paa = ds.PAA
		delete(m.sessionsByPAA, ds.PAA.String())
		delete(m.sessionsByID, sess.ID)
	}
	state = m.routesBySessionID[sess.ID]
	delete(m.routesBySessionID, sess.ID)
	m.mu.Unlock()
	if paa == nil && sess.S2B != nil {
		paa = net.ParseIP(sess.S2B.PAA)
	}
	if paa != nil {
		if err := m.removeNFQueueRule(paa); err != nil {
			m.log.Warn("NFQUEUE uplink rule remove failed", "session_id", sess.ID, "paa", paa.String(), "error", err)
		}
	}
	return m.removeRoutes(ctx, sess.ID, paa, state)
}

func (m *Manager) AddBearer(_ context.Context, sessionID string, b Bearer) error {
	if b.LocalRXTEID == 0 || b.RemoteTXTEID == 0 || b.EBI == 0 {
		return fmt.Errorf("userspace GTP-U bearer requires EBI and TEIDs")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ds := m.sessionsByID[sessionID]
	if ds == nil {
		return fmt.Errorf("session %q not found for userspace GTP-U bearer", sessionID)
	}
	if _, exists := m.bearersByLocalTEID[b.LocalRXTEID]; exists {
		return fmt.Errorf("local GTP-U RX TEID collision: %d", b.LocalRXTEID)
	}
	b.State = BearerActive
	if b.PGWGTPUIP == nil {
		b.PGWGTPUIP = ds.PGWGTPUIP
	}
	if b.LocalGTPUIP == nil {
		b.LocalGTPUIP = ds.LocalGTPUIP
	}
	ds.Bearers[b.EBI] = &b
	m.bearersByLocalTEID[b.LocalRXTEID] = &BearerRef{SessionID: sessionID, BearerEBI: b.EBI}
	storedTFTCount := 0
	if ds.Bearers[b.EBI].TFT != nil {
		storedTFTCount = len(ds.Bearers[b.EBI].TFT.Filters)
	}
	m.log.Info("userspace GTP-U dedicated bearer installed", "session_id", sessionID, "ebi", b.EBI, "local_rx_teid", b.LocalRXTEID, "remote_tx_teid", b.RemoteTXTEID, "qci", b.QoS.QCI, "stored_tft_filters", storedTFTCount)
	return nil
}

func (m *Manager) RemoveBearer(_ context.Context, sessionID string, ebi uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ds := m.sessionsByID[sessionID]
	if ds == nil {
		return nil
	}
	b := ds.Bearers[ebi]
	if b == nil {
		return nil
	}
	delete(m.bearersByLocalTEID, b.LocalRXTEID)
	delete(ds.Bearers, ebi)
	m.log.Info("userspace GTP-U bearer removed", "session_id", sessionID, "ebi", ebi)
	return nil
}

func (m *Manager) Stats() DataplaneStats {
	return DataplaneStats{
		UplinkPacketsIn:                atomic.LoadUint64(&m.stats.UplinkPacketsIn),
		UplinkPacketsGTPUOut:           atomic.LoadUint64(&m.stats.UplinkPacketsGTPUOut),
		DownlinkGTPUIn:                 atomic.LoadUint64(&m.stats.DownlinkGTPUIn),
		DownlinkPacketsOut:             atomic.LoadUint64(&m.stats.DownlinkPacketsOut),
		DroppedNoSession:               atomic.LoadUint64(&m.stats.DroppedNoSession),
		DroppedNoBearer:                atomic.LoadUint64(&m.stats.DroppedNoBearer),
		DroppedBadTEID:                 atomic.LoadUint64(&m.stats.DroppedBadTEID),
		DroppedBadPeer:                 atomic.LoadUint64(&m.stats.DroppedBadPeer),
		DroppedUnsupported:             atomic.LoadUint64(&m.stats.DroppedUnsupported),
		DroppedMalformed:               atomic.LoadUint64(&m.stats.DroppedMalformed),
		NFQueuePacketsReceived:         atomic.LoadUint64(&m.stats.NFQueuePacketsReceived),
		NFQueuePacketsEncapsulated:     atomic.LoadUint64(&m.stats.NFQueuePacketsEncapsulated),
		NFQueuePacketsDroppedNoSession: atomic.LoadUint64(&m.stats.NFQueuePacketsDroppedNoSession),
		NFQueuePacketsDroppedBadPacket: atomic.LoadUint64(&m.stats.NFQueuePacketsDroppedBadPacket),
		NFQueuePacketsDroppedSendError: atomic.LoadUint64(&m.stats.NFQueuePacketsDroppedSendError),
		NFQueueVerdictDrop:             atomic.LoadUint64(&m.stats.NFQueueVerdictDrop),
		NFQueueVerdictAccept:           atomic.LoadUint64(&m.stats.NFQueueVerdictAccept),
	}
}

func (m *Manager) nfqueueReadLoop(ctx context.Context) {
	defer m.wg.Done()
	m.markLoop("nfqueue_read_loop", true)
	defer m.markLoop("nfqueue_read_loop", false)
	for {
		pkt, err := m.nfq.ReadPacket()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				m.log.Info("NFQUEUE read loop stopped", "reason", "context_canceled")
				return
			}
			if errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINVAL) {
				m.log.Info("NFQUEUE read loop stopped", "reason", "handle_closed")
				return
			}
			m.log.Warn("NFQUEUE read failed", "queue_num", m.cfg.GTP.UplinkCapture.QueueNum, "error", err)
			continue
		}
		verdict, reason := m.handleNFQueuePacket(pkt.Payload)
		if err := m.nfq.SetVerdict(pkt.ID, verdict); err != nil {
			m.log.Warn("NFQUEUE verdict send failed", "queue_num", m.cfg.GTP.UplinkCapture.QueueNum, "packet_id", pkt.ID, "verdict", verdictName(verdict), "reason", reason, "error", err)
			continue
		}
		m.log.Debug("NFQUEUE verdict sent", "queue_num", m.cfg.GTP.UplinkCapture.QueueNum, "packet_id", pkt.ID, "verdict", verdictName(verdict), "reason", reason)
	}
}

func (m *Manager) udpReadLoop(ctx context.Context) {
	defer m.wg.Done()
	m.markLoop("gtpu_udp_read_loop", true)
	defer m.markLoop("gtpu_udp_read_loop", false)
	buf := make([]byte, 65535)
	for {
		_ = m.udp.SetReadDeadline(time.Now().Add(time.Second))
		n, peer, err := m.udp.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				m.log.Info("GTP-U UDP read loop stopped", "reason", "socket_closed")
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			m.log.Warn("userspace GTP-U UDP read failed", "error", err)
			continue
		}
		m.handleDownlink(buf[:n], peer)
	}
}

func (m *Manager) handleUplink(pkt []byte) {
	_, _ = m.encapsulateUplink(pkt, "tun")
}

func (m *Manager) handleNFQueuePacket(pkt []byte) (uint32, string) {
	atomic.AddUint64(&m.stats.NFQueuePacketsReceived, 1)
	verdictOnFailure := nfDrop
	if !m.cfg.GTP.UplinkCapture.FailClosed {
		verdictOnFailure = nfAccept
	}
	dst := destIP(pkt)
	src := sourceIP(pkt)
	proto := ipProto(pkt)
	m.log.Debug("NFQUEUE packet received",
		"queue_num", m.cfg.GTP.UplinkCapture.QueueNum,
		"packet_len", len(pkt),
		"src", ipLogString(src),
		"dst", ipLogString(dst),
		"proto", proto,
	)
	ok, reason := m.encapsulateUplink(pkt, "nfqueue")
	if !ok {
		switch reason {
		case "no_session":
			atomic.AddUint64(&m.stats.NFQueuePacketsDroppedNoSession, 1)
		case "send_gtpu_failed":
			atomic.AddUint64(&m.stats.NFQueuePacketsDroppedSendError, 1)
		default:
			atomic.AddUint64(&m.stats.NFQueuePacketsDroppedBadPacket, 1)
		}
		m.log.Debug("NFQUEUE packet dropped", "reason", reason, "src", ipLogString(src), "dst", ipLogString(dst))
		if verdictOnFailure == nfAccept {
			atomic.AddUint64(&m.stats.NFQueueVerdictAccept, 1)
		} else {
			atomic.AddUint64(&m.stats.NFQueueVerdictDrop, 1)
		}
		return verdictOnFailure, reason
	}
	atomic.AddUint64(&m.stats.NFQueuePacketsEncapsulated, 1)
	atomic.AddUint64(&m.stats.NFQueueVerdictDrop, 1)
	return nfDrop, "encapsulated"
}

func (m *Manager) encapsulateUplink(pkt []byte, source string) (bool, string) {
	atomic.AddUint64(&m.stats.UplinkPacketsIn, 1)
	src := sourceIP(pkt)
	if src == nil {
		atomic.AddUint64(&m.stats.DroppedMalformed, 1)
		return false, "bad_packet"
	}
	dst := destIP(pkt)
	m.mu.RLock()
	ds := m.sessionsByPAA[src.String()]
	var b *Bearer
	if ds != nil {
		b = m.selectUplinkBearer(ds, pkt)
	}
	m.mu.RUnlock()
	if ds == nil {
		atomic.AddUint64(&m.stats.DroppedNoSession, 1)
		return false, "no_session"
	}
	if source == "nfqueue" {
		m.log.Debug("NFQUEUE session lookup success", "session_id", ds.ID, "paa", src.String())
	}
	if b == nil {
		atomic.AddUint64(&m.stats.DroppedNoBearer, 1)
		return false, "no_bearer"
	}
	if source == "nfqueue" {
		dedicated := b.EBI != ds.DefaultEBI
		m.log.Debug("NFQUEUE uplink bearer selected", "session_id", ds.ID, "ebi", b.EBI, "dedicated", dedicated, "remote_tx_teid", b.RemoteTXTEID, "pgw_gtpu", b.PGWGTPUIP.String())
	}
	gtp, err := encodeTPDU(b.RemoteTXTEID, pkt)
	if err != nil {
		atomic.AddUint64(&m.stats.DroppedMalformed, 1)
		return false, "bad_packet"
	}
	if _, err := m.udp.WriteToUDP(gtp, &net.UDPAddr{IP: b.PGWGTPUIP, Port: config.GTPUPort}); err != nil {
		m.log.Warn("userspace GTP-U uplink send failed", "session_id", ds.ID, "ebi", b.EBI, "error", err)
		return false, "send_gtpu_failed"
	}
	atomic.AddUint64(&m.stats.UplinkPacketsGTPUOut, 1)
	atomic.AddUint64(&b.Counters.UplinkPackets, 1)
	atomic.AddUint64(&b.Counters.UplinkBytes, uint64(len(pkt)))
	b.Counters.LastUplinkPacket = time.Now()
	m.log.Debug("userspace GTP-U uplink packet encapsulated",
		"session_id", ds.ID,
		"ebi", b.EBI,
		"teid", b.RemoteTXTEID,
		"dst", fmt.Sprintf("%s:%d", b.PGWGTPUIP.String(), config.GTPUPort),
		"inner_src", src.String(),
		"inner_dst", ipLogString(dst),
		"bytes", len(pkt),
	)
	return true, "encapsulated"
}

func (m *Manager) handleDownlink(pkt []byte, peer *net.UDPAddr) {
	atomic.AddUint64(&m.stats.DownlinkGTPUIn, 1)
	parsed, err := parseGTPU(pkt)
	if err != nil {
		atomic.AddUint64(&m.stats.DroppedMalformed, 1)
		m.log.Debug("userspace GTP-U packet dropped", "reason", "malformed", "peer", peer.String(), "error", err)
		return
	}
	if parsed.MessageType == gtpuMsgEchoRequest {
		m.respondEcho(parsed.Sequence, peer)
		return
	}
	if parsed.MessageType == gtpuMsgEchoResp {
		m.handleEchoResponse(peer)
		return
	}
	if parsed.MessageType != gtpuMsgTPDU {
		atomic.AddUint64(&m.stats.DroppedUnsupported, 1)
		m.log.Debug("userspace GTP-U packet dropped", "reason", "unsupported_message", "type", parsed.MessageType, "peer", peer.String())
		return
	}
	m.mu.RLock()
	ref := m.bearersByLocalTEID[parsed.TEID]
	var ds *Session
	var b *Bearer
	if ref != nil {
		ds = m.sessionsByID[ref.SessionID]
		if ds != nil {
			b = ds.Bearers[ref.BearerEBI]
		}
	}
	m.mu.RUnlock()
	if ds == nil || b == nil {
		atomic.AddUint64(&m.stats.DroppedBadTEID, 1)
		m.log.Debug("userspace GTP-U packet dropped", "reason", "unknown_teid", "teid", parsed.TEID, "peer", peer.String())
		return
	}
	if m.cfg.GTP.StrictPeerCheck && !peer.IP.Equal(b.PGWGTPUIP) {
		atomic.AddUint64(&m.stats.DroppedBadPeer, 1)
		m.log.Debug("userspace GTP-U packet dropped", "reason", "bad_peer", "session_id", ds.ID, "ebi", b.EBI, "peer", peer.IP.String(), "expected_pgw_gtpu", b.PGWGTPUIP.String())
		return
	}
	m.log.Debug("userspace GTP-U downlink packet decapsulated", "session_id", ds.ID, "ebi", b.EBI, "teid", parsed.TEID, "bytes", len(parsed.Payload))
	innerSrc := sourceIP(parsed.Payload)
	innerDst := destIP(parsed.Payload)
	m.log.Debug("userspace GTP-U downlink inner packet parsed",
		"session_id", ds.ID,
		"ebi", b.EBI,
		"inner_src", ipLogString(innerSrc),
		"inner_dst", ipLogString(innerDst),
		"proto", ipProto(parsed.Payload),
		"bytes", len(parsed.Payload),
	)
	if !innerDst.Equal(ds.PAA) {
		atomic.AddUint64(&m.stats.DroppedBadPeer, 1)
		m.log.Warn("userspace GTP-U downlink inner destination does not match PAA, dropping",
			"session_id", ds.ID,
			"ebi", b.EBI,
			"inner_dst", ipLogString(innerDst),
			"paa", ds.PAA.String(),
		)
		return
	}
	if err := m.injectDownlink(ds, parsed.Payload); err != nil {
		m.log.Warn("userspace GTP-U downlink packet injection result",
			"session_id", ds.ID,
			"result", "error",
			"error", err,
		)
		return
	}
	atomic.AddUint64(&m.stats.DownlinkPacketsOut, 1)
	atomic.AddUint64(&b.Counters.DownlinkPackets, 1)
	atomic.AddUint64(&b.Counters.DownlinkBytes, uint64(len(parsed.Payload)))
	b.Counters.LastDownlinkPacket = time.Now()
}

func (m *Manager) injectDownlink(ds *Session, pkt []byte) error {
	dst := destIP(pkt)
	m.log.Debug("userspace GTP-U downlink packet injection started",
		"session_id", ds.ID,
		"method", "raw_ip",
		"inner_dst", ipLogString(dst),
	)
	if err := m.injectRawIPv4(pkt); err == nil {
		m.log.Debug("userspace GTP-U downlink packet injection result",
			"session_id", ds.ID,
			"method", "raw_ip",
			"inner_dst", ipLogString(dst),
			"result", "success",
		)
		return nil
	} else {
		m.log.Warn("userspace GTP-U downlink raw injection failed, falling back to TUN",
			"session_id", ds.ID,
			"inner_dst", ipLogString(dst),
			"error", err,
		)
	}
	m.log.Debug("userspace GTP-U downlink packet injection started",
		"session_id", ds.ID,
		"method", "tun",
		"inner_dst", ipLogString(dst),
	)
	if _, err := m.tun.Write(pkt); err != nil {
		return fmt.Errorf("tun injection: %w", err)
	}
	m.log.Debug("userspace GTP-U downlink packet injection result",
		"session_id", ds.ID,
		"method", "tun",
		"inner_dst", ipLogString(dst),
		"result", "success",
	)
	return nil
}

func (m *Manager) injectRawIPv4(pkt []byte) error {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return fmt.Errorf("raw IPv4 injection requires IPv4 packet")
	}
	dst := destIP(pkt)
	if dst == nil || dst.To4() == nil {
		return fmt.Errorf("raw IPv4 injection missing IPv4 destination")
	}
	ip4 := dst.To4()
	return unix.Sendto(m.rawFd, pkt, 0, &unix.SockaddrInet4{Addr: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}})
}

func openRawSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("open raw IPv4 socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("set IP_HDRINCL on raw socket: %w", err)
	}
	return fd, nil
}

func (m *Manager) respondEcho(seq uint16, peer *net.UDPAddr) {
	payload := []byte{14, 0, 1, byte(m.cfg.GTP.Recovery)}
	resp, err := encodePathMessage(gtpuMsgEchoResp, seq, payload)
	if err != nil {
		m.log.Warn("userspace GTP-U Echo Response encode failed", "error", err)
		return
	}
	if _, err := m.udp.WriteToUDP(resp, peer); err != nil {
		m.log.Warn("userspace GTP-U Echo Response send failed", "peer", peer.String(), "error", err)
	}
}

// ParseTFT parses a raw TFT IE payload per 3GPP TS 24.008 §10.5.6.12.
func ParseTFT(raw []byte) (*TFT, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("TFT too short")
	}
	opCode := raw[0] >> 5
	numFilters := int(raw[0] & 0x0f)
	if opCode != 0x01 && opCode != 0x03 && opCode != 0x04 {
		return nil, nil
	}
	tft := &TFT{}
	offset := 1
	for i := 0; i < numFilters; i++ {
		if offset+2 > len(raw) {
			return tft, fmt.Errorf("TFT packet filter %d header truncated", i)
		}
		header := raw[offset]
		direction := (header >> 4) & 0x03
		filterID := header & 0x0f
		precedence := raw[offset+1]
		offset += 2
		if offset >= len(raw) {
			return tft, fmt.Errorf("TFT packet filter %d content length truncated", i)
		}
		contentLen := int(raw[offset])
		offset++
		if offset+contentLen > len(raw) {
			return tft, fmt.Errorf("TFT packet filter %d content truncated", i)
		}
		pf := PacketFilter{ID: filterID, Precedence: precedence, Direction: direction}
		if err := parsePacketFilterContents(&pf, raw[offset:offset+contentLen]); err != nil {
			return tft, fmt.Errorf("TFT packet filter %d: %w", i, err)
		}
		tft.Filters = append(tft.Filters, pf)
		offset += contentLen
	}
	return tft, nil
}

func parsePacketFilterContents(pf *PacketFilter, data []byte) error {
	i := 0
	for i < len(data) {
		comp := data[i]
		i++
		switch comp {
		case 0x10: // IPv4 remote address (4 bytes IP + 4 bytes mask)
			if i+8 > len(data) {
				return fmt.Errorf("IPv4 remote address truncated")
			}
			pf.RemoteIPv4 = net.IPv4(data[i], data[i+1], data[i+2], data[i+3]).To4()
			pf.RemoteIPv4Mask = net.IPMask{data[i+4], data[i+5], data[i+6], data[i+7]}
			i += 8
		case 0x18: // IPv4 local address
			if i+8 > len(data) {
				return fmt.Errorf("IPv4 local address truncated")
			}
			pf.LocalIPv4 = net.IPv4(data[i], data[i+1], data[i+2], data[i+3]).To4()
			pf.LocalIPv4Mask = net.IPMask{data[i+4], data[i+5], data[i+6], data[i+7]}
			i += 8
		case 0x30: // Protocol identifier
			if i >= len(data) {
				return fmt.Errorf("protocol identifier truncated")
			}
			pf.Protocol = data[i]
			pf.HasProtocol = true
			i++
		case 0x40: // Single local port
			if i+2 > len(data) {
				return fmt.Errorf("local port truncated")
			}
			port := binary.BigEndian.Uint16(data[i : i+2])
			pf.LocalPortLo, pf.LocalPortHi = port, port
			pf.HasLocalPort = true
			i += 2
		case 0x41: // Local port range
			if i+4 > len(data) {
				return fmt.Errorf("local port range truncated")
			}
			pf.LocalPortLo = binary.BigEndian.Uint16(data[i : i+2])
			pf.LocalPortHi = binary.BigEndian.Uint16(data[i+2 : i+4])
			pf.HasLocalPort = true
			i += 4
		case 0x50: // Single remote port
			if i+2 > len(data) {
				return fmt.Errorf("remote port truncated")
			}
			port := binary.BigEndian.Uint16(data[i : i+2])
			pf.RemotePortLo, pf.RemotePortHi = port, port
			pf.HasRemotePort = true
			i += 2
		case 0x51: // Remote port range
			if i+4 > len(data) {
				return fmt.Errorf("remote port range truncated")
			}
			pf.RemotePortLo = binary.BigEndian.Uint16(data[i : i+2])
			pf.RemotePortHi = binary.BigEndian.Uint16(data[i+2 : i+4])
			pf.HasRemotePort = true
			i += 4
		case 0x60: // Security parameter index (4 bytes)
			i += 4
		case 0x70: // TOS/traffic class: value byte + mask byte
			i += 2
		case 0x80: // Flow label (IPv6, 3 bytes)
			i += 3
		default:
			return fmt.Errorf("unsupported TFT component type 0x%02x", comp)
		}
	}
	return nil
}

func tcpUDPPorts(pkt []byte) (src, dst uint16, ok bool) {
	if len(pkt) < 1 || pkt[0]>>4 != 4 {
		return 0, 0, false
	}
	if len(pkt) < 20 {
		return 0, 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	proto := pkt[9]
	if proto != 6 && proto != 17 {
		return 0, 0, false
	}
	if len(pkt) < ihl+4 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(pkt[ihl : ihl+2]),
		binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]),
		true
}

func (f *PacketFilter) matchesUplink(pkt []byte) bool {
	if f.Direction != 0x01 && f.Direction != 0x03 {
		return false
	}
	if f.RemoteIPv4 != nil {
		dst := destIP(pkt)
		if dst == nil {
			return false
		}
		if !dst.To4().Mask(f.RemoteIPv4Mask).Equal(f.RemoteIPv4.Mask(f.RemoteIPv4Mask)) {
			return false
		}
	}
	if f.HasProtocol && ipProto(pkt) != f.Protocol {
		return false
	}
	srcP, dstP, hasPorts := tcpUDPPorts(pkt)
	if f.HasLocalPort && (!hasPorts || srcP < f.LocalPortLo || srcP > f.LocalPortHi) {
		return false
	}
	if f.HasRemotePort && (!hasPorts || dstP < f.RemotePortLo || dstP > f.RemotePortHi) {
		return false
	}
	return true
}

// selectUplinkBearer returns the best bearer for an uplink packet.
// Must be called with m.mu.RLock held.
func (m *Manager) selectUplinkBearer(ds *Session, pkt []byte) *Bearer {
	if !m.cfg.GTP.DedicatedBearers.TFTUplinkSelection {
		return ds.Bearers[ds.DefaultEBI]
	}
	var best *Bearer
	bestPrecedence := uint8(255)
	for _, b := range ds.Bearers {
		if b.EBI == ds.DefaultEBI || b.TFT == nil || len(b.TFT.Filters) == 0 {
			continue
		}
		for _, f := range b.TFT.Filters {
			if f.matchesUplink(pkt) {
				if best == nil || f.Precedence < bestPrecedence {
					best = b
					bestPrecedence = f.Precedence
				}
				break
			}
		}
	}
	if best != nil {
		return best
	}
	return ds.Bearers[ds.DefaultEBI]
}

func (m *Manager) UpdateBearer(_ context.Context, sessionID string, ebi, qci uint8, tftRaw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ds := m.sessionsByID[sessionID]
	if ds == nil {
		return fmt.Errorf("session %q not found for bearer update", sessionID)
	}
	b := ds.Bearers[ebi]
	if b == nil {
		return fmt.Errorf("bearer %d not found in session %q", ebi, sessionID)
	}
	if qci != 0 {
		b.QoS.QCI = qci
	}
	if len(tftRaw) > 0 {
		tft, err := ParseTFT(tftRaw)
		if err != nil {
			m.log.Warn("Update Bearer TFT parse failed", "session_id", sessionID, "ebi", ebi, "error", err)
		} else if tft != nil {
			b.TFT = tft
		}
	}
	filterCount := 0
	if b.TFT != nil {
		filterCount = len(b.TFT.Filters)
	}
	m.log.Info("userspace GTP-U dedicated bearer updated", "session_id", sessionID, "ebi", ebi, "qci", b.QoS.QCI, "tft_filters", filterCount)
	return nil
}

func (m *Manager) pathEchoLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			for _, peer := range m.activePGWPeers() {
				m.sendEchoRequest(peer)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) activePGWPeers() []net.IP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]bool)
	var peers []net.IP
	for _, ds := range m.sessionsByID {
		if ds.PGWGTPUIP == nil {
			continue
		}
		key := ds.PGWGTPUIP.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		peers = append(peers, append(net.IP(nil), ds.PGWGTPUIP...))
	}
	return peers
}

func (m *Manager) sendEchoRequest(peer net.IP) {
	m.pathMu.Lock()
	seq := m.echoSeq
	m.echoSeq++
	key := peer.String()
	ps := m.pathsByPeer[key]
	if ps == nil {
		ps = &pathState{alive: true}
		m.pathsByPeer[key] = ps
	}
	if !ps.lastSentAt.IsZero() && ps.lastResponseAt.Before(ps.lastSentAt) {
		ps.missedEchoes++
		m.log.Warn("GTP-U path echo missed", "peer", key, "consecutive_missed", ps.missedEchoes)
		if ps.alive && ps.missedEchoes >= 3 {
			ps.alive = false
			m.log.Error("GTP-U path failure detected", "peer", key, "missed_echoes", ps.missedEchoes)
		}
	}
	ps.lastSentAt = time.Now()
	m.pathMu.Unlock()
	pkt, err := encodePathMessage(gtpuMsgEchoRequest, seq, []byte{14, 0, 1, byte(m.cfg.GTP.Recovery)})
	if err != nil {
		m.log.Warn("GTP-U path Echo Request encode failed", "peer", peer.String(), "error", err)
		return
	}
	if _, err := m.udp.WriteToUDP(pkt, &net.UDPAddr{IP: peer, Port: config.GTPUPort}); err != nil {
		m.log.Warn("GTP-U path Echo Request send failed", "peer", peer.String(), "error", err)
		return
	}
	m.log.Debug("GTP-U path Echo Request sent", "peer", peer.String(), "seq", seq)
}

func (m *Manager) handleEchoResponse(peer *net.UDPAddr) {
	key := peer.IP.String()
	m.pathMu.Lock()
	defer m.pathMu.Unlock()
	ps := m.pathsByPeer[key]
	if ps == nil {
		ps = &pathState{}
		m.pathsByPeer[key] = ps
	}
	wasAlive := ps.alive
	ps.lastResponseAt = time.Now()
	ps.missedEchoes = 0
	ps.alive = true
	if !wasAlive {
		m.log.Info("GTP-U path recovered", "peer", key)
	}
	m.log.Debug("GTP-U Echo Response received", "peer", key)
}

func (m *Manager) configureTUN() error {
	link, err := netlink.LinkByName(m.cfg.GTP.TunName)
	if err != nil {
		return fmt.Errorf("lookup userspace packet interface %q: %w", m.cfg.GTP.TunName, err)
	}
	if err := netlink.LinkSetMTU(link, m.tunMtu); err != nil {
		return fmt.Errorf("set MTU on %s: %w", m.cfg.GTP.TunName, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", m.cfg.GTP.TunName, err)
	}
	return nil
}

func (m *Manager) detectOrCleanupStaleRoutes() error {
	link, err := netlink.LinkByName(m.cfg.GTP.TunName)
	if err != nil {
		return err
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list routes for %s: %w", m.cfg.GTP.TunName, err)
	}
	for _, route := range routes {
		if route.Dst == nil || route.Table != unix.RT_TABLE_MAIN {
			continue
		}
		if !m.cfg.GTP.CleanupStaleRoutesOnStart {
			m.log.Warn("stale userspace GTP-U main PAA route detected",
				"route", fmt.Sprintf("%s dev %s", route.Dst.String(), m.cfg.GTP.TunName),
				"cleanup_enabled", false,
				"cleanup_command", fmt.Sprintf("ip route del %s dev %s", route.Dst.IP.String(), m.cfg.GTP.TunName),
			)
			continue
		}
		rb := newRollbackState(m, "startup", route.Dst.IP)
		rb.removeMainRoute(link, route.Dst.IP)
	}
	if !m.cfg.Datapath.UplinkPolicyRoutingEnabled {
		return nil
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list policy rules: %w", err)
	}
	for _, rule := range rules {
		if rule.Table != m.cfg.Datapath.UplinkTableID || rule.Src == nil {
			continue
		}
		if !m.cfg.GTP.CleanupStaleRoutesOnStart {
			m.log.Warn("stale userspace GTP-U policy rule detected",
				"from", rule.Src.String(),
				"table", rule.Table,
				"priority", rule.Priority,
				"cleanup_enabled", false,
				"cleanup_command", fmt.Sprintf("ip rule del from %s lookup %d", rule.Src.String(), rule.Table),
			)
			continue
		}
		rb := newRollbackState(m, "startup", rule.Src.IP)
		rb.removePolicyRule(rule.Src.IP, rule.Table, rule.Priority)
	}
	tableRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: m.cfg.Datapath.UplinkTableID, LinkIndex: link.Attrs().Index}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("list table %d routes for %s: %w", m.cfg.Datapath.UplinkTableID, m.cfg.GTP.TunName, err)
	}
	for _, route := range tableRoutes {
		if route.Dst != nil && !isDefaultIPv4(route.Dst) {
			continue
		}
		if !m.cfg.GTP.CleanupStaleRoutesOnStart {
			m.log.Warn("stale userspace GTP-U table default route detected",
				"table", route.Table,
				"dev", m.cfg.GTP.TunName,
				"cleanup_enabled", false,
				"cleanup_command", fmt.Sprintf("ip route flush table %d", route.Table),
			)
			continue
		}
	}
	if m.cfg.GTP.CleanupStaleRoutesOnStart {
		rb := newRollbackState(m, "startup", nil)
		rb.removeTableDefaultRoute(link, m.cfg.Datapath.UplinkTableID)
	}
	return nil
}

func newRollbackState(m *Manager, sessionID string, paa net.IP) *rollbackState {
	return &rollbackState{m: m, sessionID: sessionID, paa: paa}
}

func (r *rollbackState) add(fn func()) {
	r.actions = append(r.actions, fn)
}

func (r *rollbackState) run() {
	if r.ran {
		return
	}
	r.ran = true
	for i := len(r.actions) - 1; i >= 0; i-- {
		r.actions[i]()
	}
	paa := ""
	if r.paa != nil {
		paa = r.paa.String()
	}
	r.m.log.Info("userspace GTP-U session add rollback complete",
		"session_id", r.sessionID,
		"paa", paa,
		"removed_main_route", r.mainRouteRemoved,
		"removed_policy_rule", r.policyRuleRemoved,
		"removed_table_route", r.tableRouteRemoved,
		"removed_nfqueue_rule", r.nfqueueRuleRemoved,
		"removed_bearer_state", r.bearerStateRemoved,
		"removed_session_state", r.sessionStateRemoved,
	)
	r.actions = nil
}

func (r *rollbackState) removeSessionState(sessionID, paa string) {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	ds := r.m.sessionsByID[sessionID]
	if ds != nil {
		for _, b := range ds.Bearers {
			delete(r.m.bearersByLocalTEID, b.LocalRXTEID)
			r.bearerStateRemoved = true
		}
		delete(r.m.sessionsByID, sessionID)
		r.sessionStateRemoved = true
	}
	if paa != "" {
		if _, ok := r.m.sessionsByPAA[paa]; ok {
			delete(r.m.sessionsByPAA, paa)
			r.sessionStateRemoved = true
		}
	}
	delete(r.m.routesBySessionID, sessionID)
}

func (r *rollbackState) removeMainRoute(link netlink.Link, paa net.IP) {
	if paa == nil {
		return
	}
	err := netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: hostNet(paa)})
	result := "success"
	if err != nil {
		if isNotFound(err) {
			result = "not_found"
		} else {
			result = "error"
		}
	} else {
		r.mainRouteRemoved = true
	}
	args := []any{"session_id", r.sessionID, "paa", paa.String(), "dev", r.m.cfg.GTP.TunName, "result", result}
	if err != nil && !isNotFound(err) {
		args = append(args, "error", err)
		r.errs = append(r.errs, err)
	}
	r.m.log.Info("userspace GTP-U main PAA route removed", args...)
}

func (r *rollbackState) removePolicyRule(paa net.IP, tableID, priority int) {
	if paa == nil {
		return
	}
	rule := netlink.NewRule()
	rule.Src = hostNet(paa)
	rule.Table = tableID
	rule.Priority = priority
	err := netlink.RuleDel(rule)
	result := "success"
	if err != nil {
		if isNotFound(err) {
			result = "not_found"
		} else {
			result = "error"
		}
	} else {
		r.policyRuleRemoved = true
	}
	args := []any{"session_id", r.sessionID, "from", hostNet(paa).String(), "table", tableID, "priority", priority, "result", result}
	if err != nil && !isNotFound(err) {
		args = append(args, "error", err)
		r.errs = append(r.errs, err)
	}
	r.m.log.Info("userspace GTP-U policy rule removed", args...)
}

func (r *rollbackState) removeTableDefaultRoute(link netlink.Link, tableID int) {
	active := r.m.activeSessionCount()
	if active > 0 {
		r.m.log.Info("userspace GTP-U table default route removed",
			"table", tableID,
			"dev", r.m.cfg.GTP.TunName,
			"result", "kept_active_sessions",
			"active_sessions", active,
		)
		return
	}
	err := netlink.RouteDel(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: defaultIPv4Net(), Table: tableID, Scope: netlink.SCOPE_LINK, Protocol: unix.RTPROT_STATIC})
	result := "success"
	if err != nil {
		if isNotFound(err) {
			result = "not_found"
		} else {
			result = "error"
		}
	} else {
		r.tableRouteRemoved = true
	}
	args := []any{"table", tableID, "dev", r.m.cfg.GTP.TunName, "result", result, "active_sessions", active}
	if err != nil && !isNotFound(err) {
		args = append(args, "error", err)
		r.errs = append(r.errs, err)
	}
	r.m.log.Info("userspace GTP-U table default route removed", args...)
}

func (m *Manager) activeSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessionsByID)
}

func (m *Manager) removeRoutes(_ context.Context, sessionID string, paa net.IP, state *routeState) error {
	if !m.cfg.Datapath.InstallRoutes {
		return nil
	}
	if paa == nil {
		return nil
	}
	link, err := netlink.LinkByName(m.cfg.GTP.TunName)
	if err != nil {
		return err
	}
	if state == nil {
		state = &routeState{
			hostRouteInstalled:    true,
			ruleInstalled:         m.cfg.Datapath.UplinkPolicyRoutingEnabled,
			defaultRouteInstalled: m.cfg.Datapath.UplinkPolicyRoutingEnabled,
			tableID:               m.cfg.Datapath.UplinkTableID,
			rulePriority:          rulePriority(m.cfg.Datapath.UplinkPriorityBase, 0),
		}
		if state.rulePriority == m.cfg.Datapath.UplinkPriorityBase {
			state.rulePriority = rulePriority(m.cfg.Datapath.UplinkPriorityBase, 5)
		}
	}
	rb := newRollbackState(m, sessionID, paa)
	if state.hostRouteInstalled {
		rb.removeMainRoute(link, paa)
	}
	if state.ruleInstalled {
		rb.removePolicyRule(paa, state.tableID, state.rulePriority)
	}
	if state.defaultRouteInstalled {
		rb.removeTableDefaultRoute(link, state.tableID)
	}
	return errors.Join(rb.errs...)
}

func createTUN(name string) (*os.File, error) {
	fd, err := unix.Open(tunDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}
	var req tunIfReq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&req)))
	if errno == unix.EBUSY {
		// Interface held by a previous process (e.g. killed with -9). Delete it and retry once.
		_ = unix.Close(fd)
		if link, lerr := netlink.LinkByName(name); lerr == nil {
			_ = netlink.LinkDel(link)
		}
		return createTUN(name)
	}
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create/open TUN interface %q: %w", name, errno)
	}
	return os.NewFile(uintptr(fd), name), nil
}

type gtpuPacket struct {
	MessageType uint8
	TEID        uint32
	Sequence    uint16
	Payload     []byte
}

func encodeTPDU(teid uint32, payload []byte) ([]byte, error) {
	if teid == 0 {
		return nil, fmt.Errorf("GTP-U T-PDU requires nonzero TEID")
	}
	if len(payload) > 0xffff {
		return nil, fmt.Errorf("GTP-U payload too large: %d", len(payload))
	}
	out := make([]byte, 8+len(payload))
	out[0] = gtpuVersionPT
	out[1] = gtpuMsgTPDU
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint32(out[4:8], teid)
	copy(out[8:], payload)
	return out, nil
}

func encodePathMessage(msgType uint8, seq uint16, payload []byte) ([]byte, error) {
	if len(payload)+4 > 0xffff {
		return nil, fmt.Errorf("GTP-U path message too large: %d", len(payload))
	}
	out := make([]byte, 12+len(payload))
	out[0] = gtpuVersionPT | gtpuFlagS
	out[1] = msgType
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(payload)))
	binary.BigEndian.PutUint32(out[4:8], 0)
	binary.BigEndian.PutUint16(out[8:10], seq)
	out[10] = 0
	out[11] = 0
	copy(out[12:], payload)
	return out, nil
}

func parseGTPU(b []byte) (gtpuPacket, error) {
	if len(b) < 8 {
		return gtpuPacket{}, fmt.Errorf("GTP-U packet too short: %d", len(b))
	}
	if b[0]&0xe0 != 0x20 || b[0]&0x10 == 0 {
		return gtpuPacket{}, fmt.Errorf("unsupported GTP-U flags 0x%02x", b[0])
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length > len(b)-8 {
		return gtpuPacket{}, fmt.Errorf("GTP-U length %d exceeds packet payload %d", length, len(b)-8)
	}
	end := 8 + length
	p := gtpuPacket{MessageType: b[1], TEID: binary.BigEndian.Uint32(b[4:8])}
	offset := 8
	if b[0]&(gtpuFlagE|gtpuFlagS|gtpuFlagPN) != 0 {
		if end < 12 {
			return gtpuPacket{}, fmt.Errorf("GTP-U optional header truncated")
		}
		p.Sequence = binary.BigEndian.Uint16(b[8:10])
		nextExt := b[11]
		offset = 12
		for nextExt != 0 {
			if end < offset+1 {
				return gtpuPacket{}, fmt.Errorf("GTP-U extension header truncated")
			}
			extLen := int(b[offset]) * 4
			if extLen == 0 || end < offset+extLen {
				return gtpuPacket{}, fmt.Errorf("GTP-U extension header length invalid")
			}
			nextExt = b[offset+extLen-1]
			offset += extLen
		}
	}
	if offset > end {
		return gtpuPacket{}, fmt.Errorf("GTP-U payload offset invalid")
	}
	p.Payload = append([]byte(nil), b[offset:end]...)
	return p, nil
}

func sourceIP(pkt []byte) net.IP {
	if len(pkt) < 1 {
		return nil
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return nil
		}
		return net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	case 6:
		if len(pkt) < 40 {
			return nil
		}
		return net.IP(pkt[8:24]).To16()
	default:
		return nil
	}
}

func hostNet(ip net.IP) *net.IPNet {
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func defaultIPv4Net() *net.IPNet {
	return &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.IPMask{0, 0, 0, 0}}
}

func isDefaultIPv4(n *net.IPNet) bool {
	if n == nil {
		return true
	}
	ones, bits := n.Mask.Size()
	return bits == 32 && ones == 0 && n.IP.To4() != nil && n.IP.To4().Equal(net.IPv4zero)
}

func rulePriority(base int, ebi uint8) int {
	if base <= 0 {
		base = 10000
	}
	return base + int(ebi)
}

func ignoreNotFound(err error) error {
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ESRCH) ||
		strings.Contains(msg, "no such process") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "not found")
}

func AllocateTEID() (uint32, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		teid := binary.BigEndian.Uint32(b[:])
		if teid != 0 {
			return teid, nil
		}
	}
}
