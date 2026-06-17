package ikev2

// IKEv2 UDP server — listens on port 500 (plain IKE) and port 4500 (NAT-T).
// RFC 7296 §2.23: if NAT is detected, subsequent IKE and ESP use port 4500.

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/gtpu"
	"vectorcore-epdg/internal/s2b"
	"vectorcore-epdg/internal/session"
	"vectorcore-epdg/internal/swm"

	"github.com/free5gc/ike/message"
	"golang.org/x/sys/unix"
)

const (
	ikePort  = 500
	nattPort = 4500

	// Non-ESP marker prepended to IKE packets on port 4500 (RFC 3948 §2.2).
	nonESPMarker uint32 = 0x00000000
)

// Server is the IKEv2 responder.
type Server struct {
	cfg     *Config
	fullCfg *config.Config

	mu  sync.RWMutex
	sas map[uint64]*ikeSA // keyed by initiator SPI

	conn500  *net.UDPConn
	conn4500 *net.UDPConn

	// Dependencies injected via Set* after construction.
	swm      *swm.Client
	sessions *session.Manager
	s2b      *s2b.Client
	gtpuMgr  *gtpu.Manager

	// DER-encoded ePDG X.509 certificate (nil → no CERT payload sent).
	certDER []byte

	ctx context.Context // cancelled on Close; drives reaperLoop lifetime

	log *slog.Logger
}

// Config holds IKEv2 server configuration.
type Config struct {
	ListenAddr string // e.g. "0.0.0.0"
	IKEPort    int    // 0 → 500
	NATTPort   int    // 0 → 4500
}

func NewServer(cfg *Config, log *slog.Logger) *Server {
	return &Server{
		cfg: cfg,
		sas: make(map[uint64]*ikeSA),
		log: log,
	}
}

func (s *Server) SetFullConfig(cfg *config.Config) error {
	s.fullCfg = cfg
	if cfg.IKEv2.CertFile == "" {
		return fmt.Errorf("IKEv2: cert_file is required but not configured")
	}
	der, err := loadDERCert(cfg.IKEv2.CertFile)
	if err != nil {
		return fmt.Errorf("IKEv2: failed to load cert %q: %w", cfg.IKEv2.CertFile, err)
	}
	s.certDER = der
	s.log.Info("IKEv2: loaded ePDG certificate", "file", cfg.IKEv2.CertFile, "bytes", len(der))
	return nil
}

func (s *Server) SetSWM(c *swm.Client)                 { s.swm = c }
func (s *Server) SetSessionManager(m *session.Manager) { s.sessions = m }
func (s *Server) SetS2B(c *s2b.Client)                 { s.s2b = c }
func (s *Server) SetGTPU(m *gtpu.Manager)              { s.gtpuMgr = m }

// loadDERCert reads a PEM file and returns the first certificate's DER bytes.
func loadDERCert(path string) ([]byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pemToDER(pemBytes)
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	s.ctx = ctx
	ikeP := s.cfg.IKEPort
	if ikeP == 0 {
		ikeP = ikePort
	}
	nattP := s.cfg.NATTPort
	if nattP == 0 {
		nattP = nattPort
	}
	addr500 := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, ikeP)
	addr4500 := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, nattP)

	var err error
	s.conn500, err = net.ListenUDP("udp4", mustResolveUDP(addr500))
	if err != nil {
		return fmt.Errorf("ikev2: listen %s: %w", addr500, err)
	}
	s.conn4500, err = net.ListenUDP("udp4", mustResolveUDP(addr4500))
	if err != nil {
		s.conn500.Close()
		return fmt.Errorf("ikev2: listen %s: %w", addr4500, err)
	}
	if err := setUDPEncapESP(s.conn4500); err != nil {
		s.conn500.Close()
		s.conn4500.Close()
		return fmt.Errorf("ikev2: set UDP_ENCAP_ESPINUDP on %s: %w", addr4500, err)
	}

	s.log.Info("IKEv2 listening", "ike", addr500, "natt", addr4500)

	go s.readLoop(s.conn500, false)
	go s.readLoop(s.conn4500, true)
	go s.reaperLoop()
	return nil
}

func (s *Server) Close() {
	if s.conn500 != nil {
		s.conn500.Close()
	}
	if s.conn4500 != nil {
		s.conn4500.Close()
	}
}

func (s *Server) readLoop(conn *net.UDPConn, natt bool) {
	buf := make([]byte, 65536)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handlePacket(conn, remote, pkt, natt)
	}
}

func (s *Server) handlePacket(conn *net.UDPConn, remote *net.UDPAddr, pkt []byte, natt bool) {
	// Strip the 4-byte non-ESP marker on port 4500 (RFC 3948 §2.2).
	if natt {
		if len(pkt) < 4 {
			return
		}
		if binary.BigEndian.Uint32(pkt[:4]) != nonESPMarker {
			// ESP packet — kernel XFRM handles this, not us.
			return
		}
		pkt = pkt[4:]
	}

	if len(pkt) < message.IKE_HEADER_LEN {
		return
	}

	hdr, err := message.ParseHeader(pkt)
	if err != nil {
		s.log.Debug("IKEv2 bad header", "remote", remote, "err", err)
		return
	}

	switch hdr.ExchangeType {
	case message.IKE_SA_INIT:
		s.handleIKESAInit(conn, remote, pkt, hdr, natt)
	case message.IKE_AUTH:
		s.handleIKEAuth(conn, remote, pkt, hdr, natt)
	case message.CREATE_CHILD_SA:
		s.handleCreateChildSA(conn, remote, pkt, hdr)
	case message.INFORMATIONAL:
		s.handleInformational(conn, remote, pkt, hdr)
	default:
		s.log.Debug("IKEv2 unknown exchange", "type", hdr.ExchangeType, "remote", remote)
	}
}

// send writes a response to the remote peer.
// On NAT-T connections a non-ESP marker is prepended.
func (s *Server) send(conn *net.UDPConn, remote *net.UDPAddr, data []byte, natt bool) {
	var out []byte
	if natt {
		out = make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(out, nonESPMarker)
		copy(out[4:], data)
	} else {
		out = data
	}
	if _, err := conn.WriteToUDP(out, remote); err != nil {
		s.log.Warn("IKEv2 send failed", "remote", remote, "err", err)
	}
}

func (s *Server) lookupSA(spiI uint64) *ikeSA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sas[spiI]
}

func (s *Server) storeSA(sa *ikeSA) {
	s.mu.Lock()
	s.sas[sa.spiI] = sa
	s.mu.Unlock()
}

func (s *Server) deleteSA(spiI uint64) {
	s.mu.Lock()
	delete(s.sas, spiI)
	s.mu.Unlock()
}


func mustResolveUDP(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		panic(err)
	}
	return a
}

// setUDPEncapESP sets UDP_ENCAP_ESPINUDP on the socket so the kernel routes
// incoming ESP-in-UDP packets through XFRM instead of delivering them as plain UDP.
func setUDPEncapESP(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setSockOptErr error
	err = raw.Control(func(fd uintptr) {
		setSockOptErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_ENCAP, unix.UDP_ENCAP_ESPINUDP)
	})
	if err != nil {
		return err
	}
	return setSockOptErr
}
