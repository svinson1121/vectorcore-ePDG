package ikev2

// IKEv2 UDP server — listens on port 500 (plain IKE) and port 4500 (NAT-T).
// RFC 7296 §2.23: if NAT is detected, subsequent IKE and ESP use port 4500.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

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

	// Defaults used when fullCfg is nil (tests) or a value is unset (<=0).
	// See config.IKEv2Config for the matching production config fields.
	defaultMaxConcurrentPackets = 2048
	defaultHalfOpenSATimeout    = 30 * time.Second
	defaultMaxHalfOpenSAs       = 4096
	defaultCookieThreshold      = 2048
)

// Server is the IKEv2 responder.
type Server struct {
	cfg     *Config
	fullCfg *config.Config

	mu  sync.RWMutex
	sas map[uint64]*ikeSA // keyed by initiator SPI

	conn500  *net.UDPConn
	conn4500 *net.UDPConn

	conn500v6  *net.UDPConn // IKEv2 port 500, IPv6 (nil unless ListenAddrV6 is set)
	conn4500v6 *net.UDPConn // NAT-T port 4500, IPv6 (nil unless ListenAddrV6 is set)

	// Dependencies injected via Set* after construction.
	swm      *swm.Client
	sessions *session.Manager
	s2b      *s2b.Client
	gtpuMgr  *gtpu.Manager

	// DER-encoded ePDG X.509 certificate (nil → no CERT payload sent).
	certDER []byte

	// RSA private key matching certDER's public key, used to sign the
	// responder AUTH payload in the first IKE_AUTH response (TS 33.402 §8.2.1/8.2.2).
	privateKey *rsa.PrivateKey

	// workers bounds concurrent packet-processing goroutines (one per inbound
	// IKE packet otherwise has no ceiling). Sized in ListenAndServe.
	workers chan struct{}
	// cookies issues/verifies RFC 7296 §2.6 COOKIE challenges under load.
	cookies *cookieState

	ctx context.Context // cancelled on Close; drives reaperLoop lifetime

	log *slog.Logger
}

// Config holds IKEv2 server configuration.
type Config struct {
	ListenAddr   string // e.g. "0.0.0.0"
	ListenAddrV6 string // e.g. "::"; empty = IPv6 disabled
	IKEPort      int    // 0 → 500
	NATTPort     int    // 0 → 4500
}

func NewServer(cfg *Config, log *slog.Logger) *Server {
	return &Server{
		cfg:     cfg,
		sas:     make(map[uint64]*ikeSA),
		cookies: newCookieState(),
		log:     log,
	}
}

// saCount returns the total number of tracked IKE SAs (half-open and
// established), used as the load signal for the COOKIE and half-open-cap
// gates. Using the total rather than filtering by state avoids touching
// each ikeSA's own lock just to estimate load.
func (s *Server) saCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sas)
}

func (s *Server) maxConcurrentPackets() int {
	if s.fullCfg != nil && s.fullCfg.IKEv2.MaxConcurrentPackets > 0 {
		return s.fullCfg.IKEv2.MaxConcurrentPackets
	}
	return defaultMaxConcurrentPackets
}

func (s *Server) halfOpenSATimeout() time.Duration {
	if s.fullCfg != nil && s.fullCfg.IKEv2.HalfOpenSATimeout > 0 {
		return time.Duration(s.fullCfg.IKEv2.HalfOpenSATimeout) * time.Second
	}
	return defaultHalfOpenSATimeout
}

func (s *Server) maxHalfOpenSAs() int {
	if s.fullCfg != nil && s.fullCfg.IKEv2.MaxHalfOpenSAs > 0 {
		return s.fullCfg.IKEv2.MaxHalfOpenSAs
	}
	return defaultMaxHalfOpenSAs
}

func (s *Server) cookieThreshold() int {
	if s.fullCfg != nil && s.fullCfg.IKEv2.CookieThreshold > 0 {
		return s.fullCfg.IKEv2.CookieThreshold
	}
	return defaultCookieThreshold
}

// SetFullConfig loads and validates the ePDG certificate and private key.
// TS 33.402 §8.2.1 requires public-key signature authentication of the ePDG:
// the certificate's dNSName SAN must match the ePDG's IKEv2 ID_FQDN identity,
// and the private key must be available to sign the responder AUTH payload
// (§8.2.4.3 additionally requires the digitalSignature key usage bit).
func (s *Server) SetFullConfig(cfg *config.Config) error {
	s.fullCfg = cfg
	if cfg.IKEv2.CertFile == "" {
		return fmt.Errorf("IKEv2: cert_file is required but not configured")
	}
	if cfg.IKEv2.KeyFile == "" {
		return fmt.Errorf("IKEv2: key_file is required but not configured")
	}

	certPEM, err := os.ReadFile(cfg.IKEv2.CertFile)
	if err != nil {
		return fmt.Errorf("IKEv2: failed to read cert %q: %w", cfg.IKEv2.CertFile, err)
	}
	der, err := pemToDER(certPEM)
	if err != nil {
		return fmt.Errorf("IKEv2: failed to decode cert %q: %w", cfg.IKEv2.CertFile, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("IKEv2: failed to parse cert %q: %w", cfg.IKEv2.CertFile, err)
	}

	keyPEM, err := os.ReadFile(cfg.IKEv2.KeyFile)
	if err != nil {
		return fmt.Errorf("IKEv2: failed to read key %q: %w", cfg.IKEv2.KeyFile, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("IKEv2: no PEM block found in key %q", cfg.IKEv2.KeyFile)
	}
	var rsaKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("IKEv2: failed to parse key %q: %w", cfg.IKEv2.KeyFile, err)
		}
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("IKEv2: failed to parse key %q: %w", cfg.IKEv2.KeyFile, err)
		}
		var ok bool
		rsaKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("IKEv2: key %q is not an RSA key (got %T)", cfg.IKEv2.KeyFile, parsed)
		}
	default:
		return fmt.Errorf("IKEv2: unsupported key PEM block type %q in %q", keyBlock.Type, cfg.IKEv2.KeyFile)
	}

	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || certPub.N.Cmp(rsaKey.N) != 0 {
		return fmt.Errorf("IKEv2: private key %q does not match certificate %q", cfg.IKEv2.KeyFile, cfg.IKEv2.CertFile)
	}

	if cfg.EPDG.Name == "" {
		return fmt.Errorf("IKEv2: epdg.name must be configured to validate the certificate SAN")
	}
	if err := cert.VerifyHostname(cfg.EPDG.Name); err != nil {
		return fmt.Errorf("IKEv2: certificate %q SAN does not match epdg.name %q: %w", cfg.IKEv2.CertFile, cfg.EPDG.Name, err)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("IKEv2: certificate %q is missing the digitalSignature key usage required by TS 33.402 §8.2.4.3", cfg.IKEv2.CertFile)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("IKEv2: certificate %q is not currently valid (notBefore=%s notAfter=%s)", cfg.IKEv2.CertFile, cert.NotBefore, cert.NotAfter)
	}

	s.certDER = der
	s.privateKey = rsaKey
	s.log.Info("IKEv2: loaded ePDG certificate and private key",
		"cert", cfg.IKEv2.CertFile, "key", cfg.IKEv2.KeyFile,
		"subject", cert.Subject.CommonName, "not_after", cert.NotAfter)
	return nil
}

func (s *Server) SetSWM(c *swm.Client)                 { s.swm = c }
func (s *Server) SetSessionManager(m *session.Manager) { s.sessions = m }
func (s *Server) SetS2B(c *s2b.Client)                 { s.s2b = c }
func (s *Server) SetGTPU(m *gtpu.Manager)              { s.gtpuMgr = m }

func (s *Server) ListenAndServe(ctx context.Context) error {
	s.ctx = ctx
	s.workers = make(chan struct{}, s.maxConcurrentPackets())
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
	s.conn500, err = net.ListenUDP("udp4", mustResolveUDP("udp4", addr500))
	if err != nil {
		return fmt.Errorf("ikev2: listen %s: %w", addr500, err)
	}
	s.conn4500, err = net.ListenUDP("udp4", mustResolveUDP("udp4", addr4500))
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

	if s.cfg.ListenAddrV6 != "" {
		addr500v6 := fmt.Sprintf("[%s]:%d", s.cfg.ListenAddrV6, ikeP)
		addr4500v6 := fmt.Sprintf("[%s]:%d", s.cfg.ListenAddrV6, nattP)

		s.conn500v6, err = net.ListenUDP("udp6", mustResolveUDP("udp6", addr500v6))
		if err != nil {
			s.conn500.Close()
			s.conn4500.Close()
			return fmt.Errorf("ikev2: listen %s: %w", addr500v6, err)
		}
		s.conn4500v6, err = net.ListenUDP("udp6", mustResolveUDP("udp6", addr4500v6))
		if err != nil {
			s.conn500.Close()
			s.conn4500.Close()
			s.conn500v6.Close()
			return fmt.Errorf("ikev2: listen %s: %w", addr4500v6, err)
		}
		if err := setUDPEncapESP(s.conn4500v6); err != nil {
			s.conn500.Close()
			s.conn4500.Close()
			s.conn500v6.Close()
			s.conn4500v6.Close()
			return fmt.Errorf("ikev2: set UDP_ENCAP_ESPINUDP on %s: %w", addr4500v6, err)
		}

		s.log.Info("IKEv2 listening (IPv6)", "ike", addr500v6, "natt", addr4500v6)

		go s.readLoop(s.conn500v6, false)
		go s.readLoop(s.conn4500v6, true)
	}

	go s.reaperLoop()
	go s.halfOpenReaperLoop()
	return nil
}

func (s *Server) Close() {
	if s.conn500 != nil {
		s.conn500.Close()
	}
	if s.conn4500 != nil {
		s.conn4500.Close()
	}
	if s.conn500v6 != nil {
		s.conn500v6.Close()
	}
	if s.conn4500v6 != nil {
		s.conn4500v6.Close()
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
		// Bound concurrent packet processing: an unbounded goroutine-per-packet
		// dispatch lets unauthenticated UDP traffic exhaust goroutines/memory.
		// When saturated, drop rather than block the read loop.
		select {
		case s.workers <- struct{}{}:
			go func() {
				defer func() { <-s.workers }()
				s.handlePacket(conn, remote, pkt, natt)
			}()
		default:
			s.log.Warn("IKEv2 packet dropped: worker pool saturated", "remote", remote)
		}
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

func mustResolveUDP(network, addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr(network, addr)
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
