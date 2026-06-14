package gtpu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	nfDrop   uint32 = 0
	nfAccept uint32 = 1

	netfilterSubsysQueue = 3
	nfqnlMsgPacket       = 0
	nfqnlMsgVerdict      = 1
	nfqnlMsgConfig       = 2

	nfqaPacketHdr = 1
	nfqaPayload   = 10

	nfqaVerdictHdr = 2

	nfqaCfgCmd    = 1
	nfqaCfgParams = 2

	nfqnlCfgCmdBind   = 1
	nfqnlCfgCmdPfBind = 3
	nfqnlCopyPacket   = 2
	netfilterV0       = 0
	netlinkHeaderLen  = 16
	nfgenmsgLen       = 4
)

type nfqueueConn struct {
	fd       int
	queueNum uint16
	seq      uint32
	log      *slog.Logger
}

type nfqueuePacket struct {
	ID      uint32
	Payload []byte
}

func openNFQueue(queueNum int, log *slog.Logger) (*nfqueueConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("open NFQUEUE netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind NFQUEUE netlink socket: %w", err)
	}
	c := &nfqueueConn{fd: fd, queueNum: uint16(queueNum), log: log}
	if err := c.bind(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (c *nfqueueConn) Close() error {
	if c.fd < 0 {
		return nil
	}
	_ = unix.Shutdown(c.fd, unix.SHUT_RDWR)
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

func (c *nfqueueConn) bind() error {
	if err := c.sendConfig(0, nfqueueConfigCmd(nfqnlCfgCmdPfBind, unix.AF_INET)); err != nil {
		return fmt.Errorf("bind NFQUEUE AF_INET: %w", err)
	}
	if err := c.sendConfig(c.queueNum, nfqueueConfigCmd(nfqnlCfgCmdBind, unix.AF_INET)); err != nil {
		return fmt.Errorf("bind NFQUEUE queue %d: %w", c.queueNum, err)
	}
	params := make([]byte, 5)
	binary.BigEndian.PutUint32(params[0:4], 0xffff)
	params[4] = nfqnlCopyPacket
	if err := c.sendConfigAttrs(c.queueNum, []nfattr{{typ: nfqaCfgParams, payload: params}}); err != nil {
		return fmt.Errorf("set NFQUEUE copy mode queue %d: %w", c.queueNum, err)
	}
	return nil
}

func nfqueueConfigCmd(cmd uint8, family uint16) []byte {
	out := make([]byte, 4)
	out[0] = cmd
	binary.BigEndian.PutUint16(out[2:4], family)
	return out
}

func (c *nfqueueConn) sendConfig(queue uint16, cmd []byte) error {
	return c.sendConfigAttrs(queue, []nfattr{{typ: nfqaCfgCmd, payload: cmd}})
}

func (c *nfqueueConn) sendConfigAttrs(queue uint16, attrs []nfattr) error {
	return c.send(nfqnlMsgConfig, queue, attrs)
}

func (c *nfqueueConn) SetVerdict(packetID uint32, verdict uint32) error {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], verdict)
	binary.BigEndian.PutUint32(payload[4:8], packetID)
	return c.send(nfqnlMsgVerdict, c.queueNum, []nfattr{{typ: nfqaVerdictHdr, payload: payload}})
}

func (c *nfqueueConn) send(msgType uint16, queue uint16, attrs []nfattr) error {
	var payload []byte
	payload = append(payload, unix.AF_UNSPEC, netfilterV0, byte(queue>>8), byte(queue))
	for _, attr := range attrs {
		payload = append(payload, encodeNFAttr(attr.typ, attr.payload)...)
	}
	msgTypeFull := uint16(netfilterSubsysQueue<<8) | msgType
	length := netlinkHeaderLen + len(payload)
	out := make([]byte, length)
	nativeEndian.PutUint32(out[0:4], uint32(length))
	nativeEndian.PutUint16(out[4:6], msgTypeFull)
	nativeEndian.PutUint16(out[6:8], unix.NLM_F_REQUEST)
	seq := atomic.AddUint32(&c.seq, 1)
	nativeEndian.PutUint32(out[8:12], seq)
	copy(out[netlinkHeaderLen:], payload)
	return unix.Sendto(c.fd, out, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func (c *nfqueueConn) ReadPacket() (nfqueuePacket, error) {
	buf := make([]byte, 65535)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return nfqueuePacket{}, err
		}
		msgs, err := parseNetlinkMessages(buf[:n])
		if err != nil {
			return nfqueuePacket{}, err
		}
		for _, msg := range msgs {
			if msg.typ != uint16(netfilterSubsysQueue<<8)|nfqnlMsgPacket {
				continue
			}
			pkt, err := parseNFQueuePacket(msg.payload)
			if err != nil {
				if c.log != nil {
					c.log.Warn("NFQUEUE packet parse failed", "error", err)
				}
				continue
			}
			return pkt, nil
		}
	}
}

type nfattr struct {
	typ     uint16
	payload []byte
}

type nlmsg struct {
	typ     uint16
	payload []byte
}

var nativeEndian binary.ByteOrder = binary.NativeEndian

func encodeNFAttr(typ uint16, payload []byte) []byte {
	length := 4 + len(payload)
	out := make([]byte, align4(length))
	nativeEndian.PutUint16(out[0:2], uint16(length))
	nativeEndian.PutUint16(out[2:4], typ)
	copy(out[4:], payload)
	return out
}

func parseNetlinkMessages(b []byte) ([]nlmsg, error) {
	var out []nlmsg
	for len(b) >= netlinkHeaderLen {
		length := int(nativeEndian.Uint32(b[0:4]))
		if length < netlinkHeaderLen || length > len(b) {
			return nil, fmt.Errorf("invalid netlink message length %d remaining=%d", length, len(b))
		}
		typ := nativeEndian.Uint16(b[4:6])
		if typ == unix.NLMSG_ERROR {
			if length >= netlinkHeaderLen+4 {
				code := int32(nativeEndian.Uint32(b[netlinkHeaderLen : netlinkHeaderLen+4]))
				if code != 0 {
					return nil, unix.Errno(-code)
				}
			}
			b = b[min(align4(length), len(b)):]
			continue
		}
		out = append(out, nlmsg{typ: typ, payload: append([]byte(nil), b[netlinkHeaderLen:length]...)})
		b = b[min(align4(length), len(b)):]
	}
	return out, nil
}

func parseNFQueuePacket(payload []byte) (nfqueuePacket, error) {
	if len(payload) < nfgenmsgLen {
		return nfqueuePacket{}, fmt.Errorf("NFQUEUE packet missing nfgenmsg")
	}
	attrs, err := parseNFAttrs(payload[nfgenmsgLen:])
	if err != nil {
		return nfqueuePacket{}, err
	}
	var pkt nfqueuePacket
	for _, attr := range attrs {
		switch attr.typ {
		case nfqaPacketHdr:
			if len(attr.payload) < 4 {
				return nfqueuePacket{}, fmt.Errorf("NFQUEUE packet header too short")
			}
			pkt.ID = binary.BigEndian.Uint32(attr.payload[0:4])
		case nfqaPayload:
			pkt.Payload = append([]byte(nil), attr.payload...)
		}
	}
	if pkt.ID == 0 {
		return nfqueuePacket{}, fmt.Errorf("NFQUEUE packet missing packet id")
	}
	if len(pkt.Payload) == 0 {
		return nfqueuePacket{}, fmt.Errorf("NFQUEUE packet missing payload")
	}
	return pkt, nil
}

func parseNFAttrs(b []byte) ([]nfattr, error) {
	var attrs []nfattr
	for len(b) >= 4 {
		length := int(nativeEndian.Uint16(b[0:2]))
		if length < 4 || length > len(b) {
			return nil, fmt.Errorf("invalid NFQUEUE attr length %d remaining=%d", length, len(b))
		}
		attrs = append(attrs, nfattr{typ: nativeEndian.Uint16(b[2:4]), payload: append([]byte(nil), b[4:length]...)})
		b = b[min(align4(length), len(b)):]
	}
	return attrs, nil
}

func align4(n int) int {
	return (n + 3) &^ 3
}

func (m *Manager) setupNFQueueRules() error {
	if m.cfg.GTP.UplinkCapture.Mode != "nfqueue" || !m.cfg.GTP.UplinkCapture.InstallRules {
		return nil
	}
	if err := enableIPForward(); err != nil {
		return fmt.Errorf("enable ip_forward for NFQUEUE uplink capture: %w", err)
	}
	if err := m.iptables("-N", m.cfg.GTP.UplinkCapture.ChainName); err != nil && !iptablesAlreadyExists(err) {
		return fmt.Errorf("create NFQUEUE iptables chain %s: %w", m.cfg.GTP.UplinkCapture.ChainName, err)
	}
	if !m.iptablesCheck("FORWARD", "-j", m.cfg.GTP.UplinkCapture.ChainName) {
		if err := m.iptables("-I", "FORWARD", "1", "-j", m.cfg.GTP.UplinkCapture.ChainName); err != nil {
			return fmt.Errorf("install NFQUEUE FORWARD jump to %s: %w", m.cfg.GTP.UplinkCapture.ChainName, err)
		}
	}
	if err := m.detectOrCleanupStaleNFQueueRules(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) installNFQueueRule(sessionID string, paa net.IP) error {
	if m.cfg.GTP.UplinkCapture.Mode != "nfqueue" || !m.cfg.GTP.UplinkCapture.InstallRules {
		return nil
	}
	args := m.nfqueueRuleArgs(paa)
	if m.iptablesCheck(append([]string{m.cfg.GTP.UplinkCapture.ChainName}, args...)...) {
		return nil
	}
	if err := m.iptables(append([]string{"-A", m.cfg.GTP.UplinkCapture.ChainName}, args...)...); err != nil {
		return fmt.Errorf("install NFQUEUE uplink rule paa=%s queue=%d: %w", paa.String(), m.cfg.GTP.UplinkCapture.QueueNum, err)
	}
	m.log.Info("NFQUEUE uplink rule installed",
		"session_id", sessionID,
		"paa", paa.String(),
		"queue_num", m.cfg.GTP.UplinkCapture.QueueNum,
		"backend", m.cfg.GTP.UplinkCapture.FirewallBackend,
		"chain", m.cfg.GTP.UplinkCapture.ChainName,
	)
	return nil
}

func (m *Manager) removeNFQueueRule(paa net.IP) error {
	if m.cfg.GTP.UplinkCapture.Mode != "nfqueue" || !m.cfg.GTP.UplinkCapture.InstallRules || paa == nil {
		return nil
	}
	args := append([]string{"-D", m.cfg.GTP.UplinkCapture.ChainName}, m.nfqueueRuleArgs(paa)...)
	err := m.iptables(args...)
	result := "success"
	if err != nil {
		if iptablesNotFound(err) {
			result = "not_found"
			err = nil
		} else {
			result = "error"
		}
	}
	m.log.Info("NFQUEUE uplink rule removed",
		"paa", paa.String(),
		"queue_num", m.cfg.GTP.UplinkCapture.QueueNum,
		"backend", m.cfg.GTP.UplinkCapture.FirewallBackend,
		"chain", m.cfg.GTP.UplinkCapture.ChainName,
		"result", result,
	)
	return err
}

func (r *rollbackState) removeNFQueueRule(paa net.IP) {
	if err := r.m.removeNFQueueRule(paa); err != nil {
		r.errs = append(r.errs, err)
		return
	}
	r.nfqueueRuleRemoved = true
}

func (m *Manager) nfqueueRuleArgs(paa net.IP) []string {
	args := []string{"-s", hostNet(paa).String()}
	if m.cfg.GTP.UplinkCapture.IngressIfName != "" {
		args = append(args, "-i", m.cfg.GTP.UplinkCapture.IngressIfName)
	}
	args = append(args, "-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", m.cfg.GTP.UplinkCapture.QueueNum))
	if m.cfg.GTP.UplinkCapture.QueueBypass {
		args = append(args, "--queue-bypass")
	}
	return args
}

func (m *Manager) detectOrCleanupStaleNFQueueRules() error {
	out, err := exec.Command("iptables", "-S", m.cfg.GTP.UplinkCapture.ChainName).CombinedOutput()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "NFQUEUE") || !strings.Contains(line, "--queue-num "+fmt.Sprintf("%d", m.cfg.GTP.UplinkCapture.QueueNum)) {
			continue
		}
		if !m.cfg.GTP.UplinkCapture.CleanupStaleRulesOnStart {
			m.log.Warn("stale NFQUEUE uplink rule detected",
				"rule", line,
				"cleanup_enabled", false,
				"cleanup_command", strings.Replace(line, "-A "+m.cfg.GTP.UplinkCapture.ChainName, "iptables -D "+m.cfg.GTP.UplinkCapture.ChainName, 1),
			)
			continue
		}
		deleteArgs := strings.Fields(strings.Replace(line, "-A", "-D", 1))
		if len(deleteArgs) > 0 {
			if err := m.iptables(deleteArgs...); err != nil && !iptablesNotFound(err) {
				return fmt.Errorf("remove stale NFQUEUE rule %q: %w", line, err)
			}
		}
	}
	return nil
}

func (m *Manager) iptablesCheck(args ...string) bool {
	return m.iptables(append([]string{"-C"}, args...)...) == nil
}

func (m *Manager) iptables(args ...string) error {
	cmdArgs := append([]string{"-w"}, args...)
	out, err := exec.Command("iptables", cmdArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(cmdArgs, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// enableIPForward enables IPv4 packet forwarding. The NFQUEUE uplink chain sits
// in the FORWARD hook, which the kernel skips entirely when ip_forward is 0.
func enableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

func iptablesAlreadyExists(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "chain already exists")
}

func iptablesNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no chain/target/match") ||
		strings.Contains(msg, "bad rule") ||
		strings.Contains(msg, "does a matching rule exist")
}

func verdictName(v uint32) string {
	if v == nfAccept {
		return "ACCEPT"
	}
	return "DROP"
}

func destIP(pkt []byte) net.IP {
	if len(pkt) < 1 {
		return nil
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return nil
		}
		return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	case 6:
		if len(pkt) < 40 {
			return nil
		}
		return net.IP(pkt[24:40]).To16()
	default:
		return nil
	}
}

func ipProto(pkt []byte) uint8 {
	if len(pkt) < 1 {
		return 0
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 10 {
			return 0
		}
		return pkt[9]
	case 6:
		if len(pkt) < 7 {
			return 0
		}
		return pkt[6]
	default:
		return 0
	}
}

func ipLogString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

var _ = errors.Is
