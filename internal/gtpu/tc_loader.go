package gtpu

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const maxTCBPFTFTRules = 32

// TCDataplane manages the TC-BPF uplink GTP-U encapsulation program
// and the vc-xfrm0 XFRM interface it is attached to.
// Zero value is not valid; use newTCDataplane.
type TCDataplane struct {
	objs     GtpuEncapObjects
	tcLink   link.Link
	xfrmLink netlink.Link // the vc-xfrm0 interface
	ifID     uint32
}

type TCBPFTFTRule struct {
	TEID         uint32
	Precedence   uint8
	Flags        uint8
	Protocol     uint8
	RemoteIP     [4]uint8
	RemoteMask   [4]uint8
	LocalPortLo  uint16
	LocalPortHi  uint16
	RemotePortLo uint16
	RemotePortHi uint16
}

// newTCDataplane creates (or reuses) the named XFRM interface with the given
// if_id, loads the TC-BPF uplink encap program, and attaches it to the XFRM
// interface ingress.
func newTCDataplane(ifName string, ifID uint32, maxEntries int) (*TCDataplane, error) {
	d := &TCDataplane{ifID: ifID}

	// ── Create or reuse the XFRM interface ──────────────────────────────────
	xfrmLink, err := ensureXfrmIface(ifName, ifID)
	if err != nil {
		return nil, fmt.Errorf("tc: ensure XFRM interface %s: %w", ifName, err)
	}
	d.xfrmLink = xfrmLink

	// ── Load BPF objects ────────────────────────────────────────────────────
	spec, err := LoadGtpuEncap()
	if err != nil {
		return nil, fmt.Errorf("tc: load BPF spec: %w", err)
	}
	if maxEntries > 0 {
		if m, ok := spec.Maps["ue_session_map"]; ok {
			m.MaxEntries = uint32(maxEntries)
		}
		if m, ok := spec.Maps["tft_rule_map"]; ok {
			m.MaxEntries = uint32(maxEntries)
		}
	}
	if err := spec.LoadAndAssign(&d.objs, nil); err != nil {
		return nil, fmt.Errorf("tc: load BPF objects: %w", err)
	}

	// ── Attach TC-BPF to XFRM interface ingress ─────────────────────────────
	d.tcLink, err = link.AttachTCX(link.TCXOptions{
		Interface: xfrmLink.Attrs().Index,
		Program:   d.objs.TcGtpuEncapFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("tc: attach TC-BPF to %s ingress: %w", ifName, err)
	}

	return d, nil
}

// IfaceIndex returns the kernel index of the vc-xfrm0 interface.
// Used by the control plane to install per-UE routes via vc-xfrm0.
func (d *TCDataplane) IfaceIndex() int {
	return d.xfrmLink.Attrs().Index
}

// IfID returns the XFRM interface if_id programmed into the kernel SAs.
func (d *TCDataplane) IfID() uint32 {
	return d.ifID
}

// UplinkStats returns the ul_stats map for reading per-CPU counters.
func (d *TCDataplane) UplinkStats() *ebpf.Map {
	return d.objs.UlStats
}

// AddUESession inserts or updates a UE session entry in ue_session_map.
// paa is the UE's inner IPv4 address (key, network byte order).
// ulTEID is the uplink TEID in host byte order.
// pgwIP is the PGW GTP-U destination address.
// localIP is the ePDG S2b GTP-U source address.
// s2bIfindex is the S2b interface index for bpf_redirect_neigh.
func (d *TCDataplane) AddUESession(paa net.IP, ulTEID uint32, pgwIP, localIP net.IP, s2bIfindex int) error {
	paa4 := paa.To4()
	pgw4 := pgwIP.To4()
	loc4 := localIP.To4()
	if paa4 == nil || pgw4 == nil || loc4 == nil {
		return fmt.Errorf("tc: AddUESession: all IPs must be IPv4")
	}

	var key GtpuEncapIpv4Key
	copy(key.Addr[:], paa4)

	entry := GtpuEncapUeSessionEntry{
		UlTeid:     ulTEID,
		S2bIfindex: uint32(s2bIfindex),
		RuleCount:  0,
	}
	copy(entry.PgwIp[:], pgw4)
	copy(entry.LocalIp[:], loc4)
	if err := d.objs.UeSessionMap.Put(key, entry); err != nil {
		return fmt.Errorf("tc: ue_session_map put PAA %s: %w", paa4, err)
	}
	return nil
}

func (d *TCDataplane) SetTFTRules(paa net.IP, rules []TCBPFTFTRule) error {
	paa4 := paa.To4()
	if paa4 == nil {
		return fmt.Errorf("tc: SetTFTRules: PAA must be IPv4")
	}
	if len(rules) > maxTCBPFTFTRules {
		return fmt.Errorf("tc: SetTFTRules: %d rules exceeds max %d", len(rules), maxTCBPFTFTRules)
	}

	var sessionKey GtpuEncapIpv4Key
	copy(sessionKey.Addr[:], paa4)

	var entry GtpuEncapUeSessionEntry
	if err := d.objs.UeSessionMap.Lookup(sessionKey, &entry); err != nil {
		return fmt.Errorf("tc: ue_session_map lookup PAA %s: %w", paa4, err)
	}

	entry.RuleCount = 0
	if err := d.objs.UeSessionMap.Put(sessionKey, entry); err != nil {
		return fmt.Errorf("tc: ue_session_map clear rule_count PAA %s: %w", paa4, err)
	}
	if err := d.clearTFTRules(paa4); err != nil {
		return err
	}

	for i, rule := range rules {
		key := GtpuEncapTftRuleKey{Index: uint32(i)}
		copy(key.Addr[:], paa4)
		value := GtpuEncapTftRuleEntry{
			UlTeid:       rule.TEID,
			Precedence:   rule.Precedence,
			Flags:        rule.Flags,
			Protocol:     rule.Protocol,
			RemoteIp:     rule.RemoteIP,
			RemoteMask:   rule.RemoteMask,
			LocalPortLo:  rule.LocalPortLo,
			LocalPortHi:  rule.LocalPortHi,
			RemotePortLo: rule.RemotePortLo,
			RemotePortHi: rule.RemotePortHi,
		}
		if err := d.objs.TftRuleMap.Put(key, value); err != nil {
			return fmt.Errorf("tc: tft_rule_map put PAA %s index %d: %w", paa4, i, err)
		}
	}

	entry.RuleCount = uint32(len(rules))
	if err := d.objs.UeSessionMap.Put(sessionKey, entry); err != nil {
		return fmt.Errorf("tc: ue_session_map rule_count update PAA %s: %w", paa4, err)
	}
	return nil
}

func (d *TCDataplane) ClearTFTRules(paa net.IP) error {
	paa4 := paa.To4()
	if paa4 == nil {
		return nil
	}
	return d.clearTFTRules(paa4)
}

func (d *TCDataplane) clearTFTRules(paa4 net.IP) error {
	for i := uint32(0); i < maxTCBPFTFTRules; i++ {
		key := GtpuEncapTftRuleKey{Index: i}
		copy(key.Addr[:], paa4)
		err := d.objs.TftRuleMap.Delete(key)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("tc: tft_rule_map delete PAA %s index %d: %w", paa4, i, err)
		}
	}
	return nil
}

// RemoveUESession deletes the UE session entry for paa. Returns nil if absent.
func (d *TCDataplane) RemoveUESession(paa net.IP) error {
	paa4 := paa.To4()
	if paa4 == nil {
		return nil
	}
	if err := d.clearTFTRules(paa4); err != nil {
		return err
	}
	var key GtpuEncapIpv4Key
	copy(key.Addr[:], paa4)
	err := d.objs.UeSessionMap.Delete(key)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("tc: ue_session_map delete PAA %s: %w", paa4, err)
	}
	return nil
}

// Close detaches the TC program and releases all kernel BPF resources.
// It does NOT delete the vc-xfrm0 interface (that is done by the Manager).
func (d *TCDataplane) Close() error {
	var first error
	if d.tcLink != nil {
		if err := d.tcLink.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := d.objs.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

// ── XFRM interface helpers ────────────────────────────────────────────────────

// ensureXfrmIface returns the named XFRM interface, creating it if needed.
func ensureXfrmIface(name string, ifID uint32) (netlink.Link, error) {
	existing, err := netlink.LinkByName(name)
	if err == nil {
		// Interface exists — verify if_id matches.
		if xi, ok := existing.(*netlink.Xfrmi); ok && xi.Ifid == ifID {
			if err := netlink.LinkSetUp(existing); err != nil {
				return nil, fmt.Errorf("set %s up: %w", name, err)
			}
			return existing, nil
		}
		// Wrong type or if_id — delete and recreate.
		_ = netlink.LinkDel(existing)
	}

	xi := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Ifid:      ifID,
	}
	if err := netlink.LinkAdd(xi); err != nil {
		return nil, fmt.Errorf("add xfrm interface %s if_id=%d: %w", name, ifID, err)
	}
	created, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("look up %s after creation: %w", name, err)
	}
	if err := netlink.LinkSetUp(created); err != nil {
		return nil, fmt.Errorf("set %s up: %w", name, err)
	}
	return created, nil
}

// DeleteXfrmIface removes the named XFRM interface. Called on Manager shutdown.
func DeleteXfrmIface(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil // already gone
	}
	return netlink.LinkDel(l)
}
