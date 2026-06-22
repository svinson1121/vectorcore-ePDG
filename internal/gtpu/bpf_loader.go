package gtpu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// config_map keys, mirroring CONFIG_KEY_* in bpf/xdp_gtpu_decap.c.
const (
	configKeyLocalIP      uint32 = 0
	configKeyValidatePeer uint32 = 1
)

// BPFDataplane manages the XDP downlink decap BPF program and its maps.
// Zero value is not valid; use newBPFDataplane.
type BPFDataplane struct {
	objs       GtpuDecapObjects
	xdpLink    link.Link
	ifaceIndex int
}

// newBPFDataplane loads the embedded BPF objects into the kernel, writes
// localGTPUIP into config_map, and attaches the XDP program to iface.
//
// iface is the NIC name receiving UDP/2152 from the PGW.
// If empty, the interface that carries localGTPUIP is used.
// mode must be "generic", "native", or "offload".
// validateOuterPeer enables the outer-source-IP check (TS 29.281 §4.3.0):
// when true, a TEID's G-PDU traffic is dropped unless its outer IP source
// matches the PGW address that TEID was installed with (see AddTEID).
func newBPFDataplane(iface string, localGTPUIP net.IP, mode string, maxEntries int, validateOuterPeer bool) (*BPFDataplane, error) {
	ip4 := localGTPUIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("bpf: local GTP-U IP must be IPv4, got %s", localGTPUIP)
	}

	if iface == "" {
		var err error
		iface, err = ifaceForIP(ip4)
		if err != nil {
			return nil, fmt.Errorf("bpf: auto-detect XDP interface: %w", err)
		}
	}

	nl, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("bpf: look up interface %q: %w", iface, err)
	}
	ifindex := nl.Attrs().Index
	d := &BPFDataplane{ifaceIndex: ifindex}

	spec, err := LoadGtpuDecap()
	if err != nil {
		return nil, fmt.Errorf("bpf: load collection spec: %w", err)
	}

	if maxEntries > 0 {
		if m, ok := spec.Maps["teid_map"]; ok {
			m.MaxEntries = uint32(maxEntries)
		}
		if m, ok := spec.Maps["dl_bearer_counters"]; ok {
			m.MaxEntries = uint32(maxEntries)
		}
	}

	if err := spec.LoadAndAssign(&d.objs, nil); err != nil {
		return nil, fmt.Errorf("bpf: load and assign objects: %w", err)
	}

	ipU32 := binary.LittleEndian.Uint32(ip4)
	if err := d.objs.ConfigMap.Put(configKeyLocalIP, ipU32); err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("bpf: write config_map local IP: %w", err)
	}
	enforcePeer := uint32(0)
	if validateOuterPeer {
		enforcePeer = 1
	}
	if err := d.objs.ConfigMap.Put(configKeyValidatePeer, enforcePeer); err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("bpf: write config_map validate-peer flag: %w", err)
	}

	xdpMode, err := parseXDPMode(mode)
	if err != nil {
		d.objs.Close()
		return nil, err
	}

	d.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   d.objs.GtpuDecapFunc,
		Interface: ifindex,
		Flags:     xdpMode,
	})
	if err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("bpf: attach XDP to %s (mode=%s): %w", iface, mode, err)
	}

	return d, nil
}

// AddTEID inserts or updates a TEID → PAA + expected-peer entry in teid_map.
// teid is in host byte order. paa and pgwAddr must be 4-byte IPv4 addresses;
// pgwAddr is the PGW GTP-U address this TEID was negotiated with over
// GTPv2-C/S2b — the only outer source XDP will accept G-PDUs for this TEID
// from when outer-peer validation is enabled (TS 29.281 §4.3.0; finding #8).
func (d *BPFDataplane) AddTEID(teid uint32, paa, pgwAddr net.IP) error {
	ip4 := paa.To4()
	if ip4 == nil {
		return fmt.Errorf("bpf: PAA must be IPv4, got %s", paa)
	}
	pgw4 := pgwAddr.To4()
	if pgw4 == nil {
		return fmt.Errorf("bpf: PGW address must be IPv4, got %s", pgwAddr)
	}
	entry := GtpuDecapTeidEntry{}
	copy(entry.Paa[:], ip4)
	copy(entry.PgwAddr[:], pgw4)
	if err := d.objs.TeidMap.Put(teid, entry); err != nil {
		return fmt.Errorf("bpf: teid_map put TEID %d: %w", teid, err)
	}
	return nil
}

// RemoveTEID deletes a TEID from teid_map. Returns nil if the key was absent.
func (d *BPFDataplane) RemoveTEID(teid uint32) error {
	err := d.objs.TeidMap.Delete(teid)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("bpf: teid_map delete TEID %d: %w", teid, err)
	}
	return nil
}

// BearerCounter returns the downlink packet/byte counters recorded for teid
// in dl_bearer_counters. ok is false if no entry exists yet (e.g. the
// bearer hasn't seen any downlink traffic).
func (d *BPFDataplane) BearerCounter(teid uint32) (packets, bytes uint64, ok bool) {
	var c GtpuDecapBearerCounters
	if err := d.objs.DlBearerCounters.Lookup(teid, &c); err != nil {
		return 0, 0, false
	}
	return c.Packets, c.Bytes, true
}

// RemoveBearerCounter deletes the dl_bearer_counters entry for teid.
// Returns nil if the key was absent.
func (d *BPFDataplane) RemoveBearerCounter(teid uint32) error {
	err := d.objs.DlBearerCounters.Delete(teid)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("bpf: dl_bearer_counters delete TEID %d: %w", teid, err)
	}
	return nil
}

// IfaceIndex returns the kernel interface index of the NIC the XDP program is
// attached to. Used by the control plane to add/remove per-UE host routes.
func (d *BPFDataplane) IfaceIndex() int {
	return d.ifaceIndex
}

// DownlinkStats returns the per-CPU stats array (dl_stats map).
// Callers must sum all CPU values to get totals.
func (d *BPFDataplane) DownlinkStats() *ebpf.Map {
	return d.objs.DlStats
}

// TEIDMapCount returns the number of entries currently in teid_map.
func (d *BPFDataplane) TEIDMapCount() (int, error) {
	return countMapEntries[uint32, GtpuDecapTeidEntry](d.objs.TeidMap)
}

// countMapEntries iterates m and counts its keys. Used for read-only
// occupancy reporting; not on any packet-processing hot path.
func countMapEntries[K, V any](m *ebpf.Map) (int, error) {
	var key K
	var val V
	count := 0
	it := m.Iterate()
	for it.Next(&key, &val) {
		count++
	}
	if err := it.Err(); err != nil {
		return 0, fmt.Errorf("bpf: iterate map: %w", err)
	}
	return count, nil
}

// Close detaches the XDP program and releases all kernel BPF resources.
func (d *BPFDataplane) Close() error {
	var first error
	if d.xdpLink != nil {
		if err := d.xdpLink.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := d.objs.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

// ifaceForIP returns the name of the network interface that has ip assigned.
func ifaceForIP(ip net.IP) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ifIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ifIP = v.IP
			case *net.IPAddr:
				ifIP = v.IP
			}
			if ifIP.To4() != nil && ifIP.To4().Equal(ip) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface found with IP %s", ip)
}

func parseXDPMode(mode string) (link.XDPAttachFlags, error) {
	switch mode {
	case "generic":
		return link.XDPGenericMode, nil
	case "native":
		return link.XDPDriverMode, nil
	case "offload":
		return link.XDPOffloadMode, nil
	default:
		return 0, fmt.Errorf("bpf: unknown XDP mode %q", mode)
	}
}
