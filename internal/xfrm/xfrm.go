package xfrm

// Linux XFRM netlink — kernel IPsec SA and policy programming.
// Called after IKE_AUTH CHILD SA establishment to install ESP SAs in the kernel.

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// ChildSAParams contains all parameters needed to program one bidirectional ESP CHILD SA.
type ChildSAParams struct {
	// Outer tunnel endpoints: real IP addresses of the IPsec peers.
	LocalIP  net.IP // ePDG's IP (the address the UE sends IKE/ESP packets to)
	RemoteIP net.IP // UE's outer IP (source of received IKE/ESP packets)

	// SPIs from IKE negotiation.
	InboundSPI  uint32 // our allocation — what the UE uses when sending to us
	OutboundSPI uint32 // UE's allocation — what we use when sending to the UE

	// Derived CHILD SA keys (from prf+(SK_d, Ni|Nr)).
	EncKeyIn  []byte // SK_ei: initiator (UE→ePDG) encryption key, used for decrypt on our side
	IntKeyIn  []byte // SK_ai: initiator integrity key
	EncKeyOut []byte // SK_er: responder (ePDG→UE) encryption key
	IntKeyOut []byte // SK_ar: responder integrity key

	// Algorithm identifiers (Linux kernel crypto API strings).
	EncAlgName   string // e.g. "cbc(aes)"
	IntAlgName   string // e.g. "hmac(sha1)", "hmac(sha256)", "hmac(sha512)"
	IntTruncBits int    // truncated output in bits: 96, 128, or 256

	// NAT-T: when set, wrap ESP in UDP per RFC 3948.
	NATT        bool
	NATTSrcPort int // ePDG's NAT-T port (4500)
	NATTDstPort int // UE's NAT-T source port (usually 4500)

	// Traffic selectors for XFRM policy (inner addresses, not outer tunnel endpoints).
	LocalTS  *net.IPNet // ePDG inner: 0.0.0.0/0 (accepts all)
	RemoteTS *net.IPNet // UE inner: PAA/32 (PGW-assigned address)
}

// InstallChildSA programs inbound and outbound XFRM SAs and policies in the kernel.
func InstallChildSA(p ChildSAParams) error {
	localIP4 := p.LocalIP.To4()
	remoteIP4 := p.RemoteIP.To4()
	if localIP4 == nil || remoteIP4 == nil {
		return fmt.Errorf("xfrm: only IPv4 supported (local=%v remote=%v)", p.LocalIP, p.RemoteIP)
	}

	inbound, outbound := buildSAs(p, localIP4, remoteIP4)

	if err := netlink.XfrmStateAdd(inbound); err != nil {
		return fmt.Errorf("xfrm: add inbound SA (spi=%08x): %w", p.InboundSPI, err)
	}
	if err := netlink.XfrmStateAdd(outbound); err != nil {
		_ = netlink.XfrmStateDel(inbound)
		return fmt.Errorf("xfrm: add outbound SA (spi=%08x): %w", p.OutboundSPI, err)
	}

	inPol, fwdPol, outPol := buildPolicies(p, localIP4, remoteIP4)

	if err := netlink.XfrmPolicyAdd(inPol); err != nil {
		_ = netlink.XfrmStateDel(inbound)
		_ = netlink.XfrmStateDel(outbound)
		return fmt.Errorf("xfrm: add inbound policy: %w", err)
	}
	if err := netlink.XfrmPolicyAdd(fwdPol); err != nil {
		_ = netlink.XfrmPolicyDel(inPol)
		_ = netlink.XfrmStateDel(inbound)
		_ = netlink.XfrmStateDel(outbound)
		return fmt.Errorf("xfrm: add forward policy: %w", err)
	}
	if err := netlink.XfrmPolicyAdd(outPol); err != nil {
		_ = netlink.XfrmPolicyDel(fwdPol)
		_ = netlink.XfrmPolicyDel(inPol)
		_ = netlink.XfrmStateDel(inbound)
		_ = netlink.XfrmStateDel(outbound)
		return fmt.Errorf("xfrm: add outbound policy: %w", err)
	}
	return nil
}

// FlushAll removes all ESP XFRM states and policies from the kernel.
// Called at startup and shutdown to clear stale state from previous runs.
func FlushAll() error {
	errP := netlink.XfrmPolicyFlush()
	errS := netlink.XfrmStateFlush(netlink.XFRM_PROTO_ESP)
	if errP != nil {
		return errP
	}
	return errS
}

// RemoveChildSA deletes the XFRM SAs and policies for a CHILD SA.
// Best-effort: continues on partial failures and returns the first error.
func RemoveChildSA(p ChildSAParams) error {
	localIP4 := p.LocalIP.To4()
	remoteIP4 := p.RemoteIP.To4()
	if localIP4 == nil || remoteIP4 == nil {
		return fmt.Errorf("xfrm: only IPv4 supported")
	}

	inPol, fwdPol, outPol := buildPolicies(p, localIP4, remoteIP4)
	inbound, outbound := buildSAs(p, localIP4, remoteIP4)

	var firstErr error
	save := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	save(netlink.XfrmPolicyDel(outPol))
	save(netlink.XfrmPolicyDel(fwdPol))
	save(netlink.XfrmPolicyDel(inPol))
	save(netlink.XfrmStateDel(outbound))
	save(netlink.XfrmStateDel(inbound))
	return firstErr
}

// ─────────────────────────────────────────────────────────────────────────────

func buildSAs(p ChildSAParams, localIP4, remoteIP4 net.IP) (*netlink.XfrmState, *netlink.XfrmState) {
	// Inbound SA: UE→ePDG (we decrypt with initiator keys).
	inbound := &netlink.XfrmState{
		Src:          remoteIP4,
		Dst:          localIP4,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          int(p.InboundSPI),
		ReplayWindow: 32,
		Auth: &netlink.XfrmStateAlgo{
			Name:        p.IntAlgName,
			Key:         p.IntKeyIn,
			TruncateLen: p.IntTruncBits,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: p.EncAlgName,
			Key:  p.EncKeyIn,
		},
	}
	if p.NATT {
		inbound.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: p.NATTDstPort, // packets arrive from UE's port
			DstPort: p.NATTSrcPort, // packets arrive at our port
		}
	}

	// Outbound SA: ePDG→UE (we encrypt with responder keys).
	outbound := &netlink.XfrmState{
		Src:          localIP4,
		Dst:          remoteIP4,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          int(p.OutboundSPI),
		ReplayWindow: 32,
		Auth: &netlink.XfrmStateAlgo{
			Name:        p.IntAlgName,
			Key:         p.IntKeyOut,
			TruncateLen: p.IntTruncBits,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: p.EncAlgName,
			Key:  p.EncKeyOut,
		},
	}
	if p.NATT {
		outbound.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: p.NATTSrcPort, // we send from our port
			DstPort: p.NATTDstPort, // we send to UE's port
		}
	}
	return inbound, outbound
}

func buildPolicies(p ChildSAParams, localIP4, remoteIP4 net.IP) (*netlink.XfrmPolicy, *netlink.XfrmPolicy, *netlink.XfrmPolicy) {
	tmplIn := netlink.XfrmPolicyTmpl{
		Src:   remoteIP4,
		Dst:   localIP4,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
	}
	// Inbound policy: for traffic destined to the local machine after decryption.
	inPol := &netlink.XfrmPolicy{
		Src:      p.RemoteTS,
		Dst:      p.LocalTS,
		Dir:      netlink.XFRM_DIR_IN,
		Priority: 100,
		Tmpls:    []netlink.XfrmPolicyTmpl{tmplIn},
	}
	// Forward policy: required for UE traffic that is decrypted and then forwarded
	// (not delivered locally). Without this the kernel silently drops the inner packet.
	fwdPol := &netlink.XfrmPolicy{
		Src:      p.RemoteTS,
		Dst:      p.LocalTS,
		Dir:      netlink.XFRM_DIR_FWD,
		Priority: 100,
		Tmpls:    []netlink.XfrmPolicyTmpl{tmplIn},
	}
	// Outbound policy: inner packets from ePDG (0.0.0.0/0) to UE (PAA/32).
	outPol := &netlink.XfrmPolicy{
		Src:      p.LocalTS,
		Dst:      p.RemoteTS,
		Dir:      netlink.XFRM_DIR_OUT,
		Priority: 100,
		Tmpls: []netlink.XfrmPolicyTmpl{{
			Src:   localIP4,
			Dst:   remoteIP4,
			Proto: netlink.XFRM_PROTO_ESP,
			Mode:  netlink.XFRM_MODE_TUNNEL,
		}},
	}
	return inPol, fwdPol, outPol
}

// MigrateChildSA updates the outer tunnel endpoints of an existing CHILD SA without
// changing SPIs or keys. Used by MOBIKE (RFC 4555) when the UE changes IP address.
// The old SA is removed best-effort; install of the new SA is authoritative.
func MigrateChildSA(old, new ChildSAParams) error {
	_ = RemoveChildSA(old) // best-effort; old SA may already be evicted by kernel
	return InstallChildSA(new)
}

// LocalIPFor returns the local IP address that the OS would use to reach remote.
// Uses a connected-UDP-socket routing trick — no packet is sent.
func LocalIPFor(remote net.IP) (net.IP, error) {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remote, Port: 1})
	if err != nil {
		return nil, fmt.Errorf("xfrm: local IP lookup for %v: %w", remote, err)
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("xfrm: non-IPv4 local address for %v", remote)
	}
	return ip, nil
}
