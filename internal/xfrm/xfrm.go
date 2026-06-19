package xfrm

// Linux XFRM netlink — kernel IPsec SA and policy programming.
// Called after IKE_AUTH CHILD SA establishment to install ESP SAs in the kernel.

import (
	"fmt"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
)

const (
	IfName = "vc-xfrm0" // XFRM virtual interface; decrypted UE packets arrive here
	IfID   = uint32(1)  // if_id stamped on XFRM SAs; must match vc-xfrm0 if_id
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
	EncAlgName string // e.g. "cbc(aes)", "rfc4106(gcm(aes))"
	// IntAlgName == "" signals an AEAD cipher (EncAlgName covers integrity
	// too): buildSAs installs EncAlgName as an Aead transform instead of
	// separate Crypt+Auth ones, and IntKeyIn/Out/IntTruncBits are unused.
	IntAlgName   string // e.g. "hmac(sha1)", "hmac(sha256)", "hmac(sha512)", or "" for AEAD
	IntTruncBits int    // truncated output in bits: 96, 128, or 256; unused for AEAD

	// NAT-T: when set, wrap ESP in UDP per RFC 3948.
	NATT        bool
	NATTSrcPort int // ePDG's NAT-T port (4500)
	NATTDstPort int // UE's NAT-T source port (usually 4500)

	// Traffic selectors for XFRM policy (inner addresses, not outer tunnel endpoints).
	LocalTS  *net.IPNet // ePDG inner: 0.0.0.0/0 (accepts all)
	RemoteTS *net.IPNet // UE inner: PAA/32 (PGW-assigned address)

	// IfID, when non-zero, ties these SAs to an XFRM virtual interface (type xfrm)
	// with the matching if_id. Decrypted uplink packets are then delivered to that
	// interface where TC-BPF can encapsulate them. XFRM policies are skipped when
	// IfID is set.
	IfID uint32
}

// InstallChildSA programs inbound and outbound XFRM SAs and policies in the kernel.
func InstallChildSA(p ChildSAParams) error {
	localIP, remoteIP, err := resolveXFRMIPs(p.LocalIP, p.RemoteIP)
	if err != nil {
		return err
	}

	inbound, outbound := buildSAs(p, localIP, remoteIP)

	if err := netlink.XfrmStateAdd(inbound); err != nil {
		return fmt.Errorf("xfrm: add inbound SA (spi=%08x): %w", p.InboundSPI, err)
	}
	markInbound(p.InboundSPI)
	if err := netlink.XfrmStateAdd(outbound); err != nil {
		_ = netlink.XfrmStateDel(inbound)
		unmarkInbound(p.InboundSPI)
		return fmt.Errorf("xfrm: add outbound SA (spi=%08x): %w", p.OutboundSPI, err)
	}

	inPol, fwdPol, outPol := buildPolicies(p, localIP, remoteIP)

	if err := netlink.XfrmPolicyAdd(inPol); err != nil {
		_ = netlink.XfrmStateDel(inbound)
		_ = netlink.XfrmStateDel(outbound)
		unmarkInbound(p.InboundSPI)
		return fmt.Errorf("xfrm: add inbound policy: %w", err)
	}
	if err := netlink.XfrmPolicyAdd(fwdPol); err != nil {
		_ = netlink.XfrmPolicyDel(inPol)
		_ = netlink.XfrmStateDel(inbound)
		_ = netlink.XfrmStateDel(outbound)
		unmarkInbound(p.InboundSPI)
		return fmt.Errorf("xfrm: add uplink forward policy: %w", err)
	}
	if err := netlink.XfrmPolicyAdd(outPol); err != nil {
		_ = netlink.XfrmPolicyDel(fwdPol)
		_ = netlink.XfrmPolicyDel(inPol)
		_ = netlink.XfrmStateDel(inbound)
		_ = netlink.XfrmStateDel(outbound)
		unmarkInbound(p.InboundSPI)
		return fmt.Errorf("xfrm: add outbound policy: %w", err)
	}
	return nil
}

// ESPStats aggregates kernel ESP SA counters across all CHILD SAs this ePDG
// has installed (identified by Ifid == IfID). Read-only; used by the admin API.
type ESPStats struct {
	ActiveStates int // count of inbound+outbound XFRM states (2 per CHILD SA)
	BytesIn      uint64
	BytesOut     uint64
	PacketsIn    uint64
	PacketsOut   uint64
}

// inboundSPIs tracks which SPIs we installed as inbound, so Stats() can split
// kernel-reported counters by direction. We do our own bookkeeping rather than
// the kernel's XFRMA_SA_DIR attribute: that attribute's netlink number depends
// on the exact kernel build (some 6.x kernels don't have it, where it instead
// aliases XFRMA_SA_PCPU and gets rejected with -ERANGE on a u8/u32 size mismatch).
var (
	inboundSPIsMu sync.Mutex
	inboundSPIs   = make(map[uint32]struct{})
)

func markInbound(spi uint32) {
	inboundSPIsMu.Lock()
	inboundSPIs[spi] = struct{}{}
	inboundSPIsMu.Unlock()
}
func unmarkInbound(spi uint32) {
	inboundSPIsMu.Lock()
	delete(inboundSPIs, spi)
	inboundSPIsMu.Unlock()
}
func isInbound(spi uint32) bool {
	inboundSPIsMu.Lock()
	defer inboundSPIsMu.Unlock()
	_, ok := inboundSPIs[spi]
	return ok
}

// Stats reads all kernel ESP XFRM states tagged with our Ifid and aggregates
// their packet/byte counters, split by direction via our own inboundSPIs set.
func Stats() (ESPStats, error) {
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return ESPStats{}, fmt.Errorf("xfrm: list states: %w", err)
	}
	var out ESPStats
	for _, st := range states {
		if st.Proto != netlink.XFRM_PROTO_ESP || st.Ifid != int(IfID) {
			continue
		}
		out.ActiveStates++
		if isInbound(uint32(st.Spi)) {
			out.BytesIn += st.Statistics.Bytes
			out.PacketsIn += st.Statistics.Packets
		} else {
			out.BytesOut += st.Statistics.Bytes
			out.PacketsOut += st.Statistics.Packets
		}
	}
	return out, nil
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
	localIP, remoteIP, err := resolveXFRMIPs(p.LocalIP, p.RemoteIP)
	if err != nil {
		return err
	}

	inbound, outbound := buildSAs(p, localIP, remoteIP)

	var firstErr error
	save := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	inPol, fwdPol, outPol := buildPolicies(p, localIP, remoteIP)
	save(netlink.XfrmPolicyDel(outPol))
	save(netlink.XfrmPolicyDel(fwdPol))
	save(netlink.XfrmPolicyDel(inPol))
	save(netlink.XfrmStateDel(outbound))
	save(netlink.XfrmStateDel(inbound))
	unmarkInbound(p.InboundSPI)
	return firstErr
}

// ─────────────────────────────────────────────────────────────────────────────

// gcmICVLenBits is the ICV length, in bits, for the AES-GCM ICV size this
// ePDG negotiates (ENCR_AES_GCM_16 — RFC 5282, 16-octet/128-bit ICV). The
// kernel's xfrm_algo_aead.alg_icv_len field is in bits (linux/xfrm.h), not
// bytes, matching the existing IntTruncBits convention below.
const gcmICVLenBits = 128

// algoState builds the Auth+Crypt (CBC+HMAC) or Aead (GCM) XfrmStateAlgo
// fields for one direction's key material. p.IntAlgName == "" is the signal
// from childAlgNames that the negotiated cipher is AEAD: encKey already
// includes the 4-byte salt (encrAlg.KeyLen() in internal/ikev2/crypto.go
// accounts for it) and there is no separate integrity key.
func algoState(p ChildSAParams, encKey, intKey []byte) (auth, crypt, aead *netlink.XfrmStateAlgo) {
	if p.IntAlgName == "" {
		return nil, nil, &netlink.XfrmStateAlgo{
			Name:   p.EncAlgName,
			Key:    encKey,
			ICVLen: gcmICVLenBits,
		}
	}
	return &netlink.XfrmStateAlgo{
			Name:        p.IntAlgName,
			Key:         intKey,
			TruncateLen: p.IntTruncBits,
		}, &netlink.XfrmStateAlgo{
			Name: p.EncAlgName,
			Key:  encKey,
		}, nil
}

func buildSAs(p ChildSAParams, localIP, remoteIP net.IP) (*netlink.XfrmState, *netlink.XfrmState) {
	authIn, cryptIn, aeadIn := algoState(p, p.EncKeyIn, p.IntKeyIn)
	authOut, cryptOut, aeadOut := algoState(p, p.EncKeyOut, p.IntKeyOut)

	// Inbound SA: UE→ePDG (we decrypt with initiator keys).
	inbound := &netlink.XfrmState{
		Src:          remoteIP,
		Dst:          localIP,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          int(p.InboundSPI),
		ReplayWindow: 32,
		Ifid:         int(p.IfID),
		Auth:         authIn,
		Crypt:        cryptIn,
		Aead:         aeadIn,
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
		Src:          localIP,
		Dst:          remoteIP,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          int(p.OutboundSPI),
		ReplayWindow: 32,
		Ifid:         int(p.IfID),
		Auth:         authOut,
		Crypt:        cryptOut,
		Aead:         aeadOut,
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

func buildPolicies(p ChildSAParams, localIP, remoteIP net.IP) (*netlink.XfrmPolicy, *netlink.XfrmPolicy, *netlink.XfrmPolicy) {
	tmplIn := netlink.XfrmPolicyTmpl{
		Src:   remoteIP,
		Dst:   localIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
	}
	tmplOut := netlink.XfrmPolicyTmpl{
		Src:   localIP,
		Dst:   remoteIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
	}
	// Inbound policy: UE→ePDG traffic must arrive via ESP tunnel.
	inPol := &netlink.XfrmPolicy{
		Src:      p.RemoteTS,
		Dst:      p.LocalTS,
		Dir:      netlink.XFRM_DIR_IN,
		Priority: 100,
		Ifid:     int(p.IfID),
		Tmpls:    []netlink.XfrmPolicyTmpl{tmplIn},
	}
	// Uplink forward policy: verifies decrypted UE traffic was protected by the inbound SA.
	fwdPol := &netlink.XfrmPolicy{
		Src:      p.RemoteTS,
		Dst:      p.LocalTS,
		Dir:      netlink.XFRM_DIR_FWD,
		Priority: 100,
		Ifid:     int(p.IfID),
		Tmpls:    []netlink.XfrmPolicyTmpl{tmplIn},
	}
	// Outbound policy: any traffic to UE PAA (locally originated OR forwarded via kernel
	// routing, including XDP-decapped GTP-U inner IP) is encrypted via the outbound SA.
	outPol := &netlink.XfrmPolicy{
		Src:      p.LocalTS,
		Dst:      p.RemoteTS,
		Dir:      netlink.XFRM_DIR_OUT,
		Priority: 100,
		Ifid:     int(p.IfID),
		Tmpls:    []netlink.XfrmPolicyTmpl{tmplOut},
	}
	return inPol, fwdPol, outPol
}

// AddChildSAStates installs only the inbound and outbound XFRM SA states for a CHILD SA
// without touching policies. Used during CHILD SA rekey where policies already exist.
func AddChildSAStates(p ChildSAParams) error {
	localIP, remoteIP, err := resolveXFRMIPs(p.LocalIP, p.RemoteIP)
	if err != nil {
		return err
	}
	inbound, outbound := buildSAs(p, localIP, remoteIP)
	if err := netlink.XfrmStateAdd(inbound); err != nil {
		return fmt.Errorf("xfrm: add inbound SA (spi=%08x): %w", p.InboundSPI, err)
	}
	markInbound(p.InboundSPI)
	if err := netlink.XfrmStateAdd(outbound); err != nil {
		_ = netlink.XfrmStateDel(inbound)
		unmarkInbound(p.InboundSPI)
		return fmt.Errorf("xfrm: add outbound SA (spi=%08x): %w", p.OutboundSPI, err)
	}
	return nil
}

// RemoveChildSAStates removes only the XFRM SA states for a CHILD SA, without touching
// policies. Used when removing the old SA after a successful rekey, or aborting a rekey.
// Keys are not required — the kernel identifies SAs by SPI and endpoints only.
func RemoveChildSAStates(p ChildSAParams) error {
	localIP, remoteIP, err := resolveXFRMIPs(p.LocalIP, p.RemoteIP)
	if err != nil {
		return err
	}
	inbound := &netlink.XfrmState{
		Src:   remoteIP,
		Dst:   localIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   int(p.InboundSPI),
		Ifid:  int(p.IfID),
	}
	outbound := &netlink.XfrmState{
		Src:   localIP,
		Dst:   remoteIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   int(p.OutboundSPI),
		Ifid:  int(p.IfID),
	}
	var firstErr error
	save := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	save(netlink.XfrmStateDel(outbound))
	save(netlink.XfrmStateDel(inbound))
	unmarkInbound(p.InboundSPI)
	return firstErr
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
	network := "udp4"
	isV6 := remote.To4() == nil
	if isV6 {
		network = "udp6"
	}
	c, err := net.DialUDP(network, nil, &net.UDPAddr{IP: remote, Port: 1})
	if err != nil {
		return nil, fmt.Errorf("xfrm: local IP lookup for %v: %w", remote, err)
	}
	defer c.Close()
	localAddr := c.LocalAddr().(*net.UDPAddr).IP
	if isV6 {
		ip := localAddr.To16()
		if ip == nil {
			return nil, fmt.Errorf("xfrm: non-IPv6 local address for %v", remote)
		}
		return ip, nil
	}
	ip := localAddr.To4()
	if ip == nil {
		return nil, fmt.Errorf("xfrm: non-IPv4 local address for %v", remote)
	}
	return ip, nil
}

// resolveXFRMIPs normalises the endpoint IPs for use in XFRM structs.
// Both must be the same address family (both IPv4 or both IPv6).
//
// net.IP.To16() succeeds for IPv4 addresses too (they have a valid 16-byte
// mapped form), so family must be decided by To4() — To16() alone cannot
// distinguish a real IPv6 address from a mismatched v4/v6 pair.
func resolveXFRMIPs(local, remote net.IP) (net.IP, net.IP, error) {
	l4, r4 := local.To4(), remote.To4()
	if l4 != nil && r4 != nil {
		return l4, r4, nil
	}
	if l4 == nil && r4 == nil {
		if l6, r6 := local.To16(), remote.To16(); l6 != nil && r6 != nil {
			return l6, r6, nil
		}
	}
	return nil, nil, fmt.Errorf("xfrm: mismatched or unsupported address families (local=%v remote=%v)", local, remote)
}
