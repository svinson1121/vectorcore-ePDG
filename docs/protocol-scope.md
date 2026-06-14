# VectorCore ePDG Protocol Scope

VectorCore ePDG is a production-grade ePDG implemented as a single self-contained Go binary. It provides untrusted non-3GPP access to the Evolved Packet Core for VoWiFi using a native Go IKEv2 engine.

## Interfaces

| Interface | Role | Standard |
|-----------|------|----------|
| SWu | UE ↔ ePDG IPsec tunnel | RFC 7296 (IKEv2), RFC 4187 (EAP-AKA), RFC 4303 (ESP), RFC 3948 (NAT-T) |
| SWm | ePDG ↔ AAA EAP-AKA proxy | 3GPP TS 29.273 |
| S2b | ePDG ↔ PGW PDN session control | 3GPP TS 29.274 |
| GTP-U | ePDG ↔ PGW user-plane | 3GPP TS 29.281 |

## Capabilities

- Native Go IKEv2 engine: IKE_SA_INIT, IKE_AUTH, CHILD SA, DH key exchange, NAT-T, rekey, reauthentication, DPD
- EAP-AKA authentication proxied over SWm Diameter to AAA/HSS
- Linux XFRM netlink for kernel IPsec SA and policy installation; ESP-in-UDP for NAT traversal
- **MOBIKE (RFC 4555)** — IKEv2 Mobility: USE_MOBIKE negotiation in IKE_AUTH, COOKIE2 return-routability challenge/verify, XFRM endpoint migration when the UE changes IP address; IPv4 only
- S2b GTPv2-C: Create/Delete Session, Create/Delete/Update Bearer
- Userspace GTP-U dataplane over UDP/2152 with Linux TUN interface and nfqueue uplink capture
- Dedicated bearer support with TFT uplink packet selection
- PCO/APCO: DNS, P-CSCF IPv4 (RFC 7651 attr 20) and P-CSCF IPv6 (RFC 7651 attr 21), and MTU decoded from S2b and delivered to the UE via IKEv2 CFG_REPLY
- Full session lifecycle: IKE SA delete, CHILD SA delete, DPD, PGW-initiated delete, reauthentication
- **Bidirectional VoWiFi ↔ VoLTE handover** (see `docs/handover.md`):
  - VoWiFi→VoLTE: detects PGW Cause=10 on Delete Bearer; sends SWm STR with Termination-Cause=8 (DIAMETER_USER_MOVED)
  - VoLTE→VoWiFi: detects non-zero INTERNAL_IP4_ADDRESS in IKE_AUTH CFG_REQUEST; sets Handover Indication (HI) bit in S2b Create Session Indication IE for PDN session continuity

## Known Limitations

- Outer tunnel (SWu IPsec, XFRM, GTP-U) is IPv4 only; IPv6 transport not supported
- P-CSCF IPv6 address delivery to the UE over SWu is supported (RFC 7651 attr 21); this is independent of the outer tunnel transport
- MOBIKE: NAT re-detection on path migration not implemented; `natT` state assumed stable across address changes
- MOBIKE: multihoming (simultaneous UE addresses) not supported
- MOBIKE: in-flight migrations are lost on ePDG restart; UE reconnects normally
