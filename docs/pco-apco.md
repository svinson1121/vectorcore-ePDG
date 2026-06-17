# PCO/APCO Handling

VectorCore ePDG supports optional Protocol Configuration Options (PCO) and Additional Protocol Configuration Options (APCO) on S2b GTPv2-C.

This is deliberately conservative:

- S2b Create Session may include PCO/APCO request containers only when configured.
- S2b Create Session Response PCO/APCO is parsed and stored when present.
- Unknown containers are preserved as opaque values and logged.
- PCO/APCO absence never fails attach.
- Opaque NAS-style PCO is not sent over SWu.

Known container IDs are from 3GPP TS 24.008 table 10.5.154 and are carried as GTPv2-C PCO/APCO IEs per 3GPP TS 29.274:

| Container | ID |
| --- | --- |
| P-CSCF IPv6 Address | `0x0001` |
| DNS Server IPv6 Address | `0x0003` |
| P-CSCF IPv4 Address | `0x000c` |
| DNS Server IPv4 Address | `0x000d` |

IPv4 Link MTU (`0x0010`) is intentionally not requested or decoded. 3GPP TS
24.302 §8.2.9.3 only maps PCO-sourced address/DNS/P-CSCF values onto IKEv2
CFG_REPLY attributes for non-3GPP access; the IKEv2 Configuration Payload
attribute registry (RFC 7296, plus RFC 7651 for P-CSCF) has no MTU attribute
at all, so there is no standards-compliant way to deliver it to the UE over
SWu. The PCO MTU container only has meaning for 3GPP access, where the UE's
NAS layer parses PCO directly.

## SWu Delivery

Decoded values are delivered to the UE via IKEv2 CFG_REPLY using the following configuration attributes:

| Value | IKEv2 CFG Attribute | Reference | Gated by |
| --- | --- | --- | --- |
| DNS IPv4 | `INTERNAL_IP4_DNS` (type 3) | RFC 7296 | `pco.request_dns_v4` |
| DNS IPv6 | `INTERNAL_IP6_DNS` (type 10) | RFC 7296 | `pco.request_dns_v6` |
| P-CSCF IPv4 | `P_CSCF_IP4_ADDRESS` (type 20) | RFC 7651 §3 | `pco.request_pcscf_v4` |
| P-CSCF IPv6 | `P_CSCF_IP6_ADDRESS` (type 21) | RFC 7651 §3 | `pco.request_pcscf_v6` |

P-CSCF IPv6 delivery is independent of the outer tunnel transport — the IKEv2 tunnel itself is IPv4, but RFC 7651 attribute type 21 carries the 16-byte IPv6 address inside the CFG_REPLY payload. 3GPP TS 24.302 §8.2.9.3 requires this.

Each value's `request_*` config flag controls both what's requested from the
PGW on S2b *and* what's forwarded to the UE on SWu. A PGW may volunteer a
value the ePDG didn't request — e.g. some PGWs always echo DNS/P-CSCF in the
APCO response regardless of what was asked for — and that value is decoded
and logged either way, but it is only handed to the UE if the matching
`request_*` flag is set. This keeps "what we asked the PGW for" and "what we
tell the UE" from silently diverging.
