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
| IPv4 Link MTU | `0x0010` |

## SWu Delivery

Decoded values are delivered to the UE via IKEv2 CFG_REPLY using the following configuration attributes:

| Value | IKEv2 CFG Attribute | Reference |
| --- | --- | --- |
| DNS IPv4 | `INTERNAL_IP4_DNS` (type 14) | RFC 7296 |
| P-CSCF IPv4 | `P_CSCF_IP4_ADDRESS` (type 20) | RFC 7651 §3 |
| P-CSCF IPv6 | `P_CSCF_IP6_ADDRESS` (type 21) | RFC 7651 §3 |
| MTU | — | Stored and logged; no SWu delivery mechanism |

P-CSCF IPv6 delivery is independent of the outer tunnel transport — the IKEv2 tunnel itself is IPv4, but RFC 7651 attribute type 21 carries the 16-byte IPv6 address inside the CFG_REPLY payload. 3GPP TS 24.302 §8.2.9.3 requires this.

DNS IPv6 is decoded from S2b PCO but not currently delivered over SWu (no `INTERNAL_IP6_DNS` attribute is sent); this is a known gap with negligible impact for IMS APNs which use IPv4 DNS.
