# VectorCore ePDG

VectorCore ePDG is an Evolved Packet Data Gateway written in Go. It implements the full VoWiFi control plane and userspace datapath as a single self-contained binary.
## What It Does

An ePDG provides untrusted non-3GPP access to the Evolved Packet Core (EPC), enabling devices to use Wi-Fi for VoWiFi voice and data services via a secured IPsec tunnel authenticated with the SIM card (EAP-AKA).

```
Phone / UE
    |
    |  SWu — IKEv2 + EAP-AKA + IPsec/ESP
    |
VectorCore ePDG
    |                    |                     |
    | SWm Diameter       | S2b GTPv2-C         | Linux XFRM
    | EAP-AKA proxy      | PDN session/bearer  | kernel IPsec
    |                    |                     |
   AAA / HSS            PGW                   GTP-U dataplane
```

![Non-3GPP Architecture](images/non-3gpp.png)

## Features

- **Native Go IKEv2** — Full RFC 7296 state machine: IKE_SA_INIT, IKE_AUTH, CHILD SA, DH key exchange, NAT-T, rekey, reauthentication, DPD
- **EAP-AKA authentication** — SIM-based auth proxied over SWm Diameter to the HSS/AAA (3GPP TS 29.273); no local credentials required
- **Kernel IPsec via XFRM** — Inbound/outbound XFRM SAs and policies installed directly in the Linux kernel; ESP-in-UDP for NAT traversal
- **MOBIKE (RFC 4555)** — IKEv2 Mobility: negotiated in IKE_AUTH, COOKIE2 return-routability challenge/verify, XFRM endpoint migration when the UE changes IP address (e.g. roaming between Wi-Fi networks); IPv4 only
- **S2b GTPv2-C** — Creates and manages PDN sessions with the PGW (3GPP TS 29.274); Cisco StarOS interop validated
- **Userspace GTP-U dataplane** — UDP/2152 bearer encapsulation via Linux TUN interface and nfqueue uplink capture
- **Dedicated bearer support** — PGW-initiated Create/Delete/Update Bearer procedures with TFT uplink packet selection
- **PCO/APCO** — DNS, P-CSCF IPv4 and IPv6, and MTU decoded from S2b and delivered to the UE via IKEv2 CFG_REPLY (RFC 7651 attribute types 20 and 21)
- **Bidirectional VoWiFi ↔ VoLTE handover** — VoWiFi→VoLTE: detects PGW Cause=10 (Access changed from Non-3GPP to 3GPP) on Delete Bearer and sends SWm STR with Termination-Cause=8 (DIAMETER_USER_MOVED) for clean AAA handover. VoLTE→VoWiFi: detects non-zero INTERNAL_IP4_ADDRESS in IKE_AUTH CFG_REQUEST and sets the Handover Indication (HI) bit in the S2b Create Session Indication IE so the PGW preserves the existing PDN connection and assigns the same IP address
- **Lifecycle management** — IKE SA delete, CHILD SA delete, DPD, PGW-initiated delete; full teardown of XFRM + GTP-U + S2b state
- **Reauthentication** — Configurable policy: preserve existing S2b session or detach and re-attach
- **3GPP compliant** — Implements TS 23.402, TS 24.302, TS 29.273, TS 29.274, TS 33.402

## Supported Algorithms

### IKE SA

| Transform | Supported |
|---|---|
| Encryption | AES-CBC-128, AES-CBC-256 |
| Integrity | HMAC-SHA1-96, HMAC-SHA2-256-128, HMAC-SHA2-512-256 |
| PRF | PRF-HMAC-SHA1, PRF-HMAC-SHA256, PRF-HMAC-SHA512 |
| Diffie-Hellman | Group 14 (2048-bit MODP), Group 15 (3072-bit MODP) |

Proposals are matched in preference order. Preferred: AES-CBC-256 + HMAC-SHA2-256-128 + PRF-SHA-256 + DH14.

### ESP (CHILD SA)

| Transform | Supported |
|---|---|
| Encryption | AES-CBC-128, AES-CBC-256 |
| Integrity | HMAC-SHA1-96, HMAC-SHA2-256-128, HMAC-SHA2-512-256 |
| PFS | Group 14 or Group 15 (preferred); no-PFS accepted as fallback |

Preferred: AES-CBC-256 + HMAC-SHA2-256-128 + PFS DH14.

## Requirements

### Runtime

- Linux kernel 5.4+ with XFRM, nfqueue (`CONFIG_NETFILTER_NETLINK_QUEUE`), and TUN/TAP support
- `iptables` (for automatic nfqueue rule install; can be disabled)
- Root privileges — required for XFRM netlink, raw sockets, and TUN device creation
- IP forwarding enabled: `sysctl net.ipv4.ip_forward=1`

### Build

- Go 1.22+

## Build

```bash
make build
```

Output binary: `bin/epdg`

Build-time variables:

| Variable | Default | Description |
|---|---|---|
| `VERSION` | `0.1.1d` | Version string injected via ldflags |
| `GOCACHE` | `/tmp/vectorcore-epdg-gocache` | Go build cache path |
| `GOMODCACHE` | `/tmp/vectorcore-epdg-gomodcache` | Go module cache path |

Override at build time:

```bash
make build VERSION=1.2.0
```

### Other targets

```bash
make tidy     # go mod tidy
make test     # run all tests
make clean    # remove bin/
make install  # build and install to /opt/vectorcore/epdg/bin/epdg
```

### Install

```bash
make install
```

Creates:
- `/opt/vectorcore/epdg/bin/epdg` — binary
- `/etc/vectorcore/epdg/` — config directory
- `/var/log/vectorcore/epdg/` — log directory

## Usage

```
epdg [flags]

  -c <path>    Config file (default: /opt/vectorcore/etc/epdg.yaml)
  -d           Enable debug console logging
  -validate    Load and validate config, then exit
  -v           Print version and exit
```

On startup the binary prints `Starting VectorCore ePDG <version>` to stdout, then logs to the configured log file.

## Certificates

The ePDG presents an X.509 certificate to the UE during IKE_AUTH. The UE uses this certificate to authenticate the ePDG before completing the EAP-AKA exchange. `cert_file` is required — the binary will not start without it.

### Using an existing PKI

If your operator PKI has already issued an ePDG certificate, point the config at those files:

```yaml
ikev2:
  cert_file: /etc/vectorcore/epdg/epdg.crt
  key_file:  /etc/vectorcore/epdg/epdg.key
  ca_file:   /etc/vectorcore/epdg/ca.crt
```

The certificate's Subject or Subject Alternative Name should match the ePDG FQDN configured in `epdg.name` (e.g. `epdg.epc.mnc001.mcc001.3gppnetwork.org`).

### Generating a self-signed CA and ePDG certificate

For lab or testing environments you can generate your own CA and issue an ePDG certificate from it.

**1. Generate the CA key and self-signed CA certificate**

```bash
openssl genrsa -out ca.key 4096

openssl req -x509 -new -nodes \
  -key ca.key \
  -sha256 -days 3650 \
  -subj "/CN=VectorCore ePDG Lab CA" \
  -out ca.crt
```

**2. Generate the ePDG key and certificate signing request**

Replace `epdg.epc.mnc001.mcc001.3gppnetwork.org` with your actual ePDG FQDN.

```bash
openssl genrsa -out epdg.key 2048

openssl req -new \
  -key epdg.key \
  -subj "/CN=epdg.epc.mnc001.mcc001.3gppnetwork.org" \
  -out epdg.csr
```

**3. Sign the ePDG certificate with the CA**

```bash
openssl x509 -req \
  -in epdg.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days 825 \
  -extfile <(printf "subjectAltName=DNS:epdg.epc.mnc001.mcc001.3gppnetwork.org") \
  -out epdg.crt
```

**4. Install and configure**

```bash
install -m 0640 ca.crt epdg.crt epdg.key /etc/vectorcore/epdg/
```

```yaml
ikev2:
  cert_file: /etc/vectorcore/epdg/epdg.crt
  key_file:  /etc/vectorcore/epdg/epdg.key
  ca_file:   /etc/vectorcore/epdg/ca.crt
```

The CA certificate (`ca.crt`) must be provisioned on the UE or in the device's trusted root store for the UE to accept the ePDG's identity. In production this is typically handled by the operator PKI and device management.

### Verifying a certificate

```bash
# Confirm the cert and key match
openssl x509 -noout -modulus -in epdg.crt | md5sum
openssl rsa  -noout -modulus -in epdg.key | md5sum

# Verify the cert is signed by the CA
openssl verify -CAfile ca.crt epdg.crt

# Inspect the certificate
openssl x509 -noout -text -in epdg.crt
```

## Configuration

The config file uses a simple `section: / key: value` format. An annotated example is at `config/epdg.yaml`.

### `epdg` — Identity

| Key | Required | Description |
|---|---|---|
| `name` | yes | ePDG FQDN (e.g. `epdg.epc.mnc001.mcc001.3gppnetwork.org`) |
| `realm` | yes | Diameter / IKE realm |
| `mcc` | yes | Mobile Country Code (3 digits) |
| `mnc` | yes | Mobile Network Code (2–3 digits) |
| `mnc_length` | yes | `2` or `3` |

### `logging` — Log output

| Key | Default | Description |
|---|---|---|
| `level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `file` | `/var/log/vectorcore/epdg/epdg.log` | Log file path |

### `ikev2` — IKEv2 / SWu interface

| Key | Required | Description |
|---|---|---|
| `listen_addr` | | IP to bind IKEv2 on ports 500 and 4500. Default `0.0.0.0` |
| `listen_ifname` | | Optional: restrict to a specific network interface by name |
| `cert_file` | **yes** | Path to the ePDG X.509 certificate (PEM). Required — startup fails without it |
| `key_file` | | Path to the ePDG private key (PEM) |
| `ca_file` | | Path to the CA certificate for trust validation (PEM) |

### `swm` — SWm Diameter (EAP-AKA proxy)

| Key | Required | Description |
|---|---|---|
| `local_addr` | yes | Local IP for the Diameter transport |
| `peer_addr` | yes | Diameter peer IP (AAA or DRA) |
| `peer_port` | yes | Diameter peer port (typically `3868`) |
| `proto` | | Transport: `tcp` or `sctp` (default `sctp`) |
| `origin_host` | yes | Diameter Origin-Host (ePDG FQDN) |
| `origin_realm` | yes | Diameter Origin-Realm |
| `destination_host` | | Diameter Destination-Host. Omit to route by realm via DRA |
| `destination_realm` | yes | Diameter Destination-Realm |
| `watchdog_interval_seconds` | | DWR send interval (default `30`) |
| `watchdog_timeout_seconds` | | DWR response timeout (default `10`) |

### `gtp` — GTPv2-C control plane and GTP-U dataplane

| Key | Required | Description |
|---|---|---|
| `local_gtpc` | yes | Local IP for GTPv2-C (S2b control plane) |
| `local_gtpu` (or `local_addr`) | yes | Local IP for GTP-U (user plane) |
| `local_port` | | GTP-U listen port (default `2152`) |
| `pgw_gtpc` | yes | PGW GTPv2-C IP |
| `pgw_gtpu` | yes | PGW GTP-U IP |
| `tun_name` | | TUN interface name (default `vc-gtpu0`) |
| `mtu` | | TUN interface MTU, 576–9000 (default `1400`) |
| `validate_outer_peer` | | Validate GTP-U outer peer IP against PGW (default `true`) |
| `strict_peer_check` | | Drop packets from unexpected peers (default `true`) |
| `max_sequence` | | GTPv2-C sequence cap. Set `8388607` for Cisco StarOS (StarOS defect: rejects sequences with bit 23 set) |
| `cleanup_stale_routes_on_start` | | Remove stale PAA host routes on startup (default `false`) |
| `uplink_capture_mode` | | Uplink capture method: `nfqueue` (default `nfqueue`) |
| `nfqueue_queue_num` | | nfqueue queue number (default `4200`) |
| `nfqueue_install_rules` | | Auto-install iptables uplink rules (default `true`) |
| `nfqueue_firewall_backend` | | Firewall backend: `iptables` (default `iptables`) |
| `nfqueue_chain_name` | | iptables chain (default `VECTORCORE-EPDG-UPLINK`) |
| `nfqueue_ingress_ifname` | | Optional: scope nfqueue rule to a specific ingress interface |
| `nfqueue_queue_bypass` | | Allow bypass on nfqueue overload (default `false`) |
| `nfqueue_fail_closed` | | Drop uplink packets if nfqueue is unavailable (default `true`) |
| `nfqueue_cleanup_stale_rules_on_start` | | Remove stale nfqueue rules on startup (default `false`) |

### `dedicated_bearers` — Dedicated bearer support

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Handle PGW-initiated Create/Delete/Update Bearer requests |
| `tft_uplink_selection` | `false` | Apply TFT packet filters for uplink bearer selection |

### `apn` — APN defaults

| Key | Required | Description |
|---|---|---|
| `default` | yes | APN to use when none can be derived from the IKE IDr payload |

### `pco` — Protocol Configuration Options

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable PCO/APCO processing |
| `request_dns` | `true` | Request DNS server addresses from PGW |
| `request_pcscf` | `true` | Request P-CSCF addresses from PGW |
| `request_mtu` | `false` | Request link MTU from PGW |
| `include_apco` | `true` | Include APCO container in S2b Create Session Request |
| `strict_decode` | `false` | Fail attach on PCO decode errors |

### `datapath` — Routing and forwarding

| Key | Default | Description |
|---|---|---|
| `enable_ip_forwarding_check` | `true` | Warn at startup if IP forwarding is disabled |
| `install_routes` | `false` | Install per-PAA host routes via the TUN interface |
| `require_paa_ipsec_alignment` | `true` | Reject sessions where the PGW PAA does not match the CHILD SA traffic selector |
| `uplink_policy_routing_enabled` | `false` | Enable per-session uplink policy routing |
| `uplink_table_id` | `4200` | Policy routing table ID |
| `uplink_table_name` | `vectorcore-epdg-gtp` | Policy routing table name (`/etc/iproute2/rt_tables`) |
| `uplink_priority_base` | `10000` | Base priority for per-session `ip rule` entries |

### `reauth` — Reauthentication policy

| Key | Default | Description |
|---|---|---|
| `mode` | `preserve_existing_s2b` | `preserve_existing_s2b`: reuse the existing PGW session. `detach_new_attach`: delete and recreate the PDN session |
| `allow_fallback_new_attach` | `false` | Fall back to new attach if no existing session is found during reauth |
| `on_failure` | `keep_existing_until_ipsec_delete` | `keep_existing_until_ipsec_delete`: retain the existing PGW session until the old IPsec tunnel tears down. `delete_existing_session`: delete immediately on reauth failure |

### `shutdown` — Graceful shutdown

| Key | Default | Description |
|---|---|---|
| `timeout_seconds` | `5` | Per-component shutdown timeout in seconds |

## Planned Features

The following capabilities are planned for future releases. See `docs/` for detailed implementation plans where available.

| Feature | Notes | Plan |
|---|---|---|
| **IPv6 outer tunnel (SWu)** | IKEv2 and IPsec over IPv6 transport — required for UEs on IPv6-only Wi-Fi networks (3GPP TS 24.302 §7.2.2)

## Protocol Standards

| Interface / Feature | Standard |
|---|---|
| SWu (UE ↔ ePDG) | RFC 7296 (IKEv2), RFC 4187 (EAP-AKA), RFC 4303 (ESP), RFC 3948 (NAT-T) |
| MOBIKE | RFC 4555 — IKEv2 Mobility and Multihoming |
| SWm (ePDG ↔ AAA) | 3GPP TS 29.273 — Diameter EAP-AKA proxy |
| S2b (ePDG ↔ PGW) | 3GPP TS 29.274 — GTPv2-C |
| GTP-U dataplane | 3GPP TS 29.281 |
| Handover | 3GPP TS 23.402 §8.6 (VoWiFi↔VoLTE), TS 24.302 §8.2.3 (VoLTE→VoWiFi CFG_REQUEST) |


## Architecture

```
cmd/epdg/main.go          — Entry point, component wiring, PGW event handlers

internal/ikev2            — IKEv2 state machine, packet engine, CHILD SA negotiation
internal/xfrm             — Linux XFRM netlink: kernel IPsec SA and policy
internal/swm              — SWm Diameter client, EAP-AKA challenge/response proxy
internal/s2b              — S2b GTPv2-C client, PDN session and bearer lifecycle
internal/gtpu             — Userspace GTP-U: UDP/2152, TUN interface, nfqueue uplink
internal/session          — Session FSM and cross-component cleanup coordination
internal/config           — Config file loader and validator
internal/pco              — PCO/APCO encode/decode (3GPP TS 24.008)
internal/logging          — Structured logging (slog, file + console)
```
