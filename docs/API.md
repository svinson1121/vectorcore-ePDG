# Administrative API Reference

VectorCore ePDG exposes a read-only HTTP API for operational visibility into
connected subscribers, IKE/IPsec state, S2b sessions, GTP-U bearers, and the
BPF dataplane. It is built with [Huma](https://github.com/danielgtaylor/huma)
and is disabled by default.

## Enabling the API

```yaml
api:
  enabled: true
  listen_address: "0.0.0.0"
  listen_port: 8080
```

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Start the admin API listener |
| `listen_address` | `0.0.0.0` | Bind address |
| `listen_port` | `8080` | Bind port |

The API is plain HTTP, not HTTPS, and has **no authentication** — it is a
read-only observer, but anyone who can reach `listen_address:listen_port`
can read subscriber IMSIs, UE IPs, and SPIs. Bind to `127.0.0.1` or a
management-only interface/VLAN unless you put a reverse proxy or firewall
ACL in front of it.

## Conventions

- Base path for all data endpoints: **`/api/v1`**
- All responses are JSON and include a `$schema` field (a self-describing
  JSON Schema URL) injected by Huma — safe to ignore.
- All endpoints are `GET`. There is nothing to authenticate and nothing
  mutates state: no disconnect, no session/bearer deletion, no
  reauthentication trigger.
- CORS is wide open (`Access-Control-Allow-Origin: *`, `GET, OPTIONS`) so the
  Swagger UI or a browser-based dashboard can call it from anywhere.
- Errors use Huma's standard problem-details shape:

  ```json
  {
    "$schema": "http://host:8080/schemas/ErrorModel.json",
    "title": "Not Found",
    "status": 404,
    "detail": "no client found for IMSI 000000000000000"
  }
  ```

## Interactive docs

| Path | Purpose |
|---|---|
| `/docs` | Swagger UI (note: **not** under `/api/v1` — it's at the server root) |
| `/openapi.json`, `/openapi.yaml` | OpenAPI 3.1 spec |
| `/openapi-3.0.json`, `/openapi-3.0.yaml` | OpenAPI 3.0 spec (for older tooling) |
| `/schemas/{name}.json` | JSON Schema for each response type, referenced by `$schema` |

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health` | Liveness check |
| GET | `/api/v1/status` | Version, uptime, active client count |
| GET | `/api/v1/clients` | All attached subscribers (summary) |
| GET | `/api/v1/clients/{imsi}` | One subscriber (summary) |
| GET | `/api/v1/clients/{imsi}/diag` | Full troubleshooting detail for one subscriber, including bearers |
| GET | `/api/v1/sessions` | All sessions, with IKE/CHILD SA and S2b detail |
| GET | `/api/v1/sessions/{imsi}` | One session, with IKE/CHILD SA and S2b detail |
| GET | `/api/v1/stats` | Aggregate counts: clients, IKE SAs, CHILD SAs, bearers |
| GET | `/api/v1/stats/bpf` | Raw BPF dataplane counters (XDP downlink, TC uplink, map occupancy) |
| GET | `/api/v1/stats/gtpu` | GTP-U packet counters derived from the BPF counters above |
| GET | `/api/v1/stats/ipsec` | ESP packet/byte counters from the kernel XFRM states |

`{imsi}` lookups match the first session for that IMSI regardless of APN.
If a subscriber has no active session, these return `404`.

---

### GET /health

```bash
curl -s http://localhost:8080/api/v1/health
```

```json
{"status": "ok"}
```

### GET /status

```bash
curl -s http://localhost:8080/api/v1/status
```

```json
{
  "version": "0.3.0d",
  "build_date": "2026-06-18T05:31:57Z",
  "uptime_seconds": 459,
  "active_clients": 1
}
```

### GET /clients

```bash
curl -s http://localhost:8080/api/v1/clients
```

```json
[
  {
    "imsi": "311435300070599",
    "ue_ip": "10.150.3.222",
    "outer_ip": "192.168.105.90:4500",
    "apn": "ims",
    "state": "Active"
  }
]
```

`state` is the session FSM state: `New`, `EAPAuthenticating`,
`EAPAuthenticated`, `S2bCreateSessionSent`, `S2bAccepted`, `GTPUInstalling`,
`DatapathInstalling`, `Active`, `CleaningUp`, `Failed`, or `Deleted`.
`outer_ip` is `ip:port` of the UE's outer (SWu) tunnel endpoint, not the inner
PAA.

### GET /clients/{imsi}

```bash
curl -s http://localhost:8080/api/v1/clients/311435300070599
```

Same shape as one entry of `/clients`. `404` if not found.

### GET /clients/{imsi}/diag

The primary troubleshooting endpoint — everything needed to debug one
subscriber in one call.

```bash
curl -s http://localhost:8080/api/v1/clients/311435300070599/diag
```

```json
{
  "imsi": "311435300070599",
  "ue_ip": "10.150.3.222",
  "outer_ip": "192.168.105.90:4500",
  "apn": "ims",
  "state": "Active",
  "ike_spi_i": "0x3aa9eff94e415370",
  "ike_spi_r": "0xf93a263d28f4cce0",
  "esp_spi_in": "0xce2f40eb",
  "esp_spi_out": "0xd4eee4",
  "pgw_control_ip": "10.90.250.92",
  "pgw_control_teid": 2148655105,
  "default_bearer": {
    "ebi": 5,
    "local_teid": 4271597964,
    "pgw_teid": 2150039553,
    "qci": 0,
    "uplink_packets": 0,
    "uplink_bytes": 0,
    "downlink_packets": 0,
    "downlink_bytes": 0
  },
  "dedicated_bearers": [
    {
      "ebi": 6,
      "local_teid": 3153404994,
      "pgw_teid": 2150047745,
      "qci": 2,
      "uplink_packets": 0,
      "uplink_bytes": 0,
      "downlink_packets": 0,
      "downlink_bytes": 0
    }
  ],
  "last_activity": "2026-06-18T05:39:53.684543758Z"
}
```

> **Known limitation:** `uplink_packets`, `uplink_bytes`, `downlink_packets`,
> and `downlink_bytes` on each bearer are currently always `0`. The
> `BearerCounters` struct they're read from (`internal/gtpu/dataplane.go:135`)
> is never incremented anywhere in the codebase — it's wired but the
> increment side was never implemented. For real traffic counters right now,
> use `/stats/bpf` or `/stats/gtpu`, which read from the BPF programs and do
> update live.

### GET /sessions, GET /sessions/{imsi}

Lower-level view than `/clients`, oriented around IKE/CHILD SA and S2b
identifiers rather than bearers.

```bash
curl -s http://localhost:8080/api/v1/sessions
```

```json
[
  {
    "imsi": "311435300070599",
    "ue_ip": "10.150.3.222",
    "outer_ip": "192.168.105.90:4500",
    "apn": "ims",
    "state": "Active",
    "ike_sa": {
      "spi_i": "0x3aa9eff94e415370",
      "spi_r": "0xf93a263d28f4cce0"
    },
    "child_sa": {
      "esp_spi_in": "0xce2f40eb",
      "esp_spi_out": "0xd4eee4"
    },
    "s2b": {
      "pgw": "10.90.250.92",
      "control_teid": 2148655105,
      "data_teid": 2150039553
    }
  }
]
```

`s2b` is omitted if the session has no S2b state yet (e.g. still in EAP).

### GET /stats

```bash
curl -s http://localhost:8080/api/v1/stats
```

```json
{
  "active_clients": 1,
  "active_ike_sas": 1,
  "active_child_sas": 1,
  "active_bearers": 4
}
```

### GET /stats/bpf

Raw, unaggregated counters straight from the BPF per-CPU stats maps —
the most useful endpoint for diagnosing where packets are being dropped.

```bash
curl -s http://localhost:8080/api/v1/stats/bpf
```

```json
{
  "xdp_downlink": {
    "seen": 4686,
    "cfg_miss": 0,
    "gtp_port": 3969,
    "gtp_tpdu": 3965,
    "teid_miss": 0,
    "teid_hit": 3965,
    "paa_mismatch": 0,
    "paa_match": 3965,
    "adjust_fail": 0,
    "decap_pass": 3965
  },
  "tc_uplink": {
    "seen": 668,
    "not_ipv4": 0,
    "ue_miss": 0,
    "adjust_fail": 0,
    "store_fail": 0,
    "encap_ok": 668,
    "redir_fail": 0
  },
  "map_occupancy": {
    "teid_map_entries": 4,
    "ue_session_map_entries": 1
  }
}
```

`xdp_downlink` counters (`internal/gtpu/bpf/xdp_gtpu_decap.c`), in pipeline
order — each stage is a subset of the one before it:

| Counter | Meaning |
|---|---|
| `seen` | Any IPv4/UDP packet reaching the XDP hook on the GTP-U interface — includes non-GTP-U UDP traffic on that NIC (e.g. S2b GTPv2-C control messages), so it's normal for this to be larger than `gtp_port` |
| `cfg_miss` | Destination IP didn't match the configured local GTP-U IP |
| `gtp_port` | Passed the UDP/2152 destination port check |
| `gtp_tpdu` | Confirmed G-PDU (T-PDU) message type |
| `teid_miss` | TEID not in `teid_map` → `XDP_PASS`'d up to the UDP control socket (echo, or an unrecognized bearer) |
| `teid_hit` | TEID found in `teid_map` |
| `paa_mismatch` | Inner destination IP didn't match the bearer's stored PAA → `XDP_DROP` |
| `paa_match` | Inner destination IP matched → proceeding to decap |
| `adjust_fail` | `bpf_xdp_adjust_head` (header strip) failed |
| `decap_pass` | Outer GTP-U/UDP/IP header stripped, `XDP_PASS`'d to the kernel for routing into XFRM — this is the true "downlink delivered" count |

`tc_uplink` counters (`internal/gtpu/bpf/tc_gtpu_encap.c`), on the
`vc-xfrm0` interface (decrypted UE traffic only — no control-plane noise):

| Counter | Meaning |
|---|---|
| `seen` | Any IPv4 packet entering the uplink TC hook |
| `not_ipv4` | Non-IPv4 packet, passed through untouched |
| `ue_miss` | Source IP not found in `ue_session_map` |
| `adjust_fail` | `bpf_skb_adjust_room` (making space for the GTP-U header) failed |
| `store_fail` | `bpf_skb_store_bytes` (writing the GTP-U/UDP/IP header) failed |
| `encap_ok` | Successfully encapsulated — the true "uplink delivered" count |
| `redir_fail` | `bpf_redirect_neigh` to the egress interface failed |

Because `vc-xfrm0` only ever carries this ePDG's own decrypted UE traffic,
`seen` and `encap_ok` will be equal whenever there's no actual packet loss
— that's expected, not a bug. If `seen` and `encap_ok` ever diverge, check
`ue_miss`/`adjust_fail`/`store_fail`/`redir_fail` to see where packets are
being lost.

### GET /stats/gtpu

A friendlier subset of `/stats/bpf`, plus tunnel/bearer counts.

```bash
curl -s http://localhost:8080/api/v1/stats/gtpu
```

```json
{
  "downlink_rx_packets": 4686,
  "downlink_tx_packets": 3965,
  "dropped_bad_teid": 0,
  "dropped_bad_peer": 0,
  "dropped_unsupported": 0,
  "dropped_malformed": 0,
  "uplink_rx_packets": 668,
  "uplink_tx_packets": 668,
  "active_tunnels": 1,
  "active_bearers": 4
}
```

| Field | Source |
|---|---|
| `downlink_rx_packets` | `xdp_downlink.seen` |
| `downlink_tx_packets` | `xdp_downlink.decap_pass` |
| `dropped_bad_teid` | `xdp_downlink.teid_miss` |
| `dropped_bad_peer` | Always `0` — no code path currently classifies a downlink drop as "wrong peer" |
| `dropped_unsupported` | GTP-U control-socket packets with an unhandled message type |
| `dropped_malformed` | GTP-U control-socket packets that failed to parse |
| `uplink_rx_packets` | `tc_uplink.seen` |
| `uplink_tx_packets` | `tc_uplink.encap_ok` |

### GET /stats/ipsec

```bash
curl -s http://localhost:8080/api/v1/stats/ipsec
```

```json
{
  "active_ike_sas": 1,
  "active_child_sas": 1,
  "esp_packets_in": 8,
  "esp_packets_out": 11,
  "esp_bytes_in": 3953,
  "esp_bytes_out": 7323
}
```

Read directly from the kernel's XFRM ESP SA counters (`ip -s xfrm state`),
filtered to this ePDG's XFRM interface and aggregated across all CHILD SAs.
Direction (`_in` vs `_out`) is tracked internally by SPI, not by the
kernel's `XFRMA_SA_DIR` attribute — that kernel attribute's wire format
isn't consistent across kernel builds and was found to break SA
installation entirely on some 6.x kernels (see `internal/xfrm/xfrm.go`).

## Architecture notes

- The API is strictly read-only: it has no access to any state-mutating
  method on the session manager, GTP-U manager, or XFRM/S2b/IKE clients —
  only `Snapshot()`, `FindByIMSIAPN()`, `SessionSnapshot()`, `Stats()`,
  `XDPCounters()`, `TCCounters()`, and `BPFMapOccupancy()`.
- It runs as its own `http.Server` (`internal/api/server.go`), started and
  stopped alongside the other components (IKEv2, S2b, SWm, GTP-U) from
  `cmd/epdg/main.go`.
