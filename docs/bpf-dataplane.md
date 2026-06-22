# BPF Dataplane

VectorCore ePDG uses a BPF-only GTP-U dataplane. The old queue-based uplink
path and Go userspace T-PDU forwarding path have been removed.

## Packet Paths

```text
Downlink (PGW -> UE):
  PGW UDP/2152 -> PGW-facing NIC -> XDP GTP-U decap -> TUN/XFRM -> UE IPsec

Uplink (UE -> PGW):
  UE IPsec -> XFRM interface -> TC GTP-U encap -> PGW-facing NIC -> PGW UDP/2152
```

The UDP/2152 socket remains for GTP-U control traffic such as Echo
Request/Response. User-plane T-PDU packets are handled by the XDP and TC BPF
programs.

## Configuration

The BPF dataplane is required.

```yaml
bpf:
  xdp_attach_mode: generic
  xdp_interface: ens18
  map_max_entries: 4096
```

| Key | Description |
|-----|-------------|
| `xdp_attach_mode` | `generic`, `native`, or `offload` |
| `xdp_interface` | PGW-facing NIC that receives GTP-U and is used for uplink redirect |
| `map_max_entries` | Maximum BPF map entries for sessions and bearers |

The XFRM virtual interface name (`vc-xfrm0`) and its `if_id` (`1`) are fixed
constants (`internal/xfrm/xfrm.go`), not configurable — they're not exposed
under `bpf:` in `config/epdg.yaml`.

## BPF Programs

| Program | File | Role |
|---------|------|------|
| XDP decap | `internal/gtpu/bpf/xdp_gtpu_decap.c` | Parses outer IPv4/UDP/GTP-U, looks up TEID state, strips the GTP-U header, and redirects inner packets toward the UE path |
| TC encap | `internal/gtpu/bpf/tc_gtpu_encap.c` | Looks up PAA/bearer state, prepends outer IPv4/UDP/GTP-U headers, resolves routing, and redirects packets to the PGW-facing NIC |

Go loaders and map synchronization live in:

- `internal/gtpu/bpf_loader.go`
- `internal/gtpu/tc_loader.go`
- `internal/gtpu/dataplane.go`

## Build

`make build` runs `make generate`, which compiles and embeds the BPF bytecode
with `bpf2go`.

Build hosts need:

- Go 1.22+
- `clang` and `llvm`
- `libbpf-dev`
- Linux headers compatible with the deployment kernel family

## Runtime Requirements

- Linux kernel 5.15+
- BPF JIT enabled
- `/sys/fs/bpf` mounted
- Root privileges for XFRM netlink, TUN creation, BPF program loading, and TC/XDP attachment
- `iproute2` with TC support

## Session Map Sync

When a session or bearer is installed, Go writes the relevant TEID, PAA, PGW
GTP-U address, local GTP-U address, and TFT-derived rule state into BPF maps.
Delete and update bearer procedures remove or refresh those entries during
normal session cleanup.

Active session state requires BPF map synchronization to succeed together with
EAP-AKA success, S2b session creation, XFRM SA/policy installation, and GTP-U
bearer installation.
