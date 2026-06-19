/* XDP program: GTP-U downlink decapsulation.
 *
 * Attaches to the physical NIC receiving UDP/2152 from the PGW.
 * For each G-PDU with a known TEID:
 *   1. Look up TEID in teid_map; verify inner dst IP matches stored PAA.
 *   2. Strip outer Eth+IP+UDP+GTP-U headers via remove_gtp_header(), which
 *      rewrites the Ethernet header for the inner IP version and calls
 *      bpf_xdp_adjust_head to discard the outer headers.
 *   3. Return XDP_PASS — the inner IP packet re-enters the kernel stack,
 *      Linux routing forwards it, and the XFRM OUT policy (dst=PAA/32)
 *      encrypts it over the existing IPsec tunnel to the UE.
 *
 * Echo Request/Response are XDP_PASS'd unchanged for the Go control socket.
 * Unknown TEID T-PDUs are XDP_PASS'd unchanged and dropped by the control
 * socket path as unsupported dataplane misses.
 *
 * dl_stats PERCPU_ARRAY layout (enum xdp_stat below) lets Go read aggregate
 * counters via bpf_map_lookup_elem without touching the hot path.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/types.h>

#include "headers/gtpu.h"
#include "headers/packet_context.h"
#include "headers/parsers.h"
#include "headers/gtp_utils.h"


/* ── Stats counters ───────────────────────────────────────────────────────── */

enum xdp_stat {
    STAT_SEEN          = 0,  /* any packet entered XDP (ETH OK, IPv4, UDP) */
    STAT_CFG_MISS      = 1,  /* config_map miss or dst IP != local GTP-U IP */
    STAT_GTP_PORT      = 2,  /* reached UDP/2152 GTP-U port check */
    STAT_GTP_TPDU      = 3,  /* G-PDU message type confirmed */
    STAT_TEID_MISS     = 4,  /* TEID not in teid_map -> XDP_PASS to control socket */
    STAT_TEID_HIT      = 5,  /* TEID found in teid_map */
    STAT_PAA_MISMATCH  = 6,  /* inner dst != stored PAA → XDP_DROP */
    STAT_PAA_MATCH     = 7,  /* inner dst == PAA, proceeding to decap */
    STAT_ADJUST_FAIL   = 8,  /* remove_gtp_header or bpf_xdp_adjust_head failed */
    STAT_DECAP_PASS    = 9,  /* XDP_PASS after outer header strip → kernel routes inner IP */
    STAT_MAX           = 10,
};

/* dl_stats: per-CPU array so increments are lock-free.
 * Go sums all CPUs to get totals. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 10); /* == STAT_MAX */
} dl_stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&dl_stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

/* ── Maps ─────────────────────────────────────────────────────────────────── */

/* config_map[0] = local GTP-U IP (stored by Go as LittleEndian uint32). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,  __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} config_map SEC(".maps");

/* teid_map: TEID (host byte order) → UE PAA (network byte order). */
struct teid_entry {
    __u8 paa[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);
    __type(value, struct teid_entry);
    __uint(max_entries, 4096);
} teid_map SEC(".maps");

/* dl_bearer_counters: TEID (host byte order) → packet/byte counters for
 * traffic decapsulated to that bearer. Entries are created lazily on first
 * packet (see gtpu_decap_func) and deleted from Go when the bearer/TEID is
 * torn down. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);
    __type(value, struct bearer_counters);
    __uint(max_entries, 4096);
} dl_bearer_counters SEC(".maps");


/* ── Program ──────────────────────────────────────────────────────────────── */

SEC("xdp/gtpu_decap")
int gtpu_decap_func(struct xdp_md *ctx) {
    struct packet_context pctx = {
        .data     = (char *)(long)ctx->data,
        .data_end = (const char *)(long)ctx->data_end,
        .data_off = 0,
        .xdp_ctx  = ctx,
    };

    /* ── L2: Ethernet + IPv4 ────────────────────────────────────────────── */
    if (parse_ethernet(&pctx) != ETH_P_IP)
        return XDP_PASS;

    /* ── L3: IPv4 UDP ───────────────────────────────────────────────────── */
    if (parse_ip4(&pctx) != IPPROTO_UDP)
        return XDP_PASS;

    stat_inc(STAT_SEEN);

    /* ── Filter: local GTP-U IP only ───────────────────────────────────── */
    __u32 cfg_key = 0;
    __u32 *local_ip = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!local_ip || pctx.ip4->daddr != *local_ip) {
        stat_inc(STAT_CFG_MISS);
        return XDP_PASS;
    }

    /* ── L4: UDP/2152 ───────────────────────────────────────────────────── */
    if (parse_udp(&pctx) != GTP_UDP_PORT)
        return XDP_PASS;

    stat_inc(STAT_GTP_PORT);

    /* ── GTP-U message type ─────────────────────────────────────────────── */
    __u32 msg_type = parse_gtp(&pctx);
    if (msg_type == GTPU_ECHO_REQUEST || msg_type == GTPU_ECHO_RESPONSE)
        return XDP_PASS;
    if (msg_type != GTPU_G_PDU)
        return XDP_PASS;

    stat_inc(STAT_GTP_TPDU);

    /* ── TEID lookup ────────────────────────────────────────────────────── */
    __u32 teid = bpf_ntohl(pctx.gtp->teid);
    struct teid_entry *entry = bpf_map_lookup_elem(&teid_map, &teid);
    if (!entry) {
        stat_inc(STAT_TEID_MISS);
        return XDP_PASS; /* unknown TEID -> control socket drop */
    }
    stat_inc(STAT_TEID_HIT);

    /* ── Inner IP sanity: dst must match stored PAA ─────────────────────── */
    struct iphdr *inner = (struct iphdr *)pctx.data;
    if ((const char *)(inner + 1) > pctx.data_end)
        return XDP_PASS;

    __be32 paa_be;
    __builtin_memcpy(&paa_be, entry->paa, 4);
    if (inner->daddr != paa_be) {
        stat_inc(STAT_PAA_MISMATCH);
        return XDP_DROP;
    }
    stat_inc(STAT_PAA_MATCH);

    __u16 inner_len = bpf_ntohs(inner->tot_len);

    /* ── Strip outer Eth+IP+UDP+GTP-U, rewrite Ethernet header for inner IP.
     * remove_gtp_header copies the Ethernet header just before the inner IP,
     * then calls bpf_xdp_adjust_head to discard the outer headers.
     * The resulting packet re-enters the kernel stack as a plain inner IP
     * frame; Linux routing picks it up and the XFRM OUT policy encrypts it
     * to the UE over the existing IPsec tunnel. ─────────────────────────── */
    if (remove_gtp_header(&pctx) != 0) {
        stat_inc(STAT_ADJUST_FAIL);
        return XDP_PASS;
    }

    stat_inc(STAT_DECAP_PASS);

    struct bearer_counters *bc = bpf_map_lookup_elem(&dl_bearer_counters, &teid);
    if (!bc) {
        struct bearer_counters zero = {};
        bpf_map_update_elem(&dl_bearer_counters, &teid, &zero, BPF_NOEXIST);
        bc = bpf_map_lookup_elem(&dl_bearer_counters, &teid);
    }
    if (bc) {
        __sync_fetch_and_add(&bc->packets, 1);
        __sync_fetch_and_add(&bc->bytes, inner_len);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
