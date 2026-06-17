/* Copyright 2023-2025 Edgecom LLC. Adapted from eUPF (github.com/edgecomllc/eupf), Apache 2.0
 * Simplified: no per-CPU stats map.
 * Used in Phase 3 (uplink TC encap). Not required for Phase 2 XDP decap,
 * which uses bpf_redirect(tun_ifindex) directly from the teid_map entry. */
#pragma once

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <sys/socket.h>

/* Perform a FIB lookup and redirect the packet to the resolved nexthop.
 * Fills in src/dst MAC from the FIB result.
 * Returns an XDP action (XDP_REDIRECT, XDP_TX, XDP_DROP, or XDP_PASS). */
static __always_inline enum xdp_action route_ipv4(struct xdp_md *ctx,
                                                    struct ethhdr *eth,
                                                    const struct iphdr *ip4) {
    struct bpf_fib_lookup fib = {};
    fib.family      = AF_INET;
    fib.tos         = ip4->tos;
    fib.l4_protocol = ip4->protocol;
    fib.tot_len     = bpf_ntohs(ip4->tot_len);
    fib.ipv4_src    = ip4->saddr;
    fib.ipv4_dst    = ip4->daddr;
    fib.ifindex     = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
        __builtin_memcpy(eth->h_dest,   fib.dmac, ETH_ALEN);
        if (fib.ifindex == ctx->ingress_ifindex)
            return XDP_TX;
        return bpf_redirect(fib.ifindex, 0);
    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}
