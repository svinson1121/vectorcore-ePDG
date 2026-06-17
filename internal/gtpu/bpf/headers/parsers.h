/* Copyright 2023-2025 Edgecom LLC. Adapted from eUPF (github.com/edgecomllc/eupf), Apache 2.0
 * Simplified: removed IPv6/TCP parsers and PFCP-specific context helpers. */
#pragma once

#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include "packet_context.h"

#define ETH_P_IP_BE  0x0008
#define ETH_P_IPV6_BE 0xDD86

static __always_inline int parse_ethernet(struct packet_context *ctx) {
    struct ethhdr *eth = (struct ethhdr *)ctx->data;
    if ((const char *)(eth + 1) > ctx->data_end)
        return -1;
    ctx->data    += sizeof(*eth);
    ctx->data_off += sizeof(*eth);
    ctx->eth = eth;
    return bpf_ntohs(eth->h_proto);
}

static __always_inline int parse_ip4(struct packet_context *ctx) {
    struct iphdr *ip4 = (struct iphdr *)ctx->data;
    if ((const char *)(ip4 + 1) > ctx->data_end)
        return -1;
    __u32 ihl_bytes = ip4->ihl * 4;
    ctx->data    += ihl_bytes;
    ctx->data_off += ihl_bytes;
    ctx->ip4 = ip4;
    return ip4->protocol;
}

static __always_inline int parse_udp(struct packet_context *ctx) {
    struct udphdr *udp = (struct udphdr *)ctx->data;
    if ((const char *)(udp + 1) > ctx->data_end)
        return -1;
    ctx->data    += sizeof(*udp);
    ctx->data_off += sizeof(*udp);
    ctx->udp = udp;
    return bpf_ntohs(udp->dest);
}

static __always_inline void context_reset(struct packet_context *ctx,
                                           char *data, const char *data_end) {
    ctx->data     = data;
    ctx->data_end = data_end;
    ctx->data_off = 0;
    ctx->eth  = 0;
    ctx->ip4  = 0;
    ctx->ip6  = 0;
    ctx->udp  = 0;
    ctx->gtp  = 0;
}

/* Re-parse from the current packet start after bpf_xdp_adjust_head. */
static __always_inline long context_reinit(struct packet_context *ctx,
                                            char *data, const char *data_end) {
    context_reset(ctx, data, data_end);
    struct ethhdr *eth = (struct ethhdr *)ctx->data;
    if ((const char *)(eth + 1) > ctx->data_end)
        return -1;
    ctx->data += sizeof(*eth);
    ctx->eth = eth;
    int proto = bpf_ntohs(eth->h_proto);
    if (proto == ETH_P_IP) {
        if (-1 == parse_ip4(ctx))
            return -1;
    }
    return 0;
}
