/* Copyright 2023-2025 Edgecom LLC. Adapted from eUPF (github.com/edgecomllc/eupf), Apache 2.0
 * Simplified: removed PFCP counters and N3/N6 stats not needed here. */
#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include "gtpu.h"

struct packet_context {
    char       *data;
    const char *data_end;
    /* Bytes consumed by parsers (pure __u32 counter, no pointer arithmetic).
     * Use ctx->data_end - ctx->data - data_off to compute inner_len without
     * a PTR_TO_PACKET subtraction — that subtraction's result type confuses
     * the BPF verifier's range tracking and triggers spurious "min value is
     * negative / zero-sized read" rejections. */
    __u32      data_off;
    struct xdp_md    *xdp_ctx;
    struct ethhdr    *eth;
    struct iphdr     *ip4;
    struct ipv6hdr   *ip6;
    struct udphdr    *udp;
    struct gtpuhdr   *gtp;
};
