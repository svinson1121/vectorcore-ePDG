/* Copyright 2023-2025 Edgecom LLC. Adapted from eUPF (github.com/edgecomllc/eupf), Apache 2.0
 * Kept: parse_gtp, guess_eth_protocol, remove_gtp_header.
 * Dropped: echo handler, encap helpers (used in Phase 3 uplink TC). */
#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "gtpu.h"
#include "packet_context.h"
#include "parsers.h"

static __always_inline __u32 parse_gtp(struct packet_context *ctx) {
    struct gtpuhdr *gtp = (struct gtpuhdr *)ctx->data;
    if ((const char *)(gtp + 1) > ctx->data_end)
        return -1;
    ctx->data    += sizeof(*gtp);
    ctx->data_off += sizeof(*gtp);
    /* Use explicit byte mask to check E/S/PN flags (bits 2:0 of the flags byte).
     * Bitfield access compiles to a threshold comparison (>= 0x20) that is always
     * true for GTPv1 packets (version=1 sets bit 5, flags >= 0x20 always), causing
     * the extension word to be skipped/added incorrectly on every packet. */
    if ((*(const __u8 *)gtp) & 0x07) {
        ctx->data    += sizeof(struct gtp_hdr_ext);
        ctx->data_off += sizeof(struct gtp_hdr_ext);
    }
    ctx->gtp = gtp;
    return gtp->message_type;
}

/* Guess inner IP version from the first byte when there is no Ethernet header. */
static __always_inline int guess_eth_protocol(const char *data) {
    const __u8 ver = (*(const __u8 *)data) >> 4;
    switch (ver) {
    case 4: return ETH_P_IP_BE;
    case 6: return ETH_P_IPV6_BE;
    default: return -1;
    }
}

/* Strip the outer Eth+IP+UDP+GTP headers and leave the inner IP packet.
 * The Ethernet header is copied forward so the packet remains valid at L2.
 * Returns 0 on success, non-zero on error. */
static __always_inline long remove_gtp_header(struct packet_context *ctx) {
    if (!ctx->gtp)
        return -1;

    __u32 ext = 0;
    if ((*(const __u8 *)ctx->gtp) & 0x07)
        ext = sizeof(struct gtp_hdr_ext);

    const __u32 encap = sizeof(struct iphdr) + sizeof(struct udphdr) +
                        sizeof(struct gtpuhdr) + ext;

    char       *data     = (char *)(long)ctx->xdp_ctx->data;
    const char *data_end = (const char *)(long)ctx->xdp_ctx->data_end;

    struct ethhdr *orig_eth = (struct ethhdr *)data;
    if ((const char *)(orig_eth + 1) > data_end)
        return -1;

    /* Copy the outer Ethernet header to just before the inner IP packet. */
    struct ethhdr *new_eth = (struct ethhdr *)(data + encap);
    if ((const char *)(new_eth + 1) > data_end)
        return -1;

    /* Detect inner L3 protocol from first byte of inner IP header. */
    char *inner_ip = (char *)(new_eth + 1);
    if (inner_ip + 1 > data_end)
        return -1;
    int inner_proto = guess_eth_protocol(inner_ip);
    if (inner_proto == -1)
        return -1;

    __builtin_memcpy(new_eth, orig_eth, sizeof(*new_eth));
    new_eth->h_proto = (__u16)inner_proto;

    long rc = bpf_xdp_adjust_head(ctx->xdp_ctx, (int)encap);
    if (rc)
        return rc;

    data     = (char *)(long)ctx->xdp_ctx->data;
    data_end = (const char *)(long)ctx->xdp_ctx->data_end;
    return context_reinit(ctx, data, data_end);
}
