/* Copyright 2023-2025 Edgecom LLC. Adapted from eUPF (github.com/edgecomllc/eupf), Apache 2.0 */
#pragma once

#include <bpf/bpf_helpers.h>
#include <linux/types.h>

static __always_inline __u16 csum_fold_helper(__u64 csum) {
#pragma unroll
    for (int i = 0; i < 4; i++)
        csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

static __always_inline __u16 ipv4_csum(void *data_start, __u32 data_size) {
    __u64 csum = bpf_csum_diff(0, 0, data_start, data_size, 0);
    return csum_fold_helper(csum);
}
