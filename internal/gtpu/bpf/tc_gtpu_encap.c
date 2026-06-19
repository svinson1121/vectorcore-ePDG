/* TC-BPF uplink GTP-U encapsulation.
 *
 * Attaches to vc-xfrm0 ingress (post-XFRM/IPsec decrypt).
 *
 * vc-xfrm0 is a link/none L3-only XFRM virtual interface. The TC helper
 * offsets that matter here are relative to the skb network header, not a
 * real Ethernet header. BPF_ADJ_ROOM_NET inserts bytes before the inner IP
 * network header so the layout becomes [outer IP | UDP | GTP-U | inner IP].
 *
 * For each decrypted UE IPv4 packet:
 *   1. Look up the inner source IP in ue_session_map.
 *   2. Make room for outer IP + UDP + GTP-U headers (36 bytes).
 *   3. Write the outer headers at offsets 0 / 20 / 28.
 *   4. bpf_redirect_neigh → S2b NIC → PGW.
 *
 * Unknown source IPs pass through (TC_ACT_OK) — the kernel will drop or
 * route them normally, which is fine for control-plane traffic.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#define IP_DF   0x4000  /* Don't Fragment */
#define AF_INET 2
#define NET_HDR_OFF ETH_HLEN
#define MAX_TFT_RULES 32

#define TFT_F_REMOTE_IP   0x01
#define TFT_F_PROTOCOL    0x02
#define TFT_F_LOCAL_PORT  0x04
#define TFT_F_REMOTE_PORT 0x08

#include "headers/gtpu.h"

/* ── Maps ─────────────────────────────────────────────────────────────────── */

struct ipv4_key {
    __u8 addr[4];
};

struct ue_session_entry {
    __u32 ul_teid;      /* uplink TEID, host byte order */
    __u8 pgw_ip[4];     /* PGW GTP-U destination IP, network byte order */
    __u8 local_ip[4];   /* ePDG S2b GTP-U source IP, network byte order */
    __u32 s2b_ifindex;  /* S2b interface index for redirect */
    __u32 rule_count;   /* bounded TFT rules for this UE */
};

struct tft_rule_key {
    __u8 addr[4];
    __u32 index;
};

struct tft_rule_entry {
    __u32 ul_teid;       /* selected dedicated bearer TEID, host byte order */
    __u8 precedence;
    __u8 flags;
    __u8 protocol;
    __u8 _pad;
    __u8 remote_ip[4];
    __u8 remote_mask[4];
    __u16 local_port_lo;
    __u16 local_port_hi;
    __u16 remote_port_lo;
    __u16 remote_port_hi;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct ipv4_key);  /* UE inner IPv4 src, network byte order */
    __type(value, struct ue_session_entry);
    __uint(max_entries, 4096);
} ue_session_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct tft_rule_key);
    __type(value, struct tft_rule_entry);
    __uint(max_entries, 4096);
} tft_rule_map SEC(".maps");

/* ul_bearer_counters: TEID (host byte order) → packet/byte counters for
 * traffic encapsulated onto that bearer. Entries are created lazily on
 * first packet (see tc_gtpu_encap_func) and deleted from Go when the
 * bearer/TEID is torn down. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);
    __type(value, struct bearer_counters);
    __uint(max_entries, 4096);
} ul_bearer_counters SEC(".maps");

/* ── Stats ────────────────────────────────────────────────────────────────── */

enum ul_stat {
    UL_STAT_SEEN        = 0, /* IPv4 packets entering the hook */
    UL_STAT_NOT_IPV4    = 1, /* non-IPv4 passed through */
    UL_STAT_UE_MISS     = 2, /* src IP not in ue_session_map */
    UL_STAT_ADJUST_FAIL = 3, /* bpf_skb_adjust_room failed */
    UL_STAT_STORE_FAIL  = 4, /* bpf_skb_store_bytes failed */
    UL_STAT_ENCAP_OK    = 5, /* successfully encapsulated */
    UL_STAT_REDIR_FAIL  = 6, /* bpf_redirect_neigh returned error */
    UL_STAT_MAX         = 7,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 7); /* == UL_STAT_MAX */
} ul_stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&ul_stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

/* ── IPv4 header checksum ─────────────────────────────────────────────────── */

static __always_inline __u16 ip4_csum(struct iphdr *iph)
{
    __u32 sum = 0;
    __u16 *p = (__u16 *)iph;

    /* 20-byte fixed header = 10 × u16 words, no options. */
    sum += p[0]; sum += p[1]; sum += p[2]; sum += p[3]; sum += p[4];
    sum += p[5]; sum += p[6]; sum += p[7]; sum += p[8]; sum += p[9];

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (__u16)~sum;
}

static __always_inline int ipv4_mask_match(const __u8 pkt_ip[4], const __u8 rule_ip[4], const __u8 mask[4])
{
    if (((pkt_ip[0] ^ rule_ip[0]) & mask[0]) != 0)
        return 0;
    if (((pkt_ip[1] ^ rule_ip[1]) & mask[1]) != 0)
        return 0;
    if (((pkt_ip[2] ^ rule_ip[2]) & mask[2]) != 0)
        return 0;
    if (((pkt_ip[3] ^ rule_ip[3]) & mask[3]) != 0)
        return 0;
    return 1;
}

static __always_inline int tft_rule_matches(struct tft_rule_entry *rule, struct iphdr *inner_ip,
                                            __u16 src_port, __u16 dst_port, int has_ports)
{
    if ((rule->flags & TFT_F_REMOTE_IP) &&
        !ipv4_mask_match((const __u8 *)&inner_ip->daddr, rule->remote_ip, rule->remote_mask))
        return 0;

    if ((rule->flags & TFT_F_PROTOCOL) && inner_ip->protocol != rule->protocol)
        return 0;

    if (rule->flags & TFT_F_LOCAL_PORT) {
        if (!has_ports || src_port < rule->local_port_lo || src_port > rule->local_port_hi)
            return 0;
    }

    if (rule->flags & TFT_F_REMOTE_PORT) {
        if (!has_ports || dst_port < rule->remote_port_lo || dst_port > rule->remote_port_hi)
            return 0;
    }

    return 1;
}

/* ── Program ──────────────────────────────────────────────────────────────── */

/* Outer header size: IP(20) + UDP(8) + GTP-U(8) = 36 bytes. */
#define OUTER_HDR_LEN 36

SEC("tc")
int tc_gtpu_encap_func(struct __sk_buff *skb)
{
    /* Only handle IPv4. */
    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        stat_inc(UL_STAT_NOT_IPV4);
        return TC_ACT_OK;
    }

    stat_inc(UL_STAT_SEEN);

    struct ipv4_key key = {};
    if (bpf_skb_load_bytes_relative(skb, offsetof(struct iphdr, saddr), key.addr, sizeof(key.addr), BPF_HDR_START_NET) < 0)
        return TC_ACT_OK;

    struct ue_session_entry *sess = bpf_map_lookup_elem(&ue_session_map, &key);
    if (!sess) {
        stat_inc(UL_STAT_UE_MISS);
        return TC_ACT_OK;
    }

    struct iphdr inner_ip = {};
    if (bpf_skb_load_bytes_relative(skb, 0, &inner_ip, sizeof(inner_ip), BPF_HDR_START_NET) < 0)
        return TC_ACT_OK;
    if (inner_ip.version != 4 || inner_ip.ihl != 5)
        return TC_ACT_OK;

    __u16 inner_tot_be;
    if (bpf_skb_load_bytes_relative(skb, offsetof(struct iphdr, tot_len), &inner_tot_be, sizeof(inner_tot_be), BPF_HDR_START_NET) < 0)
        return TC_ACT_OK;
    __u32 inner_len = bpf_ntohs(inner_tot_be);

    __u32 selected_teid = sess->ul_teid;
    __u8 best_precedence = 255;
    int has_ports = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    if (inner_ip.protocol == IPPROTO_TCP || inner_ip.protocol == IPPROTO_UDP) {
        __u8 ihl = inner_ip.ihl * 4;
        __u16 ports[2] = {};
        if (bpf_skb_load_bytes_relative(skb, ihl, &ports, sizeof(ports), BPF_HDR_START_NET) == 0) {
            src_port = bpf_ntohs(ports[0]);
            dst_port = bpf_ntohs(ports[1]);
            has_ports = 1;
        }
    }

    __u32 rule_count = sess->rule_count;
    if (rule_count > MAX_TFT_RULES)
        rule_count = MAX_TFT_RULES;

    for (__u32 i = 0; i < MAX_TFT_RULES; i++) {
        if (i >= rule_count)
            break;

        struct tft_rule_key rule_key = {};
        __builtin_memcpy(rule_key.addr, key.addr, sizeof(rule_key.addr));
        rule_key.index = i;

        struct tft_rule_entry *rule = bpf_map_lookup_elem(&tft_rule_map, &rule_key);
        if (!rule)
            continue;

        if (rule->precedence >= best_precedence)
            continue;

        if (!tft_rule_matches(rule, &inner_ip, src_port, dst_port, has_ports))
            continue;

        selected_teid = rule->ul_teid;
        best_precedence = rule->precedence;
    }

    /* GTP-U message_length = inner IP packet length (GTP-U payload only).
     * UDP total  = UDP header (8) + GTP-U header (8) + inner IP.
     * IP total   = IP header (20) + UDP total. */
    __u16 gtp_len  = (__u16)inner_len;
    __u16 udp_len  = 8 + 8 + gtp_len;
    __u16 ip_total = 20 + udp_len;

    /* Prepend 36 bytes at the network layer (front of the inner IP packet).
     * After this: [outer IP(20) | UDP(8) | GTP-U(8) | inner IP]. */
    if (bpf_skb_adjust_room(skb, OUTER_HDR_LEN, BPF_ADJ_ROOM_NET, 0) < 0) {
        stat_inc(UL_STAT_ADJUST_FAIL);
        return TC_ACT_OK;
    }

    /* ── Outer IPv4 header (offset 0) ─────────────────────────────────── */
    struct iphdr outer_ip = {};
    outer_ip.version  = 4;
    outer_ip.ihl      = 5;
    outer_ip.tos      = 0;
    outer_ip.tot_len  = bpf_htons(ip_total);
    outer_ip.id       = 0;
    outer_ip.frag_off = bpf_htons(IP_DF);
    outer_ip.ttl      = 64;
    outer_ip.protocol = IPPROTO_UDP;
    outer_ip.check    = 0;
    __builtin_memcpy(&outer_ip.saddr, sess->local_ip, sizeof(outer_ip.saddr));
    __builtin_memcpy(&outer_ip.daddr, sess->pgw_ip, sizeof(outer_ip.daddr));
    outer_ip.check    = ip4_csum(&outer_ip);

    if (bpf_skb_store_bytes(skb, NET_HDR_OFF, &outer_ip, sizeof(outer_ip), 0) < 0) {
        stat_inc(UL_STAT_STORE_FAIL);
        return TC_ACT_OK;
    }

    /* ── Outer UDP header (offset 20) ─────────────────────────────────── */
    struct udphdr udp = {};
    udp.source = bpf_htons(GTP_UDP_PORT);
    udp.dest   = bpf_htons(GTP_UDP_PORT);
    udp.len    = bpf_htons(udp_len);
    udp.check  = 0; /* UDP checksum optional for IPv4 */

    if (bpf_skb_store_bytes(skb, NET_HDR_OFF + 20, &udp, sizeof(udp), 0) < 0) {
        stat_inc(UL_STAT_STORE_FAIL);
        return TC_ACT_OK;
    }

    /* ── GTP-U header (offset 28) ──────────────────────────────────────── */
    struct gtpuhdr gtp = {};
    /* Write flags byte directly — avoids the bitfield || compilation pitfall.
     * 0x30 = version=1, PT=1, E=0, S=0, PN=0. */
    *((__u8 *)&gtp) = GTP_FLAGS;
    gtp.message_type   = GTPU_G_PDU;
    gtp.message_length = bpf_htons(gtp_len);
    gtp.teid           = bpf_htonl(selected_teid);

    if (bpf_skb_store_bytes(skb, NET_HDR_OFF + 28, &gtp, sizeof(gtp), 0) < 0) {
        stat_inc(UL_STAT_STORE_FAIL);
        return TC_ACT_OK;
    }

    if (bpf_skb_store_bytes(skb, NET_HDR_OFF + OUTER_HDR_LEN, &inner_ip, sizeof(inner_ip), 0) < 0) {
        stat_inc(UL_STAT_STORE_FAIL);
        return TC_ACT_OK;
    }

    stat_inc(UL_STAT_ENCAP_OK);

    struct bearer_counters *bc = bpf_map_lookup_elem(&ul_bearer_counters, &selected_teid);
    if (!bc) {
        struct bearer_counters zero = {};
        bpf_map_update_elem(&ul_bearer_counters, &selected_teid, &zero, BPF_NOEXIST);
        bc = bpf_map_lookup_elem(&ul_bearer_counters, &selected_teid);
    }
    if (bc) {
        __sync_fetch_and_add(&bc->packets, 1);
        __sync_fetch_and_add(&bc->bytes, inner_len);
    }

    /* Redirect to S2b interface; kernel fills in Ethernet header via ARP. */
    struct bpf_redir_neigh nh = {};
    nh.nh_family = AF_INET;
    __builtin_memcpy(&nh.ipv4_nh, sess->pgw_ip, sizeof(nh.ipv4_nh));

    long rc = bpf_redirect_neigh(sess->s2b_ifindex, &nh, sizeof(nh), 0);
    if (rc != TC_ACT_REDIRECT)
        stat_inc(UL_STAT_REDIR_FAIL);
    return (int)rc;
}

char _license[] SEC("license") = "GPL";
