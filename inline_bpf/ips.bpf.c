#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ips_fast_common.h"

// ==============================================================================
// MAPS DEFINITIONS
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ips_token_bucket);
    __uint(max_entries, 10240);
} ip_tracker SEC(".maps");

#define SNI_MAX_LEN 256

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sni_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
} sni_blocklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sni_key);
    __type(value, __u8);
    __uint(max_entries, 1024);
} doh_blocklist_map SEC(".maps");

// ==============================================================================
// #REQ-072: L7 BPF Protocol Parsers (SNI, DNS, HTTP) via bpf_tail_call
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10);
} jmp_table SEC(".maps");

#define PROG_IDX_TLS_PARSER 0
#define PROG_IDX_DNS_PARSER 1
#define PROG_IDX_HTTP_PARSER 2
#define PROG_IDX_SSH_PARSER 3

// ==============================================================================
// #REQ-009: Dynamic Blocklist Map (rate-limit bans, always a single /32 IP)
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // Key: Source IPv4 Address
    __type(value, struct ips_blocklist_data);
    __uint(max_entries, 65536);
} dynamic_bans_map SEC(".maps");

// ==============================================================================
// #REQ-057: Static Threat-Intel Blocklist Map (CIDR-capable, injector.c owns writes)
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key);
    __type(value, struct ips_blocklist_data);
    __uint(max_entries, 262144); // Can hold 256k known malicious IPs/subnets
    __uint(map_flags, BPF_F_NO_PREALLOC); // the kernel cannot pre-allocate memory for an LPM Trie
} threat_intel_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10240);
} honeypot_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct ips_allowlist_data);
    __uint(max_entries, 131072);
} allowlist SEC(".maps");

// #REQ-XXX: Greylist bootstrap ("5 clean observations -> trust"), per source IP.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct ips_greylist_data);
    __uint(max_entries, 65536);
} greylist SEC(".maps");

// #REQ-XXX: Port/protocol conformance ("first packet" tracking for http_parser/ssh_parser).
// Presence means this flow's very first payload-bearing packet already ran the strict
// request-line/banner check -- HTTP/SSH only guarantee their identifying shape on that one
// packet (everything after is a body chunk, a second keep-alive request, or opaque encrypted
// framing), so later packets skip re-checking instead of false-positiving on ordinary
// multi-packet traffic. Keyed on struct flow_key but callers always zero .tcp_flags/.padding
// before use -- unlike `allowlist` below, this must match the same flow regardless of which
// packet (SYN/ACK/PSH/...) triggered the lookup.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
} l7_seen_map SEC(".maps");

// #REQ-XXX: Stage 2.6 out-of-state ACK detection (ACK/Window/Maimon scan). Presence means
// a genuine SYN (SYN=1,ACK=0) was observed for this flow -- written for BOTH directions
// (forward and reverse, same reasoning as `allowlist`'s promotion above) so the server's own
// return traffic isn't mistaken for an out-of-state probe too. Keyed on struct flow_key with
// .tcp_flags/.padding always zeroed by callers, same convention as l7_seen_map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u8);
    __uint(max_entries, 131072);
} conn_seen_map SEC(".maps");

// Source IPs/subnets exempt from the greylist bootstrap, loaded once from config.ini's
// excluded_source_ips at startup (main.c owns writes, same as threat_intel_map/injector.c).
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key);
    __type(value, __u8);
    __uint(max_entries, MAX_EXCLUDED_SRCS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} excluded_srcs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ban_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10240);
} quarantine_map SEC(".maps");

// ==============================================================================
// #REQ-074: Recon Events Stream
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} recon_events SEC(".maps");

volatile const __u32 burst_tokens = 50;
volatile const __u32 max_tolerated_drops = 15;
volatile const __u64 refill_interval_ns = 50000000ULL;
volatile const __u32 wan_ifindex = 0;
// Boot-monotonic ns deadline (bpf_ktime_get_ns() domain) computed once at attach time in
// main.c: now + conn_track_grace_period_sec. Before this, stage 2.6 doesn't enforce, so
// connections already established when ips_loader restarts (this box's own SSH session
// included) survive instead of getting banned for having no recorded SYN in the fresh map.
volatile const __u64 grace_period_end_ns = 0;

//----------------------------------------------------------------------------------------------------------------------

// syn+fin, null scan, fin+psh+urg (xmas), bare fin (fin scan) -- single-packet, stateless,
// no reassembly needed. Bare FIN is safe to flag unconditionally: once a connection is
// established, a legitimate stack always sets ACK alongside FIN during teardown -- FIN
// without ACK never happens in real traffic, only in nmap -sF style scans.
static __always_inline int is_malicious_tcp_flags(const struct tcphdr *tcp) {
    return (tcp->syn && tcp->fin) ||
           (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->urg) ||
           (tcp->fin && tcp->psh && tcp->urg) ||
           (tcp->fin && !tcp->ack);
}

SEC("xdp")
int ips_xdp_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // ----------------------------------------------------
    // LAYER 2 & 3 PARSING
    // ----------------------------------------------------
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    // TODO: IPv6 currently passes completely uninspected (no rate limit, no blocklist,
    // nothing) -- a real bypass on any dual-stack network. A bounded walk of the common
    // extension headers (hop-by-hop/routing/fragment, capped at a small max depth) is
    // feasible in XDP; anything deeper should punt to the slow path like today's IPv4 path.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dest_ip = ip->daddr;
    __u8 *action_flag;

    // ====================================================
    // STAGE 0.05: IP FRAGMENTATION - #REQ-XXX
    // ====================================================
    // Every check downstream of this point (malformed-flags, port/protocol conformance,
    // recon tracker, L7 parsers...) assumes the full L4 header is present in this one
    // packet. `nmap -f`/`--mtu` defeats all of that at once by splitting the TCP header
    // itself across two IP fragments: the first fragment can be crafted short enough to
    // omit the flags byte (passes every bounds check below as "incomplete, not TCP"), and
    // the trailing fragment has no L4 header at all to inspect. On this rig's single,
    // uniform-MTU LAN, genuine fragmentation basically never happens for TCP -- PMTUD
    // avoids it entirely -- so instead of the real fix (stateful reassembly, expensive and
    // its own source of bugs), fragments are treated the same as any other structural
    // attack signature already in this file: instant ban, same as Stage 2.5.
    //
    // Two sourced fixes to reach for if this blanket policy ever turns out to be a real
    // problem (a legitimate host on this network that genuinely needs to fragment):
    //   1. (implemented below) exempt specific sources via excluded_srcs -- same config.ini
    //      excluded_source_ips list already used to exempt infra from Stage 0.5/5.
    //   2. (not implemented) a real IP defragmentation engine: buffer fragments per
    //      (src_ip, dst_ip, id) in a map, reassemble once all arrive, re-run this whole
    //      pipeline against the reassembled packet. Correctly handles legitimate
    //      fragmentation instead of just carving out exceptions for it, but is a
    //      meaningfully bigger feature -- per-flow buffering, reassembly timeouts,
    //      overlapping-fragment attacks (the classic teardrop/rose-fragment evasion class)
    //      to guard against in the reassembly logic itself -- worth it only if exemption
    //      lists prove to be too blunt in practice.
    __u16 frag_info = bpf_ntohs(ip->frag_off);
    __u16 frag_offset = frag_info & 0x1FFF;    // low 13 bits: offset in 8-byte units
    int more_fragments = (frag_info & 0x2000) != 0; // bit 13: MF flag

    if (frag_offset != 0 || more_fragments) {
        struct lpm_ip_key frag_excl_key = { .prefixlen = 32, .ip = src_ip };
        if (!bpf_map_lookup_elem(&excluded_srcs, &frag_excl_key)) {
            struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
            if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                bpf_map_delete_elem(&ip_tracker, &src_ip);
                struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                if (event) {
                    event->src_ip     = src_ip;
                    event->drop_count = 0;
                    event->reason     = IPS_BAN_REASON_FRAGMENTED;
                    bpf_ringbuf_submit(event, 0);
                }
            }
            return XDP_DROP;
        }
        // Excluded source: still can't be inspected (no full L4 header here), but skip the
        // ban -- falls through to the rest of the pipeline like any other packet, which
        // will itself PASS or DROP incomplete headers per each stage's own bounds checks.
    }

    // ====================================================
    // STAGE 0.1: ANTI-SPOOFING (BCP38) - #REQ-075
    // ====================================================
    // If the packet arrived on the WAN interface, it MUST NOT have an internal source IP.
    if (wan_ifindex > 0 && ctx->ingress_ifindex == wan_ifindex && is_internal_ip(src_ip)) {
        return XDP_DROP;
    }

    // ====================================================
    // STAGE 0.5: QUARANTINE & COMPROMISE DETECTION
    // ====================================================
    // Core network infrastructure (gateway, AP) is exempt: quarantine_map has no expiry
    // (unlike dynamic_bans_map), so a single innocent packet from one of these devices toward
    // a client that happens to be banned at that instant -- e.g. a DHCP renewal, or just a
    // normal reply -- would otherwise silently and permanently quarantine the infrastructure
    // device itself until the next service restart. Put the gateway/AP IPs in
    // excluded_source_ips (config.ini) to cover this.
    struct lpm_ip_key q_excl_key = { .prefixlen = 32, .ip = src_ip };
    if (!bpf_map_lookup_elem(&excluded_srcs, &q_excl_key)) {
        __u8 *quarantined = bpf_map_lookup_elem(&quarantine_map, &src_ip);
        if (quarantined) {
            return XDP_DROP; // Host is isolated!
        }

        struct ips_blocklist_data *dest_blocked = bpf_map_lookup_elem(&dynamic_bans_map, &dest_ip);
        if (dest_blocked) {
            __u8 val = 1;
            bpf_map_update_elem(&quarantine_map, &src_ip, &val, BPF_ANY);
            return XDP_DROP;
        }
    }

    // ====================================================
    // STAGE 1: BLOCKLIST
    // After testing, decided to set it first due to writing overhead 
    // caused by incrementing packet drops on already banned IPs
    // ====================================================

    // THE PACKET LOOKUP -- dynamic (rate-limit) bans first, then static/threat-intel
    struct ips_blocklist_data *blocked = bpf_map_lookup_elem(&dynamic_bans_map, &src_ip);
    if (blocked) {
        __sync_fetch_and_add(&blocked->packets_dropped, 1);
        return XDP_DROP;
    }

    struct lpm_ip_key search_key = {};
    search_key.prefixlen = 32;     // A packet is always a single exact IP (/32) (ONLY IPv4)
    search_key.ip = ip->saddr;

    struct ips_blocklist_data *static_blocked = bpf_map_lookup_elem(&threat_intel_map, &search_key);
    if (static_blocked) {
        __sync_fetch_and_add(&static_blocked->packets_dropped, 1);
        return XDP_DROP;
    }

    // ====================================================
    // STAGE 2: RATE LIMITER
    // ====================================================
    //bpf_printk("[IPS-DEBUG] 2. Checking Rate Limiter\n");
    __u64 current_time = bpf_ktime_get_ns();
    struct ips_token_bucket *bucket;
    struct ips_token_bucket new_bucket = {0};

    bucket = bpf_map_lookup_elem(&ip_tracker, &src_ip);
    if (!bucket) {
        //bpf_printk("[IPS-DEBUG] -> Rate Limiter: New IP, bucket created (Pass)\n");
        new_bucket.last_update = current_time;
        new_bucket.tokens = burst_tokens - 1;
        bpf_map_update_elem(&ip_tracker, &src_ip, &new_bucket, BPF_ANY);
    } else {
        __u64 time_passed = current_time - bucket->last_update;
        __u32 tokens_to_add = time_passed / refill_interval_ns;

        if (tokens_to_add > 0) {
            bucket->tokens += tokens_to_add;
            if (bucket->tokens > burst_tokens) bucket->tokens = burst_tokens;
            bucket->last_update += (tokens_to_add * refill_interval_ns);

            // Graceful decay: forgive drops in proportion to tokens earned back, instead of
            // wiping drop_count on any partial refill. A full reset here let an attacker pace
            // packets just above the refill interval, re-forgiving itself every tick and never
            // reaching max_tolerated_drops no matter how many packets it had dropped overall.
            if (bucket->drop_count > 0) {
                bucket->drop_count = (tokens_to_add >= bucket->drop_count) ? 0 : bucket->drop_count - tokens_to_add;
            }
        }

        if (bucket->tokens > 0) {
            bucket->tokens -= 1;
        } else {
            //bpf_printk("[IPS-DEBUG] -> Rate Limit Exceeded: Dropping packet!\n");
            __sync_fetch_and_add(&bucket->drop_count, 1);
            if (bucket->drop_count > max_tolerated_drops) {
                //bpf_printk("[IPS-DEBUG] -> Max tolerated drops crossed: Triggering Ban!\n");

                struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };

                if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                    // Now that it's in the dynamic_bans_map, remove from the active rate limiter tracker
                    bpf_map_delete_elem(&ip_tracker, &src_ip);

                    // Notify User-Space for logging and updating the CSV
                    struct ips_ban_event *event;
                    event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                    if (event) {
                        event->src_ip = src_ip;
                        event->drop_count = bucket->drop_count;
                        event->reason = IPS_BAN_REASON_RATE_LIMIT;
                        bpf_ringbuf_submit(event, 0);
                    }
                }
            }
            return XDP_DROP;
        }
    }

    // ----------------------------------------------------
    // LAYER 4 PARSING (Needed for Allowlist 5-tuple)
    // ----------------------------------------------------
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
    if ((void *)((__u8 *)ip + ip_hdr_len) > data_end) return XDP_PASS;

    struct flow_key current_flow = {0};
    current_flow.source_ip = ip->saddr;
    current_flow.dest_ip = ip->daddr;
    current_flow.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        current_flow.source_port = tcp->source;
        current_flow.dest_port = tcp->dest;
        
        // Extract tcp flags (byte 13 of TCP header)
        __u8 *tcp_bytes = (__u8 *)tcp;
        current_flow.tcp_flags = tcp_bytes[13];

        // ====================================================
        // STAGE 2.5: MALFORMED TCP FLAGS - #REQ-069
        // ====================================================
        if (is_malicious_tcp_flags(tcp)) {
            struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };

            if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                bpf_map_delete_elem(&ip_tracker, &src_ip);

                struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                if (event) {
                    event->src_ip = src_ip;
                    event->drop_count = 0;
                    event->reason = IPS_BAN_REASON_MALFORMED_FLAGS;
                    bpf_ringbuf_submit(event, 0);
                }
            }
            return XDP_DROP;
        }

        // ====================================================
        // STAGE 2.6: OUT-OF-STATE ACK - #REQ-XXX (ACK/Window/Maimon scan detection)
        // ====================================================
        // ACK/Window scans (-sA/-sW) and Maimon scans (-sM) send a bare ACK or FIN+ACK that
        // never followed a real SYN -- flags alone can't tell that apart from a legitimate
        // mid-connection packet (every real ACK looks exactly like this too), so this needs
        // actual state: has this exact flow ever sent a SYN we saw? (recorded below in
        // Stage 6, for both directions, so the server's own return traffic isn't mistaken
        // for an out-of-state probe). Skipped during the post-restart grace period so
        // connections already established before this ips_loader process started (this
        // box's own SSH session included) aren't banned just for predating a freshly empty
        // conn_seen_map.
        if (tcp->ack && !tcp->syn && bpf_ktime_get_ns() >= grace_period_end_ns) {
            struct flow_key seen_key = current_flow;
            seen_key.tcp_flags = 0;

            if (!bpf_map_lookup_elem(&conn_seen_map, &seen_key)) {
                struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
                if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                    bpf_map_delete_elem(&ip_tracker, &src_ip);
                    struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                    if (event) {
                        event->src_ip     = src_ip;
                        event->drop_count = 0;
                        event->reason     = IPS_BAN_REASON_OUT_OF_STATE_ACK;
                        bpf_ringbuf_submit(event, 0);
                    }
                }
                return XDP_DROP;
            }
        }
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((__u8 *)ip + ip_hdr_len);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        current_flow.source_port = udp->source;
        current_flow.dest_port = udp->dest;

    }

    // ====================================================
    // STAGE 3: ALLOWLIST
    // ====================================================
    struct ips_allowlist_data *allow_entry = bpf_map_lookup_elem(&allowlist, &current_flow);
    if (allow_entry) {
        return XDP_PASS;
    }

    // ====================================================
    // STAGE 4: HONEYPOT
    // TODO: this only ever XDP_PASSes flagged IPs -- there's no actual redirect-to-
    // honeypot (VLAN 100/"dirtnet") wired in yet. Per the spec, that redirect is meant
    // to happen via br_netfilter DNAT further up the stack (not here in XDP), so this
    // stage just needs to keep marking/passing; the DNAT rule + Cowrie honeypot + VLAN
    // 100 routing are the still-missing pieces, all outside this file.
    // ====================================================
    action_flag = bpf_map_lookup_elem(&honeypot_map, &src_ip);
    if (action_flag && *action_flag == 1) {
        return XDP_PASS;
    }

    // ====================================================
    // STAGE 5: GREYLIST BOOTSTRAP ("5 clean observations -> trust")
    // Only reachable for TCP/UDP (current_flow's ports are unset otherwise), on a flow that
    // just missed the allowlist above. Ported from the old user-space slow_path_sniffer()/
    // track_and_check_greylist() -- same semantics, now line-rate and lock-free (the counter
    // uses __sync_fetch_and_add instead of a mutex, same pattern as bucket->drop_count above).
    // ====================================================
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct lpm_ip_key excl_key = { .prefixlen = 32, .ip = src_ip };
        if (!bpf_map_lookup_elem(&excluded_srcs, &excl_key)) {
            struct ips_greylist_data *grey = bpf_map_lookup_elem(&greylist, &src_ip);
            int promote = 0;

            if (!grey) {
                struct ips_greylist_data new_grey = { .count = 1, .authorized = 0 };
                bpf_map_update_elem(&greylist, &src_ip, &new_grey, BPF_ANY);
            } else if (grey->authorized) {
                // Already proven clean -- fast-track this (possibly new) flow without
                // re-counting, even if its earlier allowlist entry aged out.
                promote = 1;
            } else {
                __u32 new_count = __sync_fetch_and_add(&grey->count, 1) + 1;
                if (new_count >= 500) {
                    grey->authorized = 1;
                    promote = 1;
                    bpf_map_delete_elem(&ip_tracker, &src_ip);
                }
            }

            if (promote) {
                struct ips_allowlist_data trust = { .last_seen = bpf_ktime_get_ns() / 1000000000ULL };
                bpf_map_update_elem(&allowlist, &current_flow, &trust, BPF_ANY);

                struct flow_key reverse_flow = current_flow;
                reverse_flow.source_ip = current_flow.dest_ip;
                reverse_flow.dest_ip = current_flow.source_ip;
                reverse_flow.source_port = current_flow.dest_port;
                reverse_flow.dest_port = current_flow.source_port;
                bpf_map_update_elem(&allowlist, &reverse_flow, &trust, BPF_ANY);
            }
        }
    }

    // ====================================================
    // STAGE 6: RECON TRACKER (PORT SNOOPING & PING SWEEPS)
    // Runs after allowlist check to prevent false positives from internal IT.
    // ====================================================
    if (ip->protocol == IPPROTO_TCP && (current_flow.tcp_flags & 0x02) && !(current_flow.tcp_flags & 0x10)) {
        // SYN=1 (0x02), ACK=0 (0x10)
        struct ips_recon_event *revent = bpf_ringbuf_reserve(&recon_events, sizeof(*revent), 0);
        if (revent) {
            revent->src_ip = ip->saddr;
            revent->dst_port = bpf_ntohs(current_flow.dest_port);
            revent->protocol = PROTO_TCP;
            bpf_ringbuf_submit(revent, 0);
        }

        // Feeds Stage 2.6 (out-of-state ACK detection, above): a genuine SYN proves this
        // flow's later ACKs are legitimate. Recorded for BOTH directions -- same reasoning
        // as the allowlist promotion below -- so the server's own reply traffic (a
        // different 5-tuple) isn't mistaken for an out-of-state probe too.
        struct flow_key seen_key = current_flow;
        seen_key.tcp_flags = 0;
        __u8 seen_val = 1;
        bpf_map_update_elem(&conn_seen_map, &seen_key, &seen_val, BPF_ANY);

        struct flow_key seen_key_rev = seen_key;
        seen_key_rev.source_ip   = seen_key.dest_ip;
        seen_key_rev.dest_ip     = seen_key.source_ip;
        seen_key_rev.source_port = seen_key.dest_port;
        seen_key_rev.dest_port   = seen_key.source_port;
        bpf_map_update_elem(&conn_seen_map, &seen_key_rev, &seen_val, BPF_ANY);
    } else if (ip->protocol == IPPROTO_ICMP) {
        // Need to include icmp header parsing
        struct icmphdr {
            __u8 type;
            __u8 code;
            __u16 checksum;
            union {
                struct {
                    __u16 id;
                    __u16 sequence;
                } echo;
                __u32 gateway;
                struct {
                    __u16 __unused;
                    __u16 mtu;
                } frag;
            } un;
        };
        struct icmphdr *icmp = (void *)((__u8 *)ip + ip_hdr_len);
        if ((void *)(icmp + 1) <= data_end) {
            if (icmp->type == 8) { // Echo Request
                struct ips_recon_event *revent = bpf_ringbuf_reserve(&recon_events, sizeof(*revent), 0);
                if (revent) {
                    revent->src_ip = ip->saddr;
                    revent->dst_port = 0;
                    revent->protocol = PROTO_ICMP;
                    bpf_ringbuf_submit(revent, 0);
                }
            }
        }
    }

    // ====================================================
    // STAGE 7: L7 DEEP PACKET INSPECTION (TAIL CALLS)
    // Runs last so it doesn't bypass Allowlist and Recon trackers.
    // ====================================================
    if (ip->protocol == IPPROTO_TCP) {
        if (current_flow.dest_port == bpf_htons(443)) {
            bpf_tail_call(ctx, &jmp_table, PROG_IDX_TLS_PARSER);
        } else if (current_flow.dest_port == bpf_htons(80)) {
            bpf_tail_call(ctx, &jmp_table, PROG_IDX_HTTP_PARSER);
        } else if (current_flow.dest_port == bpf_htons(22)) {
            bpf_tail_call(ctx, &jmp_table, PROG_IDX_SSH_PARSER);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        if (current_flow.dest_port == bpf_htons(53)) {
            bpf_tail_call(ctx, &jmp_table, PROG_IDX_DNS_PARSER);
        }
    }

    return XDP_PASS;
}

#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_CLIENT_HELLO_TYPE      0x01
#define TLS_EXT_SERVER_NAME        0x0000
#define TLS_SNI_HOST_NAME_TYPE     0x00

SEC("xdp")
// #REQ-058: L7 (TLS/SNI) Parser — redesigned to use bpf_xdp_load_bytes().
//
// bpf_xdp_load_bytes(ctx, numeric_offset, local_buf, size) takes a plain __u32
// offset and copies bytes into a stack buffer.  The verifier does NOT need to prove
// the offset is in-bounds — the helper does that at runtime, returning < 0 on error.
// We check the return value and bail.  No variable-offset pointer arithmetic at all.
//
// Exit semantics:
//   XDP_PASS  — packet is not a TLS ClientHello (data record, ACK, alert, etc.)
//   XDP_PASS  — well-formed ClientHello, SNI not in blocklist
//   XDP_DROP  — packet positively identified as a ClientHello but structurally
//               malformed (truncated mid-field, field value outside RFC 5246 limits).
//               Blocks evasion via crafted malformed handshakes.
//   XDP_DROP  — SNI matches sni_blocklist_map or doh_blocklist_map → ban + event
int tls_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u32 pkt_len  = (__u32)(data_end - data);

    // Fixed-size headers: safe pointer arithmetic (compile-time struct sizes)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS; // bounds check
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS; // IPv4 check

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS; // bounds check for standard 20-byte IPv4 header
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS; // bogus packet data protection (header claims a false size)
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS; // Protocol filter

    struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len); // TCP header start
    if ((void *)(tcp + 1) > data_end) return XDP_PASS; // bounds check for the header
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) return XDP_PASS; // TCP header length check

    // payload_off: plain integer offset, NOT a pointer derived from data.
    // bpf_xdp_load_bytes uses this as a numeric index and validates it internally.
    __u32 payload_off = ((__u8 *)tcp - (__u8 *)data) + tcp_hdr_len;

    // --- TLS Record Header: content_type(1) + version(2) + length(2) = 5 bytes ---
    // No payload at all (bare ACK, etc.) -- nothing to enforce, this is normal TCP traffic.
    __u8 tls_hdr[3]; // content_type, version_major, version_minor
    if (bpf_xdp_load_bytes(ctx, payload_off, tls_hdr, 3) < 0) return XDP_PASS;

    __u8 content_type  = tls_hdr[0];
    __u8 version_major = tls_hdr[1];

    // #REQ-XXX: Port/protocol conformance. Every TLS record -- handshake, application_data,
    // alert, change_cipher_spec, heartbeat -- carries this same 5-byte header shape on every
    // single packet of the connection, not just the handshake. Unlike HTTP (see http_parser),
    // that makes it cheap AND correct to enforce continuously: a non-TLS protocol tunneled
    // over 443 (an SSH banner, raw C2 bytes, ...) fails this on every packet it ever sends,
    // not just the first one, so there's no need for a per-flow "already checked" map here.

    int looks_like_tls = version_major == 3 && // Protocol Version
        (content_type == 20 || content_type == 21 || content_type == 22 ||
         content_type == 23 || content_type == 24); // Record type (22 means Handshake. Important due to ClientHello)

    if (!looks_like_tls) {
        __u32 src_ip = ip->saddr;
        struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
        if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
            bpf_map_delete_elem(&ip_tracker, &src_ip);
            struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
            if (event) {
                event->src_ip     = src_ip;
                event->drop_count = 0;
                event->reason     = IPS_BAN_REASON_PROTOCOL_MISMATCH;
                bpf_ringbuf_submit(event, 0);
            }
        }
        return XDP_DROP;
    }

    if (content_type != TLS_HANDSHAKE_CONTENT_TYPE) return XDP_PASS; // valid TLS record, just not a ClientHello -- nothing more to inspect

    // --- Handshake type byte at offset +5 ---
    __u8 hs_type;
    if (bpf_xdp_load_bytes(ctx, payload_off + 5, &hs_type, 1) < 0) return XDP_PASS;
    if (hs_type != TLS_CLIENT_HELLO_TYPE) return XDP_PASS;

    // Packet has positively identified as a TLS ClientHello.
    // Any structural failure from here on is DROP (malformed or evasion attempt).
    //
    // ClientHello memory layout (offsets from payload_off):
    //   [0]      TLS record content_type  (verified above)
    //   [1..2]   TLS record version
    //   [3..4]   TLS record length
    //   [5]      Handshake type           (verified above)
    //   [6..8]   Handshake length (3 bytes)
    //   [9..10]  ClientHello version
    //   [11..42] Random (32 bytes)
    //   [43]     session_id_length        ← pos starts here
    __u32 pos = payload_off + 43;

    __u8 session_id_len;
    if (bpf_xdp_load_bytes(ctx, pos, &session_id_len, 1) < 0) return XDP_DROP;
    if (session_id_len > 32) return XDP_DROP;  // RFC 5246 §7.4.1.2 hard limit
    pos += 1 + (__u32)session_id_len;

    __u8 cs_len_buf[2];
    if (bpf_xdp_load_bytes(ctx, pos, cs_len_buf, 2) < 0) return XDP_DROP;
    __u32 cipher_suites_len = ((__u32)cs_len_buf[0] << 8) | cs_len_buf[1];
    if (cipher_suites_len > 512) return XDP_DROP;  // 512 B = 256 suites; pathological beyond that
    pos += 2 + cipher_suites_len;

    __u8 comp_len;
    if (bpf_xdp_load_bytes(ctx, pos, &comp_len, 1) < 0) return XDP_DROP;
    if (comp_len > 16) return XDP_DROP;  // Practically always 1 (null compression only)
    pos += 1 + (__u32)comp_len;

    // Extensions total length — may be absent in bare TLS 1.2 without extensions → pass.
    __u8 ext_total_buf[2];
    if (bpf_xdp_load_bytes(ctx, pos, ext_total_buf, 2) < 0) return XDP_PASS;
    pos += 2;

    __u32 src_ip = ip->saddr;

    // Phase 1: scan extensions to locate the SNI extension.
    // We only record its offset here — no name_len, no barrier_var inside the loop.
    // Keeping the loop body simple (no opaque scalars) prevents verifier state explosion.
    __u32 sni_pos = 0;  // offset of the SNI extension data (0 = not found)

    #pragma unroll // copy the loop contents in the compiled bytecode
    for (int i = 0; i < 10; i++) { // we do it 10 times to save CPU cycles. If it's not in the first 10 extensions provided, then we stop looking
        __u8 ext_hdr[4];
        if (bpf_xdp_load_bytes(ctx, pos, ext_hdr, 4) < 0) break;

        __u32 ext_type = ((__u32)ext_hdr[0] << 8) | ext_hdr[1];
        __u32 ext_len  = ((__u32)ext_hdr[2] << 8) | ext_hdr[3];
        pos += 4;

        if (ext_type == TLS_EXT_SERVER_NAME) {
            sni_pos = pos; // no parsing due to state explosion
            break;
        }

        // Bound ext_len to prevent unbounded pos accumulation across iterations.
        // A legitimate TLS extension body is never > 2048 bytes; anything larger
        // is either malformed or a crafted evasion attempt.
        if (ext_len > 2048) return XDP_DROP; // integer overflow limit
        pos += ext_len;
    }

    // Phase 2: if we found an SNI extension, parse and check it.
    // This is straight-line code — no loops, so barrier_var(name_len) only
    // affects one linear path. The verifier's state space stays manageable.
    if (sni_pos == 0)
        return XDP_PASS;  // No SNI extension → nothing to check

    __u8 sni_hdr[5];
    if (bpf_xdp_load_bytes(ctx, sni_pos, sni_hdr, 5) < 0) return XDP_DROP;

    __u8  name_type = sni_hdr[2];
    if (name_type != TLS_SNI_HOST_NAME_TYPE) return XDP_PASS;

    // barrier_var: prevents the compiler from optimising the >= SNI_MAX_LEN check into
    // a high-byte-only branch (if sni_hdr[3] != 0) which leaves name_len's verifier
    // range at [0, 65535].  With the barrier, the compiler must emit a direct comparison
    // on name_len itself, so the verifier narrows it to [1, SNI_MAX_LEN-1] = [1, 255].
    __u32 name_len = ((__u32)sni_hdr[3] << 8) | sni_hdr[4];
    barrier_var(name_len);
    if (name_len == 0 || name_len >= SNI_MAX_LEN) return XDP_DROP;
    // Verifier: name_len in [1, 255] <= sizeof(key.sni) = 256.

    struct sni_key key = {0};
    if (bpf_xdp_load_bytes(ctx, sni_pos + 5, key.sni, name_len) < 0)
        return XDP_DROP;

    __u8 *is_blocked = bpf_map_lookup_elem(&sni_blocklist_map, &key);
    if (is_blocked) {
        struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
        if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
            bpf_map_delete_elem(&ip_tracker, &src_ip);
            struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
            if (event) {
                event->src_ip     = src_ip;
                event->drop_count = 0;
                event->reason     = IPS_BAN_REASON_MALICIOUS_SNI;
                bpf_ringbuf_submit(event, 0);
            }
        }
        return XDP_DROP;
    }

    __u8 *is_doh = bpf_map_lookup_elem(&doh_blocklist_map, &key);
    if (is_doh) {
        struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
        if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
            bpf_map_delete_elem(&ip_tracker, &src_ip);
            struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
            if (event) {
                event->src_ip     = src_ip;
                event->drop_count = 0;
                event->reason     = IPS_BAN_REASON_MALICIOUS_SNI;
                bpf_ringbuf_submit(event, 0);
            }
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp")
// #REQ-058: L7 (DNS) Parser — redesigned to use bpf_xdp_load_bytes().
//
// Exit semantics:
//   XDP_PASS  — not a DNS query (response, multi-question, or packet too short)
//   XDP_DROP  — packet is a DNS query but QNAME is structurally malformed
//               (truncated mid-label, label length > 63 per RFC 1035)
//               Blocks evasion via oversized/crafted QNAME labels.
//   XDP_DROP  — queried domain matches sni_blocklist_map → ban + event
int dns_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u32 pkt_len  = (__u32)(data_end - data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)((__u8 *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    __u32 payload_off = ((__u8 *)udp - (__u8 *)data) + sizeof(struct udphdr);

    // DNS header is 12 bytes; packet too short → pass (let the kernel handle it)
    if (payload_off + 12 > pkt_len) return XDP_PASS;
    __u8 dns_hdr[12];
    if (bpf_xdp_load_bytes(ctx, payload_off, dns_hdr, 12) < 0) return XDP_PASS;

    if (dns_hdr[2] & 0x80) return XDP_PASS;  // QR=1: DNS response, not a query

    __u16 qdcount = ((__u16)dns_hdr[4] << 8) | dns_hdr[5];
    if (qdcount != 1) return XDP_PASS;  // Multi-question DNS is unusual; skip safely

    // QNAME starts immediately after the 12-byte DNS header.
    // From here, the packet is a single-question DNS query.
    // Structural failures (truncated label, label_len > 63) → DROP.
    __u32 pos = payload_off + 12;

    // Flat single loop — no nested loops, no variable-offset stack writes.
    //
    // Why flat?  The previous design had nested (outer-label × inner-char) loops.
    // The inner character loop could not be fully unrolled (llen is a runtime value),
    // leaving a real back-edge that the verifier traced for every distinct key_len
    // value (0…63 per label × 10 labels = hundreds of states) → -E2BIG.
    //
    // With #pragma unroll on a single 253-iteration loop, the compiler emits 253
    // distinct loop bodies.  Crucially, each body uses key.sni[i] with i being a
    // compile-time constant, so NO variable-offset stack write ever occurs.
    // All bpf_xdp_load_bytes calls have constant size=1, and the remaining/in-label
    // tracking uses simple scalar registers that the verifier can track trivially.
    //
    // DNS name max is 253 printable chars (RFC 1035 §2.3.4: 255 wire bytes minus
    // two length-octets for the smallest non-trivial label).
    struct sni_key key = {0};
    __u32 remaining = 0;  // Characters still to read in the current label
    __u32 key_len   = 0;  // Bytes written to key.sni so far
    __u8  valid     = 1;  // Stays 1 until we see the root label (llen==0)

    #pragma unroll
    for (int i = 0; i < 253; i++) {
        if (!valid) break;

        __u8 c;
        if (bpf_xdp_load_bytes(ctx, pos + i, &c, 1) < 0) return XDP_DROP;

        if (remaining == 0) {
            // This byte is a label length.
            if (c == 0) {
                // Root label: QNAME complete.
                valid = 0;
                break;
            }
            if ((c & 0xC0) == 0xC0) {
                // Compression pointer — stop here, treat as complete.
                valid = 0;
                break;
            }
            if (c > 63) return XDP_DROP;  // RFC 1035 hard limit: label ≤ 63 chars

            remaining = c;

            // Insert '.' separator between labels (not before the first).
            if (key_len > 0 && key_len < SNI_MAX_LEN - 1) {
                // key_len is guaranteed < SNI_MAX_LEN-1 by the check above, and i
                // is a compile-time constant so key.sni[i] is a fixed stack slot.
                // We use key_len as a runtime check, but write into key.sni[key_len]
                // ONLY if key_len < SNI_MAX_LEN-1; the verifier sees this as safe.
                // Note: this is the ONE remaining variable-offset write.  It is safe
                // because we prove key_len < SNI_MAX_LEN-1 with the if() above.
                // To keep it verifier-friendly we cap it with & (SNI_MAX_LEN-1).
                __u32 kl = key_len & (SNI_MAX_LEN - 1);
                ((char *)key.sni)[kl] = '.';
                key_len++;
            }
        } else {
            // This byte is a label character.
            if (key_len < SNI_MAX_LEN - 1) {
                __u32 kl = key_len & (SNI_MAX_LEN - 1);
                ((char *)key.sni)[kl] = (char)c;
                key_len++;
            }
            remaining--;
        }
    }

    if (key_len > 0) {
        __u32 src_ip = ip->saddr;

        __u8 *is_blocked = bpf_map_lookup_elem(&sni_blocklist_map, &key);
        if (is_blocked) {
            struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
            if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                bpf_map_delete_elem(&ip_tracker, &src_ip);
                struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                if (event) {
                    event->src_ip     = src_ip;
                    event->drop_count = 0;
                    event->reason     = IPS_BAN_REASON_MALICIOUS_SNI;
                    bpf_ringbuf_submit(event, 0);
                }
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

SEC("xdp")
// L7 (HTTP) Parser — redesigned to use bpf_xdp_load_bytes().
//
// Strategy: load the first N bytes of HTTP payload into a local stack buffer, then
// scan entirely from that buffer.  All subsequent access is plain array indexing on
// a stack object — zero packet pointer arithmetic, zero verifier complaints.
//
// Exit semantics:
//   XDP_PASS  — payload too short, or "Host:" not found in the inspected window
//   XDP_DROP  — "Host:" found and hostname matches sni_blocklist_map → ban + event
int http_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u32 pkt_len  = (__u32)(data_end - data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) return XDP_PASS;

    __u32 payload_off = ((__u8 *)tcp - (__u8 *)data) + tcp_hdr_len;

    // Bound-check directly on `avail` (the value actually fed to bpf_xdp_load_bytes
    // below), not on a derived temporary like `payload_off + 16 > pkt_len`. The
    // latter ties the [16, pkt_len] guarantee to a dead scratch register that's
    // unrelated to `avail` as far as the verifier's precision tracking is
    // concerned once a few more instructions separate them -- depending on
    // whatever else changes in this function's codegen, that relation can get
    // lost, leaving avail's proven lower bound at 0 instead of 16 and tripping
    // "invalid zero-sized read" on the helper call. Checking `avail` itself here
    // keeps the fact live on the exact register that needs it.
    if (payload_off > pkt_len) return XDP_PASS;  // guards the subtraction below
    __u32 avail = pkt_len - payload_off;
    if (avail < 16) return XDP_PASS;

    // Load up to 200 bytes of HTTP payload onto the stack.
    // After this call, ALL parsing is pure stack array access — no derived pointers.
    __u8 http_buf[200];
    __builtin_memset(http_buf, 0, sizeof(http_buf));

    __u32 load_len = (avail < sizeof(http_buf)) ? avail : sizeof(http_buf);
    if (bpf_xdp_load_bytes(ctx, payload_off, http_buf, load_len) < 0) return XDP_PASS;

    // #REQ-XXX: Port/protocol conformance -- only on this flow's first payload-bearing
    // packet, since that's the only place a genuine HTTP request line is guaranteed to
    // appear. A non-HTTP protocol tunneled over port 80 (SSH, raw C2, ...) fails this on
    // its very first byte. A large POST body or a keep-alive connection's later packets
    // are exempt via l7_seen_map -- those legitimately don't start with a verb, and
    // checking every packet the way tls_parser does would false-positive on them.
    struct flow_key l7_key = {0};
    l7_key.source_ip   = ip->saddr;
    l7_key.dest_ip     = ip->daddr;
    l7_key.source_port = tcp->source;
    l7_key.dest_port   = tcp->dest;
    l7_key.protocol    = ip->protocol;

    if (!bpf_map_lookup_elem(&l7_seen_map, &l7_key)) {
        __u8 mark = 1;
        bpf_map_update_elem(&l7_seen_map, &l7_key, &mark, BPF_ANY);

        int is_http_request =
            (http_buf[0]=='G' && http_buf[1]=='E' && http_buf[2]=='T' && http_buf[3]==' ') ||
            (http_buf[0]=='P' && http_buf[1]=='O' && http_buf[2]=='S' && http_buf[3]=='T' && http_buf[4]==' ') ||
            (http_buf[0]=='H' && http_buf[1]=='E' && http_buf[2]=='A' && http_buf[3]=='D' && http_buf[4]==' ') ||
            (http_buf[0]=='P' && http_buf[1]=='U' && http_buf[2]=='T' && http_buf[3]==' ') ||
            (http_buf[0]=='D' && http_buf[1]=='E' && http_buf[2]=='L' && http_buf[3]=='E' && http_buf[4]=='T' && http_buf[5]=='E' && http_buf[6]==' ') ||
            (http_buf[0]=='O' && http_buf[1]=='P' && http_buf[2]=='T' && http_buf[3]=='I' && http_buf[4]=='O' && http_buf[5]=='N' && http_buf[6]=='S' && http_buf[7]==' ') ||
            (http_buf[0]=='C' && http_buf[1]=='O' && http_buf[2]=='N' && http_buf[3]=='N' && http_buf[4]=='E' && http_buf[5]=='C' && http_buf[6]=='T' && http_buf[7]==' ') ||
            (http_buf[0]=='P' && http_buf[1]=='A' && http_buf[2]=='T' && http_buf[3]=='C' && http_buf[4]=='H' && http_buf[5]==' ') ||
            (http_buf[0]=='T' && http_buf[1]=='R' && http_buf[2]=='A' && http_buf[3]=='C' && http_buf[4]=='E' && http_buf[5]==' ');

        if (!is_http_request) {
            __u32 src_ip = ip->saddr;
            struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
            if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                bpf_map_delete_elem(&ip_tracker, &src_ip);
                struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                if (event) {
                    event->src_ip     = src_ip;
                    event->drop_count = 0;
                    event->reason     = IPS_BAN_REASON_PROTOCOL_MISMATCH;
                    bpf_ringbuf_submit(event, 0);
                }
            }
            return XDP_DROP;
        }
    }

    struct sni_key key = {0};
    int key_len = 0;

    // Flat single-pass scan for "Host: <value>", mirroring dns_parser's design
    // above: one fully-unrolled loop over the buffer with a small state variable
    // driving per-byte behaviour, instead of a search loop followed by (or
    // nesting) a copy loop.
    //
    // Every two-loop shape tried here first hit the same wall from a different
    // angle: a search loop that finds a delimiter and THEN feeds a separate
    // ~256-iteration copy loop forces the verifier to re-walk the copy loop once
    // per distinct way the search could exit (once per unrolled match position,
    // or once per distinct value/range the search loop's exit state carries) --
    // multiplicative, and it blew straight through the 1M instruction budget
    // (E2BIG) every time, no matter which side of the pair got unrolled. A single
    // flat loop has no second entry point for the verifier to re-explore: it's
    // additive in the number of bytes scanned, period.
    //
    // match_pos tracks how many bytes of the literal "Host: " have matched
    // consecutively (0..6); reaching 6 flips into copy mode. The pattern has no
    // internal repeats, so on a mismatch it's always correct to restart at 1 if
    // the current byte is 'H' (could be the start of a new match) or 0 otherwise
    // -- no KMP-style overlap table needed for this specific 6-byte literal.
    // Compared via if/else, not a lookup array or switch: a switch here made
    // clang emit a jump table (landed in a new .rodata datasec) instead of
    // unrolling, since a shared jump table can't be duplicated per unrolled
    // copy -- #pragma unroll silently no-opped and left a real back-edge loop
    // with runtime-tracked state, i.e. exactly the "hundreds of states -> E2BIG"
    // trap described above dns_parser's own loop. Plain comparisons unroll fine.
    //
    // No load_len check in this loop at all -- confirmed in isolation that
    // combining this two-state (search/collect) branch structure with ANY break
    // condition that reads load_len (even OR'd with a literal constant, the
    // shape that unblocks a single-state loop) makes clang silently refuse to
    // unroll again. It doesn't need one anyway: http_buf was memset to 0 before
    // the load, so every byte beyond what bpf_xdp_load_bytes actually copied in
    // is '\0' -- which the search state never matches and the collect state
    // already treats as end-of-value. The loop's own constant bound (194, well
    // inside the 200-byte http_buf) is the only bound this needs.
    int match_pos = 0;
    int collecting = 0;

    #pragma unroll
    for (int i = 0; i < 194; i++) {
        __u8 c = http_buf[i];

        if (!collecting) {
            __u8 want = (match_pos == 0) ? 'H' :
                        (match_pos == 1) ? 'o' :
                        (match_pos == 2) ? 's' :
                        (match_pos == 3) ? 't' :
                        (match_pos == 4) ? ':' : ' ';
            if (c == want) {
                match_pos++;
                if (match_pos == 6) collecting = 1;
            } else {
                match_pos = (c == 'H') ? 1 : 0;
            }
        } else {
            if (c == '\r' || c == '\n' || c == '\0') break;
            if (key_len < SNI_MAX_LEN - 1) {
                // Masked index (matches dns_parser's pattern): without it, clang's
                // unroller if-converts adjacent guarded stores into a single
                // branchless address computed with `|=`, which the verifier
                // rejects (pointer ALU ops besides bounded ADD/SUB are illegal).
                __u32 kl = key_len & (SNI_MAX_LEN - 1);
                key.sni[kl] = c;
                key_len++;
                barrier_var(key_len);
            }
        }
    }

    if (key_len > 0) {
        __u32 src_ip = ip->saddr;
        __u8 *is_blocked = bpf_map_lookup_elem(&sni_blocklist_map, &key);
        if (is_blocked) {
            struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
            if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                bpf_map_delete_elem(&ip_tracker, &src_ip);
                struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                if (event) {
                    event->src_ip     = src_ip;
                    event->drop_count = 0;
                    event->reason     = IPS_BAN_REASON_MALICIOUS_SNI;
                    bpf_ringbuf_submit(event, 0);
                }
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

SEC("xdp")
// #REQ-XXX: Port/protocol conformance -- SSH (port 22) parser.
//
// Real SSH always sends "SSH-" as the literal first 4 bytes of the connection (RFC 4253
// SS4.2's version-exchange banner, e.g. "SSH-2.0-OpenSSH_9.6"), before any key exchange or
// encryption -- unlike everything after it, which switches to the encrypted Binary Packet
// Protocol and looks like opaque bytes on the wire. So, like http_parser, this only strictly
// enforces the banner shape once per flow (via l7_seen_map) and gets out of the way after.
//
// Exit semantics:
//   XDP_PASS  -- no payload yet, or flow already validated
//   XDP_DROP  -- first payload packet doesn't start with "SSH-" -> non-SSH protocol
//                tunneled over port 22 -> ban + event
int ssh_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u32 pkt_len  = (__u32)(data_end - data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) return XDP_PASS;

    __u32 payload_off = ((__u8 *)tcp - (__u8 *)data) + tcp_hdr_len;
    if (payload_off > pkt_len) return XDP_PASS;  // guards the subtraction below
    if (pkt_len - payload_off < 4) return XDP_PASS; // no payload yet (bare ACK, etc.)

    struct flow_key l7_key = {0};
    l7_key.source_ip   = ip->saddr;
    l7_key.dest_ip     = ip->daddr;
    l7_key.source_port = tcp->source;
    l7_key.dest_port   = tcp->dest;
    l7_key.protocol    = ip->protocol;

    if (bpf_map_lookup_elem(&l7_seen_map, &l7_key)) return XDP_PASS; // already validated

    __u8 banner[4];
    if (bpf_xdp_load_bytes(ctx, payload_off, banner, 4) < 0) return XDP_PASS;

    __u8 mark = 1;
    bpf_map_update_elem(&l7_seen_map, &l7_key, &mark, BPF_ANY);

    if (banner[0] != 'S' || banner[1] != 'S' || banner[2] != 'H' || banner[3] != '-') {
        __u32 src_ip = ip->saddr;
        struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
        if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
            bpf_map_delete_elem(&ip_tracker, &src_ip);
            struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
            if (event) {
                event->src_ip     = src_ip;
                event->drop_count = 0;
                event->reason     = IPS_BAN_REASON_PROTOCOL_MISMATCH;
                bpf_ringbuf_submit(event, 0);
            }
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";