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

// ==============================================================================
// #REQ-009: Dynamic Blocklist Map (rate-limit bans, always a single /32 IP)
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // Key: Source IPv4 Address
    __type(value, struct ips_blocklist_data);
    __uint(max_entries, 65536);
} blocklist SEC(".maps");

// ==============================================================================
// #REQ-057: Static Threat-Intel Blocklist Map (CIDR-capable, injector.c owns writes)
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key);
    __type(value, struct ips_blocklist_data);
    __uint(max_entries, 262144); // Can hold 256k known malicious IPs/subnets
    __uint(map_flags, BPF_F_NO_PREALLOC); // the kernel cannot pre-allocate memory for an LPM Trie
} static_blocklist SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ban_events SEC(".maps");

volatile const __u32 burst_tokens = 50;
volatile const __u32 max_tolerated_drops = 15;
volatile const __u64 refill_interval_ns = 50000000ULL; 

//----------------------------------------------------------------------------------------------------------------------

SEC("xdp")
int fast_path_parser(struct xdp_md *ctx) {
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
    __u8 *action_flag;

    // ====================================================
    // STAGE 1: BLOCKLIST
    // After testing, decided to set it first due to writing overhead 
    // caused by incrementing packet drops on already banned IPs
    // ====================================================

    // THE PACKET LOOKUP -- dynamic (rate-limit) bans first, then static/threat-intel
    struct ips_blocklist_data *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked) {
        return XDP_DROP;
    }

    struct lpm_ip_key search_key = {};
    search_key.prefixlen = 32;     // A packet is always a single exact IP (/32) (ONLY IPv4)
    search_key.ip = ip->saddr;

    struct ips_blocklist_data *static_blocked = bpf_map_lookup_elem(&static_blocklist, &search_key);
    if (static_blocked) {
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

                if (bpf_map_update_elem(&blocklist, &src_ip, &block_data, BPF_ANY) == 0) {
                    // Now that it's in the blocklist, remove from the active rate limiter tracker
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

        // TODO: the malformed-flag check (syn+fin, null scan, fin+psh+urg) currently
        // lives in user-space slow_path_sniffer() in main.c. It's a single-packet,
        // stateless check with no reassembly needed -- a good candidate to move here
        // as its own STAGE so it drops at line rate instead of relying on a raw-socket
        // sniffer that only sees a copy after the fact and can miss packets under load.
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
    // STAGE 5: SLOW-PATH (Default)
    // ====================================================
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";