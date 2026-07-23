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

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key);
    __type(value, struct ips_blocklist_data);
    __uint(max_entries, 262144); // Can hold 256k known malicious IPs/subnets
    __uint(map_flags, BPF_F_NO_PREALLOC); // the kernel cannot pre-allocate memory for an LPM Trie
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 10240);
} honeypot_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u8);
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

    struct lpm_ip_key search_key = {};
    search_key.prefixlen = 32;     // A packet is always a single exact IP (/32) (ONLY IPv4)
    search_key.ip = ip->saddr;

    struct ips_blocklist_data *blocked = bpf_map_lookup_elem(&blocklist, &search_key);
    if (blocked) {
        return XDP_DROP;
    }

    // ====================================================
    // STAGE 2: RATE LIMITER
    // ====================================================
    __u64 current_time = bpf_ktime_get_ns();
    struct ips_token_bucket *bucket;
    struct ips_token_bucket new_bucket = {0};

    bucket = bpf_map_lookup_elem(&ip_tracker, &src_ip);
    if (!bucket) {
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
            __sync_fetch_and_add(&bucket->drop_count, 1);
            if (bucket->drop_count > max_tolerated_drops) {

                // Wrap the IP in the LPM key format (/32 for single IP)
                struct lpm_ip_key ban_key = {};
                ban_key.prefixlen = 32;
                ban_key.ip = src_ip;

                struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };

                // LPM_TRIE requires BPF_F_NO_PREALLOC, so inserting a brand-new key allocates
                // memory right here -- exactly when the system is under attack and memory is
                // under the most pressure. If that allocation fails, don't clear the tracker
                // or announce a ban that never actually landed in the map.
                if (bpf_map_update_elem(&blocklist, &ban_key, &block_data, BPF_ANY) == 0) {
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
    action_flag = bpf_map_lookup_elem(&allowlist, &current_flow);
    if (action_flag && *action_flag == 1) {
        return XDP_PASS;
    }

    // ====================================================
    // STAGE 4: HONEYPOT
    // ====================================================
    action_flag = bpf_map_lookup_elem(&honeypot_map, &src_ip);
    if (action_flag && *action_flag == 1) {
        // (Temporary PASS until DNAT logic is implemented)
        return XDP_PASS; 
    }

    // ====================================================
    // STAGE 5: SLOW-PATH (Default)
    // ====================================================
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";