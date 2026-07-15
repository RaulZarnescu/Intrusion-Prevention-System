#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//----------------------------------------------------------------------------------------------------------------------

#include "ips_fast_common.h"

// ==============================================================================
// Hash Map Pachet
// ==============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_HASH);                 // The type of map
    __type(key, __u32);                              // The Key: A 32-bit integer (IPv4 address)
    __type(value, struct ips_token_bucket);           // The Value: Our rate limit structure
    __uint(max_entries, 10240);                      // Max IPs to track before the map is full
} ip_tracker SEC(".maps") ;                          // The name of our map and its special memory section

// ==============================================================================
// #REQ-009 & #REQ-057: Static/Dynamic Blocklist Map
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // Key: Source IPv4 Address
    __type(value, struct ips_blocklist_data);
    __uint(max_entries, 65536); // Can hold 65k known malicious IPs
} blocklist SEC(".maps");

// ==============================================================================
// #REQ-024: Honeypot Redirect Map
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // Key: Source IPv4 Address
    __type(value, __u8);  // Value: Boolean flag (1 = Redirect to Honeypot)
    __uint(max_entries, 10240);
} honeypot_map SEC(".maps");

// ==============================================================================
// #REQ-007: Dynamic Flow Offload (Allowlist)
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // Auto-evicts old entries to save memory
    __type(key, __u32);   // Key: Source IPv4 Address
    __type(value, __u8);  // Value: Boolean flag (1 = Trusted Flow)
    __uint(max_entries, 131072); // Can track ~131k simultaneous trusted connections
} allowlist SEC(".maps");

//----------------------------------------------------------------------------------------------------------------------

SEC("xdp")
int fast_path_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // ----------------------------------------------------
    // LAYER 2: Ethernet Header
    // ----------------------------------------------------
    struct ethhdr *eth = data;

    // BOUNDS CHECK: Is the packet at least as big as an Ethernet header?
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS; // Packet is too small, let the OS handle it
    }

    // We only care about IPv4 traffic for this initial step
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // ----------------------------------------------------
    // LAYER 3: IPv4 Header
    // ----------------------------------------------------
    struct iphdr *ip = (void *)(eth + 1);

    // BOUNDS CHECK: Is there enough data for a basic IP header?
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Grab the source IP from the packet immediately for Rate Limiting
    __u32 src_ip = ip->saddr;
    __u8 *action_flag;

    // ----------------------------------------------------
    // PIPELINE STAGE 1
    // Blocklist (#REQ-009)
    // After testing, decided to set it first due to writing overhead caused by incrementing pachet drops on already banned ip's
    // ----------------------------------------------------

    struct ips_blocklist_data *block_data;
    block_data = bpf_map_lookup_elem(&blocklist, &src_ip);

    if (block_data) {
        // If the lookup doesn't return NULL, the IP is in the map.
        // We don't even need to check the timestamp here in the kernel.
        // If it's in the map, it's banned. The user-space handles the aging!
        return XDP_DROP;
    }

    // ----------------------------------------------------
    // PIPELINE STAGE 2
    // #REQ-010: Rate Limiting per-source (PPS)
    // ----------------------------------------------------

    __u64 current_time = bpf_ktime_get_ns();
    struct ips_token_bucket *bucket;
    struct ips_token_bucket new_bucket = {0};

    bucket = bpf_map_lookup_elem(&ip_tracker, &src_ip);
    if (!bucket) {
        // First time seeing this IP. Give them a full bucket minus 1 for this packet.
        new_bucket.last_update = current_time;
        new_bucket.tokens = BURST_TOKENS - 1;
        bpf_map_update_elem(&ip_tracker, &src_ip, &new_bucket, BPF_ANY);
    } else {
        // IP exists. Calculate how much time has passed
        __u64 time_passed = current_time - bucket->last_update;
        __u32 tokens_to_add = time_passed / REFILL_INTERVAL_NS;

        if (tokens_to_add > 0) {
            // Refill the bucket, capping it at BURST_TOKENS
            bucket->tokens += tokens_to_add;
            if (bucket->tokens > BURST_TOKENS) {
                bucket->tokens = BURST_TOKENS;
            }
            // Move the timestamp forward, preserving fractional time leftovers
            bucket->last_update += (tokens_to_add * REFILL_INTERVAL_NS);
        }

        // Check if they have tokens to spend
        if (bucket->tokens > 0) {
            bucket->tokens -= 1; // Consume 1 token
        } else {
            // Bucket is empty!
            __sync_fetch_and_add(&bucket->drop_count, 1);
            return XDP_DROP;
        }
    }

    // ----------------------------------------------------
    // PIPELINE STAGE 3: Marcaj Honeypot (#REQ-024)
    // ----------------------------------------------------

    action_flag = bpf_map_lookup_elem(&honeypot_map, &src_ip);
    if (action_flag && *action_flag == 1) {
        // bpf_printk("HONEYPOT: Redirecting attacker %pI4\n", &src_ip);
        // TODO: Implement actual MAC/IP manipulation for DNAT here later
        return XDP_PASS; // (Temporary PASS until we write the DNAT logic)
    }

    // ----------------------------------------------------
    // PIPELINE STAGE 4: Dynamic Flow Offload / Allowlist (#REQ-007)
    // ----------------------------------------------------
    action_flag = bpf_map_lookup_elem(&allowlist, &src_ip);
    if (action_flag && *action_flag == 1) {
        // Traffic is known and trusted by the Slow-Path.
        return XDP_PASS;
    }

    // ----------------------------------------------------
    // PIPELINE STAGE 5: Implicit PASS (To Slow-Path)
    // ----------------------------------------------------
    // If it survived the rate limiter, isn't blocked, isn't a honeypot target,
    // and isn't offloaded yet, it gets passed to the OS/Slow-Path for L7 inspection.


    // ----------------------------------------------------
    // LAYER 4: TCP / UDP Headers
    // ----------------------------------------------------
    // Calculate full IP header length (including options)
    int ip_hdr_len = ip->ihl * 4;

    // Sanity check: A valid IP header is at least 20 bytes
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    // Make sure we don't read past the variable-length IP options
    if ((void *)((__u8 *)ip + ip_hdr_len) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);

        // BOUNDS CHECK: Is there enough data for the TCP header?
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }

        // Log the TCP packet to trace_pipe
        bpf_printk("[TCP] %pI4:%d -> %pI4:%d\n",
                   &ip->saddr, bpf_ntohs(tcp->source),
                   &ip->daddr, bpf_ntohs(tcp->dest));
    }

    // If we made it here, the packet is safe to pass!
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
