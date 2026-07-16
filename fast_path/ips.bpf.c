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

// ==============================================================================
// Ring Buffer for User-Space Events
// ==============================================================================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} ban_events SEC(".maps");

// ==============================================================================
// Runtime Configuration (.rodata)
// ==============================================================================
volatile const __u32 burst_tokens = 50;
volatile const __u32 max_tolerated_drops = 15;
volatile const __u64 refill_interval_ns = 50000000ULL; // Default (20 PPS)

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
        new_bucket.tokens = burst_tokens - 1;
        bpf_map_update_elem(&ip_tracker, &src_ip, &new_bucket, BPF_ANY);
    } else {
        // IP exists. Calculate how much time has passed
        __u64 time_passed = current_time - bucket->last_update;
        __u32 tokens_to_add = time_passed / refill_interval_ns;

        if (tokens_to_add > 0) {
            // Refill the bucket, capping it at burst_tokens
            bucket->tokens += tokens_to_add;
            if (bucket->tokens > burst_tokens) {
                bucket->tokens = burst_tokens;
            }
            // Move the timestamp forward, preserving fractional time leftovers
            bucket->last_update += (tokens_to_add * refill_interval_ns);

            // Graceful reset: forgive minor packet drops since the IP backed off and waited for tokens
            if (bucket->drop_count > 0) {
                bucket->drop_count = 0;
            }
        }

        // Check if they have tokens to spend
        if (bucket->tokens > 0) {
            bucket->tokens -= 1; // Consume 1 token
        } else {
            // Bucket is empty!
            __sync_fetch_and_add(&bucket->drop_count, 1);

            if (bucket->drop_count > max_tolerated_drops) {
                // Ultra-optimization: Instantly block the IP at pipeline stage 1!
                // We use 0 as the timestamp because BPF wall-clock time isn't trivially synced here.
                // User-space will correct this timestamp in a millisecond via the ring buffer event.
                struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
                bpf_map_update_elem(&blocklist, &src_ip, &block_data, BPF_ANY);

                // Now that it's in the blocklist, remove from the active rate limiter tracker
                bpf_map_delete_elem(&ip_tracker, &src_ip);

                // Notify User-Space for logging and updating the CSV
                struct ips_ban_event *event;
                event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                if (event) {
                    event->src_ip = src_ip;
                    event->drop_count = bucket->drop_count;
                    bpf_ringbuf_submit(event, 0);
                }
            }

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
