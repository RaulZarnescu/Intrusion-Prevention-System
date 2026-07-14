#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//----------------------------------------------------------------------------------------------------------------------

// Standard Ethernet protocol types
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define MAX_PPS 10000
#define ONE_SECOND_NS 1000000000ULL // Define 1 second in nanoseconds (1 billion)

//----------------------------------------------------------------------------------------------------------------------

struct rate_limit_data {
    __u64 timestamp; // The start of the 1-second window (in nanoseconds)
    __u32 count;     // How many packets seen in this window
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);                 // The type of map
    __type(key, __u32);                              // The Key: A 32-bit integer (IPv4 address)
    __type(value, struct rate_limit_data);           // The Value: Our rate limit structure
    __uint(max_entries, 10240);                      // Max IPs to track before the map is full
} ip_tracker SEC(".maps") ;                          // The name of our map and its special memory section

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

    // ----------------------------------------------------
    // #REQ-010: Rate Limiting per-source (PPS)
    // Evaluated first before any deep parsing/logs
    // ----------------------------------------------------
    __u64 current_time = bpf_ktime_get_ns();
    struct rate_limit_data *rl_data;

    // FIX: Assigned correctly to rl_data, not "data"
    rl_data = bpf_map_lookup_elem(&ip_tracker, &src_ip);

    if (rl_data) {
        // IP exists! Check the time window
        __u64 time_diff = current_time - rl_data->timestamp;

        if (time_diff > ONE_SECOND_NS) {
            // More than 1 second has passed. Reset the window.
            rl_data->timestamp = current_time;
            rl_data->count = 1;
        } else {
            // Still within the 1-second window. Increment the counter.
            __sync_fetch_and_add(&rl_data->count, 1);

            // --- THE DROP RULE ---
            if (rl_data->count > MAX_PPS) {
                bpf_printk("RATE LIMIT: Dropping packet from %pI4 (Count: %d)\n", &src_ip, rl_data->count);
                return XDP_DROP;
            }
        }
    } else {
        // First time seeing this IP. Initialize the struct and add to map.
        struct rate_limit_data new_data = {};
        new_data.timestamp = current_time;
        new_data.count = 1;

        bpf_map_update_elem(&ip_tracker, &src_ip, &new_data, BPF_ANY);
    }

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
        // FIX: Safe pointer arithmetic casting
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