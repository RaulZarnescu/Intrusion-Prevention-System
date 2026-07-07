#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Standard Ethernet protocol types
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

SEC("xdp")
int fast_path_parser(struct xdp_md *ctx) {
    // 1. Get the raw memory pointers
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // ----------------------------------------------------
    // LAYER 2: Ethernet Header
    // ----------------------------------------------------
    // Cast the start of the data to an Ethernet header structure
    struct ethhdr *eth = data;

    // BOUNDS CHECK: Is the packet at least as big as an Ethernet header?
    // (eth + 1) means "jump forward by the size of one ethhdr"
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS; // Packet is too small, let the OS handle it
    }

    // We only care about IPv4 traffic for this initial step
    // bpf_htons() converts the number to "Network Byte Order"
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // ----------------------------------------------------
    // LAYER 3: IPv4 Header
    // ----------------------------------------------------
    // The IP header starts exactly where the Ethernet header ends
    struct iphdr *ip = (void *)(eth + 1);

    // BOUNDS CHECK: Is there enough data for a basic IP header?
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // An IP header can have a variable length if it contains "Options".
    // ip->ihl (Internet Header Length) tells us how many 32-bit words it takes up.
    int ip_hdr_len = ip->ihl * 4;

    // Sanity check: A valid IP header is at least 20 bytes
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    // ----------------------------------------------------
    // LAYER 4: TCP / UDP Headers
    // ----------------------------------------------------
    if (ip->protocol == IPPROTO_TCP) {
        // The TCP header starts exactly where the IP header ends
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;

        // BOUNDS CHECK: Is there enough data for the TCP header?
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }

        // We successfully parsed everything! Print it to the trace pipe.
        // %pI4 is a special eBPF formatting tag that prints an IPv4 address cleanly
        bpf_printk("[TCP] %pI4:%d -> %pI4:%d\n",
                   &ip->saddr, bpf_ntohs(tcp->source),
                   &ip->daddr, bpf_ntohs(tcp->dest));

    } else if (ip->protocol == IPPROTO_UDP) {
        // The UDP header starts exactly where the IP header ends
        struct udphdr *udp = (void *)ip + ip_hdr_len;

        // BOUNDS CHECK: Is there enough data for the UDP header?
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }

        bpf_printk("[UDP] %pI4:%d -> %pI4:%d\n",
                   &ip->saddr, bpf_ntohs(udp->source),
                   &ip->daddr, bpf_ntohs(udp->dest));
    }

    // Let the packet continue to its destination
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";