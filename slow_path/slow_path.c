#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

#include "slow_path.h"
#include "../fast_path/ips_fast_common.h"
#include "../fast_path/main.h"

// ------------------------------------------------------------------------------------------------------------
// IMPROVED GREYLISTING TRACKER
// ------------------------------------------------------------------------------------------------------------
#define GREYLIST_MAX 8192

struct grey_ip {
    __u32 ip;
    int count;
    int authorized;
};

struct grey_ip greylist_tracker[GREYLIST_MAX] = {0};
// Guards greylist_tracker: with one sniffer thread per interface, the same source IP's
// traffic can legitimately reach both (a flow allowed through one NIC gets bridged and
// egresses the other), so concurrent probes into this hand-rolled table need a lock.
pthread_mutex_t greylist_lock = PTHREAD_MUTEX_INITIALIZER;

static int track_and_check_greylist(__u32 src_ip, int mark_authorized) {
    uint32_t idx = src_ip % GREYLIST_MAX;
    int result = 0;
    int slot_found = 0;

    pthread_mutex_lock(&greylist_lock);

    for (int i = 0; i < 10; i++) {
        uint32_t probe = (idx + i) % GREYLIST_MAX;

        if (greylist_tracker[probe].ip == src_ip) {
            slot_found = 1;
            if (mark_authorized) {
                greylist_tracker[probe].authorized = 1;
                result = -1;
                break;
            }
            if (greylist_tracker[probe].authorized) {
                result = -1;
                break;
            }
            greylist_tracker[probe].count += 1;
            result = greylist_tracker[probe].count;
            break;
        }

        if (greylist_tracker[probe].ip == 0) {
            slot_found = 1;
            if (mark_authorized) {
                result = -1;
                break;
            }
            greylist_tracker[probe].ip = src_ip;
            greylist_tracker[probe].count = 1;
            greylist_tracker[probe].authorized = 0;
            result = 1;
            break;
        }
    }

    pthread_mutex_unlock(&greylist_lock);

    if (!slot_found) {
        struct in_addr addr = { .s_addr = src_ip };
        fprintf(stderr, "[!] Greylist probe chain exhausted for IP %s -- all 10 probed slots "
                         "occupied by other IPs (table contention or GREYLIST_MAX too small).\n",
                inet_ntoa(addr));
    }

    return result;
}

// ------------------------------------------------------------------------------------------------------------
// SLOW-PATH: Deep Packet Inspection & Dynamic Allowlisting Thread
// TODO: this is IPv4-only (see the ETH_P_IP check below) and only does TCP-flag anomaly
// detection + the "5 clean observations -> trust" greylist bootstrap. Per the spec this
// path is also supposed to do TLS ClientHello/SNI extraction, JA3/JA4 fingerprinting, and
// ECH/DoH canary-domain handling -- none of that is wired in here yet. There's a standalone
// Scapy-based SNI extractor prototype at OoB/Parsers/parsers.py, but it's not called from
// any live traffic path (it only runs against a hardcoded mock packet at the bottom of the
// file). IPv6 needs handling too, likely via Scapy here since eBPF can't cheaply do
// variable-length extension header parsing for the general case.
// ------------------------------------------------------------------------------------------------------------
void *slow_path_sniffer(void *arg) { // TODO: Streamline it
    struct sniffer_args *fds = (struct sniffer_args *)arg;

    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        perror("Failed to open raw socket for slow-path");
        return NULL;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = fds->ifindex; // bind to the same interface the XDP program attached to
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(raw_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Failed to bind raw socket to interface");
        close(raw_sock);
        return NULL;
    }

    unsigned char buffer[65536];
    printf("[Slow-Path] Packet sniffer thread started and listening on ifindex %d...\n", fds->ifindex);

    while (1) {
        int data_size = recvfrom(raw_sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            fprintf(stderr, "[!] recvfrom failed on slow-path sniffer (ifindex %d): %s\n",
                    fds->ifindex, strerror(errno));
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

        struct flow_key current_flow = {0};
        current_flow.source_ip = ip->saddr;
        current_flow.dest_ip = ip->daddr;
        current_flow.protocol = ip->protocol;

        int ip_hdr_len = ip->ihl * 4;

        // Ignore the VM's own outbound traffic and loopback -- otherwise the sniffer
        // greylists/trusts flows that never actually crossed the monitored interface.
        __u32 src_ip = ip->saddr;
        if (src_ip == inet_addr("192.168.56.103") ||
            src_ip == inet_addr("10.0.2.15") ||
            (ntohl(src_ip) & 0xFF000000) == 0x7F000000) {
            continue;
        }

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_hdr_len);
            current_flow.source_port = tcp->source;
            current_flow.dest_port = tcp->dest;

            if ((tcp->syn && tcp->fin) ||
                     (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->urg) ||
                     (tcp->fin && tcp->psh && tcp->urg)) {

                printf("[Slow-Path] [!] MALICIOUS TCP FLAGS from %s! Banning IP.\n", inet_ntoa(*(struct in_addr *)&src_ip));

                struct ips_blocklist_data block_data;
                block_data.ban_timestamp = (uint64_t)time(NULL);
                block_data.is_static = 0;

                // blocklist is a plain HASH map keyed on the bare IP
                bpf_map_update_elem(fds->blocklist_fd, &src_ip, &block_data, BPF_ANY);
                append_blocklist_entry_to_csv(src_ip, &block_data);
                continue;
            }

            int obs_count = track_and_check_greylist(src_ip, 0);

            if (obs_count > 0 && obs_count < 5) {
                printf("[Slow-Path] [i] IP %s is clean. Observation count: %d/5\n", inet_ntoa(*(struct in_addr *)&src_ip), obs_count);
            }
            else if (obs_count == 5 || obs_count == -1) {
                if (obs_count == 5) {
                    track_and_check_greylist(src_ip, 1);
                    printf("[Slow-Path] [+] IP %s proved clean 5 times. Trusting IP!\n", inet_ntoa(*(struct in_addr *)&src_ip));

                    bpf_map_delete_elem(fds->blocklist_fd, &src_ip);
                    bpf_map_delete_elem(fds->tracker_fd, &src_ip);
                }

                struct ips_allowlist_data trust = { .last_seen = (uint64_t)time(NULL) };
                bpf_map_update_elem(fds->allowlist_fd, &current_flow, &trust, BPF_ANY);

                struct flow_key reverse_flow = current_flow;
                reverse_flow.source_ip = current_flow.dest_ip;
                reverse_flow.dest_ip = current_flow.source_ip;
                reverse_flow.source_port = current_flow.dest_port;
                reverse_flow.dest_port = current_flow.source_port;

                bpf_map_update_elem(fds->allowlist_fd, &reverse_flow, &trust, BPF_ANY);
            }
        }
        else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_hdr_len);
            current_flow.source_port = udp->source;
            current_flow.dest_port = udp->dest;

            int obs_count = track_and_check_greylist(src_ip, 0);

            if (obs_count > 0 && obs_count < 5) {
                printf("[Slow-Path] [i] IP %s is clean. Observation count: %d/5\n", inet_ntoa(*(struct in_addr *)&src_ip), obs_count);
            }
            else if (obs_count == 5 || obs_count == -1) {
                if (obs_count == 5) {
                    track_and_check_greylist(src_ip, 1);
                    printf("[Slow-Path] [+] IP %s proved clean 5 times. Trusting UDP IP!\n", inet_ntoa(*(struct in_addr *)&src_ip));

                    bpf_map_delete_elem(fds->blocklist_fd, &src_ip);
                    bpf_map_delete_elem(fds->tracker_fd, &src_ip);
                }

                struct ips_allowlist_data trust = { .last_seen = (uint64_t)time(NULL) };
                bpf_map_update_elem(fds->allowlist_fd, &current_flow, &trust, BPF_ANY);

                struct flow_key reverse_flow = current_flow;
                reverse_flow.source_ip = current_flow.dest_ip;
                reverse_flow.dest_ip = current_flow.source_ip;
                reverse_flow.source_port = current_flow.dest_port;
                reverse_flow.dest_port = current_flow.source_port;

                bpf_map_update_elem(fds->allowlist_fd, &reverse_flow, &trust, BPF_ANY);
            }
        }
    }
    close(raw_sock);
    return NULL;
}
