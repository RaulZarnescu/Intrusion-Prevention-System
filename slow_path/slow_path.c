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

// ------------------------------------------------------------------------------------------------------------
// SLOW-PATH: Deep Packet Inspection Thread
// TODO: this is currently an empty shell -- the two checks that used to live here (malformed
// TCP flags, and the "5 clean observations -> trust" greylist bootstrap) both now run at line
// rate in fast_path/ips.bpf.c instead. Per the spec this path is meant to do TLS ClientHello/
// SNI extraction, JA3/JA4 fingerprinting, ECH/DoH canary-domain handling, and the decision to
// mirror uncertain traffic out to OoB for deep (non-inline) analysis -- none of that is wired
// in here yet. There's a standalone Scapy-based SNI extractor prototype at
// OoB/Parsers/parsers.py, but it's not called from any live traffic path (it only runs against
// a hardcoded mock packet at the bottom of the file). IPv6 needs handling too, likely via Scapy
// here since eBPF can't cheaply do variable-length extension header parsing for the general case.
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
        (void)ip; // TODO: next slow-path feature (SNI/JA3 extraction, OoB mirroring decision) hooks in here.
    }
    close(raw_sock);
    return NULL;
}
