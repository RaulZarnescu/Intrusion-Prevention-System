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
#include "sni_blocklist.h"
#include "../fast_path/ips_fast_common.h"
#include "../fast_path/main.h"

// ------------------------------------------------------------------------------------------------------------
// TLS CLIENTHELLO / SNI EXTRACTION
// Byte-level walk of the record/handshake/extensions -- there's no C equivalent of Scapy's TLS
// layer (see the OoB/Parsers/parsers.py prototype this replaces), so this parses the wire format
// directly. Only handles a ClientHello that fits in a single TCP segment (the overwhelming
// majority in practice); one fragmented across segments is silently skipped -- reassembly would
// need a per-flow buffer and is a separate feature, not bolted on here.
// ------------------------------------------------------------------------------------------------------------
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_CLIENT_HELLO_TYPE      0x01
#define TLS_EXT_SERVER_NAME        0x0000
#define TLS_SNI_HOST_NAME_TYPE     0x00
#define SNI_MAX_LEN 256

// Returns 1 and fills sni (NUL-terminated) if payload is a ClientHello carrying an SNI
// extension, 0 otherwise (not a ClientHello, no SNI, malformed, or fragmented).
static int extract_sni(const unsigned char *payload, int len, char *sni, size_t sni_size) {
    if (len < 5 || payload[0] != TLS_HANDSHAKE_CONTENT_TYPE) return 0;
    int record_len = (payload[3] << 8) | payload[4];
    if (5 + record_len > len) return 0; // fragmented across TCP segments -- skip

    if (len < 9 || payload[5] != TLS_CLIENT_HELLO_TYPE) return 0;
    int handshake_len = (payload[6] << 16) | (payload[7] << 8) | payload[8];
    int handshake_end = 9 + handshake_len;
    if (handshake_end > len) return 0;

    int pos = 9 + 2 + 32; // skip client_version (2) + random (32)
    if (pos + 1 > handshake_end) return 0;

    int session_id_len = payload[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > handshake_end) return 0;

    int cipher_suites_len = (payload[pos] << 8) | payload[pos + 1];
    pos += 2 + cipher_suites_len;
    if (pos + 1 > handshake_end) return 0;

    int compression_len = payload[pos];
    pos += 1 + compression_len;
    if (pos + 2 > handshake_end) return 0;

    int extensions_len = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;
    int extensions_end = pos + extensions_len;
    if (extensions_end > handshake_end) return 0;

    while (pos + 4 <= extensions_end) {
        int ext_type = (payload[pos] << 8) | payload[pos + 1];
        int ext_len = (payload[pos + 2] << 8) | payload[pos + 3];
        pos += 4;
        if (pos + ext_len > extensions_end) return 0;

        if (ext_type == TLS_EXT_SERVER_NAME) {
            // server_name_list: list_len(2) then entries of type(1)+name_len(2)+name -- only
            // the first entry is read, which is all any real ClientHello ever sends.
            if (ext_len < 6) return 0; // list_len(2) + name_type(1) + name_len(2) + >=1 byte name
            int sp = pos + 2;
            unsigned char name_type = payload[sp];
            int name_len = (payload[sp + 1] << 8) | payload[sp + 2];
            sp += 3;
            if (name_type != TLS_SNI_HOST_NAME_TYPE || sp + name_len > pos + ext_len) return 0;
            if ((size_t)name_len >= sni_size) name_len = (int)sni_size - 1;
            memcpy(sni, &payload[sp], name_len);
            sni[name_len] = '\0';
            return 1;
        }
        pos += ext_len;
    }
    return 0;
}

// ------------------------------------------------------------------------------------------------------------
// SLOW-PATH: Deep Packet Inspection Thread
// TODO: the malformed-TCP-flags check and the "5 clean observations -> trust" greylist
// bootstrap that used to live here both now run at line rate in fast_path/ips.bpf.c instead.
// Still missing per the spec: JA3/JA4 fingerprinting alongside SNI, ECH/DoH canary-domain
// handling, and the actual decision to mirror uncertain traffic out to OoB for deep (non-inline)
// analysis -- extract_sni() above only observes and logs for now, nothing consumes it yet. IPv6
// needs handling too (deferred until after the IPv4 MVP is done).
// ------------------------------------------------------------------------------------------------------------
void *slow_path_sniffer(void *arg) { // TODO: Streamline it
    const struct sniffer_args *fds = (const struct sniffer_args *)arg;

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
        if ((unsigned char *)(ip + 1) > buffer + data_size) continue;
        if (ip->protocol != IPPROTO_TCP) continue;

        int ip_hdr_len = ip->ihl * 4;
        struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_hdr_len);
        if ((unsigned char *)(tcp + 1) > buffer + data_size) continue;

        // Only the client -> server direction carries a ClientHello.
        if (ntohs(tcp->dest) != 443) continue;

        int payload_offset = sizeof(struct ethhdr) + ip_hdr_len + tcp->doff * 4;
        if (payload_offset >= data_size) continue;

        char sni[SNI_MAX_LEN];
        if (extract_sni(buffer + payload_offset, data_size - payload_offset, sni, sizeof(sni))) {
            struct in_addr src_addr = { .s_addr = ip->saddr };
            printf("[Slow-Path] [i] TLS ClientHello SNI from %s: %s\n", inet_ntoa(src_addr), sni);

            if (sni_blocklist_contains(sni)) {
                struct ips_blocklist_data block_data = {
                    .ban_timestamp = (uint64_t)time(NULL),
                    .is_static = 0,
                };
                int err = bpf_map_update_elem(fds->blocklist_fd, &ip->saddr, &block_data, BPF_ANY);
                if (err != 0) {
                    fprintf(stderr, "[!] Slow-Path: failed to ban %s for SNI %s (err=%d): %s\n",
                            inet_ntoa(src_addr), sni, err, strerror(errno));
                } else {
                    printf("[!] Slow-Path BAN: %s matched blocklisted SNI %s\n", inet_ntoa(src_addr), sni);
                    append_blocklist_entry_to_csv(ip->saddr, &block_data);
                }
            }
            // TODO: decide "uncertain" (no match either way) and mirror to OoB here -- that
            // pipeline doesn't exist yet (see the file-level TODO above).
        }
    }
    close(raw_sock);
    return NULL;
}
