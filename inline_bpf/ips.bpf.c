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

volatile const __u32 burst_tokens = 50;
volatile const __u32 max_tolerated_drops = 15;
volatile const __u64 refill_interval_ns = 50000000ULL;

//----------------------------------------------------------------------------------------------------------------------

// syn+fin, null scan, fin+psh+urg -- single-packet, stateless, no reassembly needed.
static __always_inline int is_malicious_tcp_flags(const struct tcphdr *tcp) {
    return (tcp->syn && tcp->fin) ||
           (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->urg) ||
           (tcp->fin && tcp->psh && tcp->urg);
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
    __u8 *action_flag;

    // ====================================================
    // STAGE 1: BLOCKLIST
    // After testing, decided to set it first due to writing overhead 
    // caused by incrementing packet drops on already banned IPs
    // ====================================================

    // THE PACKET LOOKUP -- dynamic (rate-limit) bans first, then static/threat-intel
    struct ips_blocklist_data *blocked = bpf_map_lookup_elem(&dynamic_bans_map, &src_ip);
    if (blocked) {
        return XDP_DROP;
    }

    struct lpm_ip_key search_key = {};
    search_key.prefixlen = 32;     // A packet is always a single exact IP (/32) (ONLY IPv4)
    search_key.ip = ip->saddr;

    struct ips_blocklist_data *static_blocked = bpf_map_lookup_elem(&threat_intel_map, &search_key);
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

        if (tcp->dest == bpf_htons(443)) {
            bpf_tail_call(ctx, &jmp_table, PROG_IDX_TLS_PARSER);
        } else if (tcp->dest == bpf_htons(80)) {
            bpf_tail_call(ctx, &jmp_table, PROG_IDX_HTTP_PARSER);
        }

        // ====================================================
        // STAGE 2.5: MALFORMED TCP FLAGS
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
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((__u8 *)ip + ip_hdr_len);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        current_flow.source_port = udp->source;
        current_flow.dest_port = udp->dest;

        if (udp->dest == bpf_htons(53)) {
            bpf_tail_call(ctx, &jmp_table, PROG_IDX_DNS_PARSER);
        }
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
                if (new_count >= 5) {
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

    return XDP_PASS;
}

#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_CLIENT_HELLO_TYPE      0x01
#define TLS_EXT_SERVER_NAME        0x0000
#define TLS_SNI_HOST_NAME_TYPE     0x00

SEC("xdp/tls_parser")
int tls_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) return XDP_PASS;

    __u8 *payload = (__u8 *)tcp + tcp_hdr_len;
    
    if (payload + 5 > (__u8 *)data_end) return XDP_PASS;
    if (payload[0] != TLS_HANDSHAKE_CONTENT_TYPE) return XDP_PASS;

    if (payload + 9 > (__u8 *)data_end) return XDP_PASS;
    if (payload[5] != TLS_CLIENT_HELLO_TYPE) return XDP_PASS;

    int pos = 9 + 2 + 32;
    if (payload + pos + 1 > (__u8 *)data_end) return XDP_PASS;

    int session_id_len = payload[pos];
    pos += 1 + session_id_len;
    if (payload + pos + 2 > (__u8 *)data_end) return XDP_PASS;

    int cipher_suites_len = (payload[pos] << 8) | payload[pos + 1];
    pos += 2 + cipher_suites_len;
    if (payload + pos + 1 > (__u8 *)data_end) return XDP_PASS;

    int compression_len = payload[pos];
    pos += 1 + compression_len;
    if (payload + pos + 2 > (__u8 *)data_end) return XDP_PASS;

    int extensions_len = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        // We use bitwise mask `& 0x3FFF` (max 16KB) on pos to appease BPF verifier bounds checking on loops
        int cur_pos = pos & 0x3FFF; 
        
        if (payload + cur_pos + 4 > (__u8 *)data_end) break;
        int ext_type = (payload[cur_pos] << 8) | payload[cur_pos + 1];
        int ext_len = (payload[cur_pos + 2] << 8) | payload[cur_pos + 3];
        pos = cur_pos + 4;

        if (ext_type == TLS_EXT_SERVER_NAME) {
            if (payload + pos + 5 > (__u8 *)data_end) break;
            
            int sp = pos + 2;
            __u8 name_type = payload[sp];
            int name_len = (payload[sp + 1] << 8) | payload[sp + 2];
            sp += 3;

            if (name_type == TLS_SNI_HOST_NAME_TYPE) {
                if (name_len > 0 && name_len < SNI_MAX_LEN) {
                    if (payload + sp + name_len > (__u8 *)data_end) break;
                    
                    struct sni_key key = {0};
                    #pragma unroll
                    for (int j = 0; j < SNI_MAX_LEN; j++) {
                        if (j >= name_len) break;
                        key.sni[j] = payload[sp + j];
                    }
                    
                    __u8 *is_blocked = bpf_map_lookup_elem(&sni_blocklist_map, &key);
                    if (is_blocked) {
                        struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
                        __u32 src_ip = ip->saddr;
                        
                        if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                            bpf_map_delete_elem(&ip_tracker, &src_ip);
                            
                            struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                            if (event) {
                                event->src_ip = src_ip;
                                event->drop_count = 0;
                                event->reason = IPS_BAN_REASON_MALICIOUS_SNI;
                                bpf_ringbuf_submit(event, 0);
                            }
                        }
                        return XDP_DROP;
                    }

                    __u8 *is_doh = bpf_map_lookup_elem(&doh_blocklist_map, &key);
                    if (is_doh) {
                        struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
                        __u32 src_ip = ip->saddr;
                        
                        if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                            bpf_map_delete_elem(&ip_tracker, &src_ip);
                            
                            struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                            if (event) {
                                event->src_ip = src_ip;
                                event->drop_count = 0;
                                event->reason = IPS_BAN_REASON_MALICIOUS_SNI;
                                bpf_ringbuf_submit(event, 0);
                            }
                        }
                        return XDP_DROP;
                    }
                }
            }
            break;
        }
        
        pos += ext_len;
    }
    
    return XDP_PASS;
}

SEC("xdp/dns_parser")
int dns_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    int ip_hdr_len = ip->ihl * 4;

    struct udphdr *udp = (void *)((__u8 *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    __u8 *payload = (__u8 *)(udp + 1);
    
    // DNS Header is 12 bytes
    if (payload + 12 > (__u8 *)data_end) return XDP_PASS;
    
    // Check if it's a query (QR == 0). Byte 2 bit 7 is QR.
    if (payload[2] & 0x80) return XDP_PASS; // It's a response
    
    // Check QDCOUNT (Question Count)
    int qdcount = (payload[4] << 8) | payload[5];
    if (qdcount != 1) return XDP_PASS; // Only parse standard single queries
    
    int pos = 12;
    struct sni_key key = {0}; // Reusing sni_key struct for DNS names
    int key_len = 0;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) { // Max 10 labels
        int cur_pos = pos & 0x3FFF;
        if (payload + cur_pos + 1 > (__u8 *)data_end) break;
        
        int label_len = payload[cur_pos];
        if (label_len == 0) break; // End of QNAME
        
        // Pointers not supported in simple QNAME parser
        if (label_len >= 192) break; 
        
        if (payload + cur_pos + 1 + label_len > (__u8 *)data_end) break;
        
        // Append dot if not the first label
        if (key_len > 0 && key_len < SNI_MAX_LEN) {
            key.sni[key_len++] = '.';
        }
        
        #pragma unroll
        for (int j = 0; j < 64; j++) {
            if (j >= label_len) break;
            if (key_len < SNI_MAX_LEN - 1) {
                key.sni[key_len++] = payload[cur_pos + 1 + j];
            }
        }
        
        pos = cur_pos + 1 + label_len;
    }
    
    if (key_len > 0) {
        __u8 *is_blocked = bpf_map_lookup_elem(&sni_blocklist_map, &key);
        if (is_blocked) {
            struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
            __u32 src_ip = ip->saddr;
            
            if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                bpf_map_delete_elem(&ip_tracker, &src_ip);
                
                struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                if (event) {
                    event->src_ip = src_ip;
                    event->drop_count = 0;
                    event->reason = IPS_BAN_REASON_MALICIOUS_SNI;
                    bpf_ringbuf_submit(event, 0);
                }
            }
            return XDP_DROP;
        }
    }
    
    return XDP_PASS;
}

SEC("xdp/http_parser")
int http_parser(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    int ip_hdr_len = ip->ihl * 4;

    struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    int tcp_hdr_len = tcp->doff * 4;

    __u8 *payload = (__u8 *)tcp + tcp_hdr_len;
    if (payload >= (__u8 *)data_end) return XDP_PASS;

    int payload_len = (__u8 *)data_end - payload;
    if (payload_len < 16) return XDP_PASS; // Minimum size for HTTP header

    // Extremely basic Host: extraction for unencrypted HTTP
    struct sni_key key = {0};
    int key_len = 0;
    int found_host = 0;

    #pragma unroll
    for (int i = 0; i < 200; i++) {
        if (payload + i + 6 > (__u8 *)data_end) break;
        
        // Look for "Host: "
        if (payload[i] == 'H' && payload[i+1] == 'o' && 
            payload[i+2] == 's' && payload[i+3] == 't' && 
            payload[i+4] == ':' && payload[i+5] == ' ') {
            
            int host_start = i + 6;
            
            #pragma unroll
            for (int j = 0; j < SNI_MAX_LEN; j++) {
                if (payload + host_start + j + 1 > (__u8 *)data_end) break;
                __u8 c = payload[host_start + j];
                if (c == '\r' || c == '\n') break;
                if (key_len < SNI_MAX_LEN - 1) {
                    key.sni[key_len++] = c;
                }
            }
            found_host = 1;
            break;
        }
    }

    if (found_host && key_len > 0) {
        __u8 *is_blocked = bpf_map_lookup_elem(&sni_blocklist_map, &key);
        if (is_blocked) {
            struct ips_blocklist_data block_data = { .ban_timestamp = 0, .is_static = 0 };
            __u32 src_ip = ip->saddr;
            
            if (bpf_map_update_elem(&dynamic_bans_map, &src_ip, &block_data, BPF_ANY) == 0) {
                bpf_map_delete_elem(&ip_tracker, &src_ip);
                
                struct ips_ban_event *event = bpf_ringbuf_reserve(&ban_events, sizeof(*event), 0);
                if (event) {
                    event->src_ip = src_ip;
                    event->drop_count = 0;
                    event->reason = IPS_BAN_REASON_MALICIOUS_SNI;
                    bpf_ringbuf_submit(event, 0);
                }
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";