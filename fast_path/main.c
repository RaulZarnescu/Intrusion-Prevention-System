#include <stdio.h>
#include <unistd.h>
#include <net/if.h> 
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ips.skel.h" 
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h> 
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#include "ips_fast_common.h"
#include "threat_intel.h"

struct sniffer_args {
    int allowlist_fd;
    int blocklist_fd;
    int tracker_fd;
    int ifindex; // interface to bind the raw socket to
};

//------------------------------- Functions -----------------------------------------------------

void load_config(const char *filename, struct ips_config *config) {
    config->ban_duration_sec = 3600;
    config->token_bucket_max = 50;
    config->token_refill_rate = 10;
    config->max_tolerated_drops = 15;
    config->threat_intel_refresh_sec = 86400;

    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "[*] /config/config.ini not found. Using safe defaults.\n");
        return;
    }

    char line[256];
    char key[128], value[128];

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n') continue;

        if (sscanf(line, " %127[^= ] = %127s", key, value) == 2) {
            if (strcmp(key, "ban_duration_seconds") == 0) {
                config->ban_duration_sec = atoi(value); 
            }
            else if (strcmp(key, "token_bucket_max") == 0) {
                if (atoi(value)==0) {
                    printf("[!] config.ini is not valid. Max bucket tokens can not be 0. (Minimum is 1)");
                    return;
                }
                config->token_bucket_max = atoi(value); 
            }
            else if (strcmp(key, "token_refill_rate") == 0) {
                config->token_refill_rate = atoi(value);
            }
            else if (strcmp(key, "max_tolerated_drops") == 0) {
                config->max_tolerated_drops = atoi(value);
            }
            else if (strcmp(key, "threat_intel_refresh_seconds") == 0) {
                config->threat_intel_refresh_sec = atoi(value);
            }
        }
    }
    fclose(file);
    printf("[+] Configuration loaded successfully.\n");
}

void load_blocklist_from_csv(int blocklist_fd) {
    FILE *fp = fopen(CSV_FILE, "r");
    if (!fp) {
        printf("[i] No existing blocklist.csv found. Starting fresh.\n");
        return;
    }

    char line[256];
    int count = 0;

    // Read the CSV line by line (Format: IP,Prefixlen,Timestamp,IsStatic). blocklist.csv only
    // ever holds dynamic bans (see filter_dynamic_only at the write side), so prefixlen is
    // always 32 here -- it's kept in the format for backward compatibility with old CSVs and
    // with monitor.py, but the dynamic map itself is a plain HASH keyed on the bare IP.
    while (fgets(line, sizeof(line), fp)) {
        char ip_str[32];
        uint64_t ts;

        if (sscanf(line, "%31[^,],%*u,%lu,%*d", ip_str, &ts) == 2) {
            struct in_addr addr;
            inet_aton(ip_str, &addr); 

            struct ips_blocklist_data val = { .ban_timestamp = ts, .is_static = 0 };

            // Push it down into the eBPF kernel map
            bpf_map_update_elem(blocklist_fd, &addr.s_addr, &val, BPF_ANY);
            count++;
        }
    }
    fclose(fp);
    printf("[i] Loaded %d bans from %s\n", count, CSV_FILE);
}

// ------------------------------------------------------------------------------------------------------------
// Generic batched map -> CSV dump. Saves RAM to Disk whenever a change happens.
// `fmt` renders one key/value pair; `key_size`/`value_size` are that map's key/value type
// sizes, used to stride through the raw batch buffers since both can differ per map.
// ------------------------------------------------------------------------------------------------------------

typedef void (*csv_formatter_fn)(FILE *fp, const void *key, const void *value);
// Returns non-zero to include the row, 0 to skip it. NULL means "include everything".
typedef int (*csv_filter_fn)(const void *key, const void *value);

// blocklist is now a plain HASH map (dynamic bans only), keyed on the bare IP -- prefixlen
// is always 32 here but kept in the row format for compatibility with monitor.py.
static void fmt_blocklist_row(FILE *fp, const void *key, const void *value) {
    const __u32 *k = key;
    const struct ips_blocklist_data *v = value;
    struct in_addr addr = { .s_addr = *k };
    fprintf(fp, "%s,%u,%llu,%llu\n", inet_ntoa(addr), 32,
            (unsigned long long)v->ban_timestamp,
            (unsigned long long)v->is_static);
}

static void fmt_tracker_row(FILE *fp, const void *key, const void *value) {
    const __u32 *k = key;
    const struct ips_token_bucket *v = value;
    struct in_addr addr = { .s_addr = *k };
    fprintf(fp, "%s,%llu,%u,%u\n", inet_ntoa(addr),
            (unsigned long long)v->last_update, v->tokens, v->drop_count);
}

static void fmt_flag_row(FILE *fp, const void *key, const void *value) {
    const __u32 *k = key;
    const __u8 *v = value;
    struct in_addr addr = { .s_addr = *k };
    fprintf(fp, "%s,%u\n", inet_ntoa(addr), *v);
}

void save_batch_map_to_csv(int fd, const char *temp_file, const char *final_file,
                            size_t key_size, size_t value_size, csv_formatter_fn fmt,
                            csv_filter_fn filter) {
    FILE *fp = fopen(temp_file, "w");
    if (!fp) return;

    void *keys = malloc((size_t)BATCH_SIZE * key_size);
    void *values = malloc((size_t)BATCH_SIZE * value_size);
    if (!keys || !values) {
        free(keys);
        free(values);
        fclose(fp);
        return;
    }

    __u32 batch_token;
    void *in_batch = NULL;          
    void *out_batch = &batch_token; 
    __u32 count;
    int err = 0;

    while (1) {
        count = BATCH_SIZE; 
        err = bpf_map_lookup_batch(fd, in_batch, out_batch, keys, values, &count, NULL);

        for (__u32 i = 0; i < count; i++) {
            const void *k = (const __u8 *)keys + (size_t)i * key_size;
            const void *v = (const __u8 *)values + (size_t)i * value_size;
            if (filter && !filter(k, v)) {
                continue;
            }
            fmt(fp, k, v);
        }

        if (err != 0) break;
        in_batch = &batch_token;
    }

    free(keys);
    free(values);
    fclose(fp);
    rename(temp_file, final_file); 
}

void save_blocklist_to_csv(int blocklist_fd) {
    // No filter needed: blocklist is now structurally dynamic-only (static entries
    // live in the separate static_blocklist map), so nothing here needs excluding.
    save_batch_map_to_csv(blocklist_fd, CSV_TEMP, CSV_FILE,
                           sizeof(__u32), sizeof(struct ips_blocklist_data),
                           fmt_blocklist_row, NULL);
}

void save_tracker_to_csv(int tracker_fd) {
    save_batch_map_to_csv(tracker_fd, TRACKER_CSV_TEMP, TRACKER_CSV_FILE,
                           sizeof(__u32), sizeof(struct ips_token_bucket), fmt_tracker_row, NULL);
}

void save_simple_map_to_csv(int fd, const char *temp_file, const char *final_file) {
    save_batch_map_to_csv(fd, temp_file, final_file, sizeof(__u32), sizeof(__u8), fmt_flag_row, NULL);
}

// ------------------------------------------------------------------------------------------------------------
// Dedicated CSV Exporter for 5-Tuple Allowlist
// ------------------------------------------------------------------------------------------------------------
void save_allowlist_to_csv(int fd, const char *temp_file, const char *final_file) {
    FILE *fp = fopen(temp_file, "w");
    if (!fp) return;

    struct flow_key prev_key = {0};
    struct flow_key next_key;
    __u8 value;

    while (bpf_map_get_next_key(fd, &prev_key, &next_key) == 0) {
        bpf_map_lookup_elem(fd, &next_key, &value);
        
        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &next_key.source_ip, src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &next_key.dest_ip, dst_str, INET_ADDRSTRLEN);
        
        fprintf(fp, "%s,%s,%u,%u,%u\n", 
                src_str, dst_str, 
                ntohs(next_key.source_port), ntohs(next_key.dest_port), 
                next_key.protocol);
        
        prev_key = next_key;
    }
    
    fclose(fp);
    rename(temp_file, final_file);
}

// A new ban only ever adds one entry, so persisting it doesn't need to read the whole
// map back and rewrite the whole file (O(n) per ban -> O(n^2) for n bans in a burst).
// Just append the one line. The eBPF map stays the source of truth; save_blocklist_to_csv()
// (driven by aging, when a ban expires) still does the full rewrite, which reconciles/
// compacts the file since removing a line from a flat file can't be done incrementally.
static void append_blocklist_entry_to_csv(__u32 ip, const struct ips_blocklist_data *block_data) {
    FILE *fp = fopen(CSV_FILE, "a");
    if (!fp) {
        fprintf(stderr, "[!] Failed to open %s for appending.\n", CSV_FILE);
        return;
    }
    fmt_blocklist_row(fp, &ip, block_data);
    fclose(fp);
}

//------------------------------------------------------------------------------------------------------------
// Ring Buffer Callback
//------------------------------------------------------------------------------------------------------------
static const char *ban_reason_to_str(__u32 reason) {
    switch (reason) {
        case IPS_BAN_REASON_RATE_LIMIT: return "rate limit exceeded";
        default: return "unknown reason";
    }
}

int handle_ban_event(void *ctx, void *data, size_t data_sz) {
    int blocklist_fd = *(int *)ctx;
    const struct ips_ban_event *event = data;

    struct in_addr ip_addr;
    ip_addr.s_addr = event->src_ip;

    printf("[!] BAN: %s (%s) Drops: %u\n",
           inet_ntoa(ip_addr), ban_reason_to_str(event->reason), event->drop_count);

    // Prepare the real-time data
    struct ips_blocklist_data block_data;
    block_data.ban_timestamp = (uint64_t)time(NULL);
    block_data.is_static = 0;

    // blocklist is a plain HASH map keyed on the bare IP
    bpf_map_update_elem(blocklist_fd, &event->src_ip, &block_data, BPF_ANY);

    // O(1) append instead of an O(n) full blocklist dump
    append_blocklist_entry_to_csv(event->src_ip, &block_data);
    printf("[i] Ban appended to disk.\n");

    return 0;
}

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

int track_and_check_greylist(__u32 src_ip, int mark_authorized) {
    uint32_t idx = src_ip % GREYLIST_MAX;
    
    for (int i = 0; i < 10; i++) {
        uint32_t probe = (idx + i) % GREYLIST_MAX;
        
        if (greylist_tracker[probe].ip == src_ip) {
            if (mark_authorized) {
                greylist_tracker[probe].authorized = 1;
                return -1;
            }
            if (greylist_tracker[probe].authorized) {
                return -1; 
            }
            greylist_tracker[probe].count += 1;
            return greylist_tracker[probe].count;
        }
        
        if (greylist_tracker[probe].ip == 0) {
            if (mark_authorized) return -1;
            greylist_tracker[probe].ip = src_ip;
            greylist_tracker[probe].count = 1;
            greylist_tracker[probe].authorized = 0;
            return 1;
        }
    }
    return 0;
}

// ------------------------------------------------------------------------------------------------------------
// SLOW-PATH: Deep Packet Inspection & Dynamic Allowlisting Thread
// ------------------------------------------------------------------------------------------------------------
void *slow_path_sniffer(void *arg) {
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
    printf("[Slow-Path] Packet sniffer thread started and listening...\n");

    while (1) {
        int data_size = recvfrom(raw_sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) continue;

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

                __u8 trust_flag = 1;
                bpf_map_update_elem(fds->allowlist_fd, &current_flow, &trust_flag, BPF_ANY);

                struct flow_key reverse_flow = current_flow;
                reverse_flow.source_ip = current_flow.dest_ip;
                reverse_flow.dest_ip = current_flow.source_ip;
                reverse_flow.source_port = current_flow.dest_port;
                reverse_flow.dest_port = current_flow.source_port;

                bpf_map_update_elem(fds->allowlist_fd, &reverse_flow, &trust_flag, BPF_ANY);
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

                __u8 trust_flag = 1;
                bpf_map_update_elem(fds->allowlist_fd, &current_flow, &trust_flag, BPF_ANY);

                struct flow_key reverse_flow = current_flow;
                reverse_flow.source_ip = current_flow.dest_ip;
                reverse_flow.dest_ip = current_flow.source_ip;
                reverse_flow.source_port = current_flow.dest_port;
                reverse_flow.dest_port = current_flow.source_port;

                bpf_map_update_elem(fds->allowlist_fd, &reverse_flow, &trust_flag, BPF_ANY);
            }
        }
    }
    close(raw_sock);
    return NULL;
}

//------------------------------------------------------------------------------------------------------------
// MAIN
//------------------------------------------------------------------------------------------------------------
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    int err;

    struct ips_config current_config;
    load_config(CONFIG_FILE_PATH, &current_config);

    printf("Starting IPS with: \n");
    printf("Ban Duration: %u seconds\n", current_config.ban_duration_sec);
    printf("Max Tolerated Drops: %u drops\n", current_config.max_tolerated_drops);
    printf("Bucket size: %u tokens\n", current_config.token_bucket_max);
    printf("Token Refill Rate: %u tokens/sec \n", current_config.token_refill_rate);
    
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "[!] Failed to increase RLIMIT_MEMLOCK!\n");
        return 1;
    }

    struct ips_bpf *skel = ips_bpf__open();
    if (!skel) {
        fprintf(stderr, "[!] FATAL: Failed to open BPF skeleton.\n");
        return 1;
    }

    skel->rodata->burst_tokens = current_config.token_bucket_max;
    skel->rodata->max_tolerated_drops = current_config.max_tolerated_drops;
    if (current_config.token_refill_rate > 0) {
        skel->rodata->refill_interval_ns = 1000000000ULL / current_config.token_refill_rate;
    } else {
        skel->rodata->refill_interval_ns = 1000000000ULL; 
    }

    err = ips_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[!] FATAL: Failed to load BPF skeleton.\n");
        ips_bpf__destroy(skel);
        return 1;
    }    

    // BPF filesystem define
    // Only static_blocklist needs a pin: it's the one ips_injector reaches from outside
    // this process. Nothing external touches the dynamic blocklist map.

    bpf_map__unpin(skel->maps.static_blocklist, STATIC_BLOCKLIST_PIN_PATH); //unpin in case we had a crash and it remained unpinned

    err = bpf_map__pin(skel->maps.static_blocklist, STATIC_BLOCKLIST_PIN_PATH);
    if (err) {
        fprintf(stderr, "[!] FATAL: Failed to pin static_blocklist map: %d.\n", err);
        return 1;
    }

    fprintf(stderr, "[+] static_blocklist map pinned to %s.\n", STATIC_BLOCKLIST_PIN_PATH);

    int ifindex = 0;
    const char *iface_name = NULL;

    if ((ifindex = if_nametoindex("enp0s8")) > 0) { // VirtualBox Host-Only adapter
        iface_name = "enp0s8";
    }
    else if ((ifindex = if_nametoindex("enp0s3")) > 0) {
        iface_name = "enp0s3";
    }
    else if ((ifindex = if_nametoindex("enp2s0")) > 0) {
        iface_name = "enp2s0";
    }

    if (ifindex <= 0) {
        fprintf(stderr, "[!] Error: No known network interfaces found!\n");
        return 1;
    }

    printf("[i] Using interface %s (Index: %d)\n", iface_name, ifindex);

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.fast_path_parser, ifindex);
    if (!link) {
        fprintf(stderr, "[!] Failed to attach XDP program to %s\n", iface_name);
        return 1;
    }

    printf("IPS Fast-Path successfully attached to %s!\n", iface_name);
    printf("XDP is active. Listening for traffic...\n");
    printf("Monitoring traffic... Press Ctrl+C to stop.\n\n");

    int tracker_fd = bpf_map__fd(skel->maps.ip_tracker);
    int blocklist_fd = bpf_map__fd(skel->maps.blocklist);               // dynamic bans (HASH)
    int static_blocklist_fd = bpf_map__fd(skel->maps.static_blocklist); // threat-intel (LPM_TRIE)
    int allowlist_fd = bpf_map__fd(skel->maps.allowlist);
    int honeypot_fd = bpf_map__fd(skel->maps.honeypot_map);

    if (mkdir(IPS_SAVE_DIR, 0755) == 0) {
        printf("[i] Created new storage directory at %s\n", IPS_SAVE_DIR);
    }

    struct sniffer_args args;
    args.allowlist_fd = allowlist_fd;
    args.blocklist_fd = blocklist_fd;
    args.tracker_fd = tracker_fd;
    args.ifindex = ifindex;

    pthread_t sniffer_thread;
    if (pthread_create(&sniffer_thread, NULL, slow_path_sniffer, &args) != 0) {
        fprintf(stderr, "Failed to create slow-path thread\n");
        return 1;
    }

    load_blocklist_from_csv(blocklist_fd);

    // --- REBUILD STATIC THREAT INTEL ---
    // static_blocklist is fresh on every restart (the pin just points at whatever
    // ips_bpf__load() created this run), and it's never written to blocklist.csv, so
    // threats.txt is its only durable source. Re-run the injection here instead of requiring
    // an operator to rerun ips_injector by hand after every restart; ips_injector remains
    // available for hot-updating the live map while the daemon keeps running.
    inject_threat_intel(THREATS_INTEL_FILE, static_blocklist_fd);
    // Anchors the periodic re-check below so it doesn't immediately re-run at t=0.
    uint64_t last_static_refresh = (uint64_t)time(NULL);

    // --- SETUP RING BUFFER ---
    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ban_events), handle_ban_event, &blocklist_fd, NULL);
    if (!rb) {
        fprintf(stderr, "[!] Failed to create ring buffer\n");
        return 1;
    }

    printf("--- System Status: Event-Driven Mode Active ---\n");

    while (1) {
        int err = ring_buffer__poll(rb, 1000);
        if (err < 0) {
            fprintf(stderr, "[!] Error polling ring buffer: %d\n", err);
            break;
        }

        bool blacklist_map_changed = 0;

        uint64_t current_time = (uint64_t)time(NULL);

        // ====================================================================
        // ALLOWLIST/BLOCKLIST RECONCILIATION
        // ====================================================================
        // A flow can get allowlisted by the slow-path sniffer and later have its
        // source IP banned (dynamic or static) through an unrelated path. Purge any
        // allowlist entry whose source IP is now blocked so the fast-path's
        // allowlist check (STAGE 3) can't bypass a ban made after the fact.
        struct flow_key al_prev = {0}, al_next;
        struct flow_key expired_allowlist_flows[BATCH_SIZE];
        int allowlist_purge_count = 0;

        while (bpf_map_get_next_key(allowlist_fd, &al_prev, &al_next) == 0) {
            struct ips_blocklist_data dummy_val;
            struct lpm_ip_key static_lookup_key = { .prefixlen = 32, .ip = al_next.source_ip };

            bool is_blocked =
                bpf_map_lookup_elem(blocklist_fd, &al_next.source_ip, &dummy_val) == 0 ||
                bpf_map_lookup_elem(static_blocklist_fd, &static_lookup_key, &dummy_val) == 0;

            if (is_blocked && allowlist_purge_count < BATCH_SIZE) {
                expired_allowlist_flows[allowlist_purge_count++] = al_next;
            }
            al_prev = al_next;
        }

        for (int i = 0; i < allowlist_purge_count; i++) {
            bpf_map_delete_elem(allowlist_fd, &expired_allowlist_flows[i]);
        }

        // ====================================================================
        // AGING (Dynamic Blocklist Eviction)
        // ====================================================================
        // blocklist is now the dynamic-only HASH map, so this walk never has to wade
        // through threat-intel entries just to skip them -- every key it visits is
        // always eligible for aging.

        // bl_key starts at 0 as a "doesn't exist yet" sentinel, same convention a HASH
        // map's first bpf_map_get_next_key() call expects. Deletions are collected and
        // applied only after the walk finishes, since deleting mid-walk is fragile.
        __u32 bl_key = 0, bl_next_key;
        struct ips_blocklist_data bl_value;

        __u32 expired_keys[BATCH_SIZE];
        int expired_count = 0;

        while (bpf_map_get_next_key(blocklist_fd, &bl_key, &bl_next_key) == 0) {
            bpf_map_lookup_elem(blocklist_fd, &bl_next_key, &bl_value);

            if (bl_value.ban_timestamp == 0) {
                // meaning pending fixup with current time
                // TODO: maybe an handling,
                // although idk this is usually a breaking point only if the IPS is under attack, that's why i added an if to not unban a timestamp of 0
            }
            else if ((current_time - bl_value.ban_timestamp) > current_config.ban_duration_sec) {
                if (expired_count < BATCH_SIZE) {
                    expired_keys[expired_count++] = bl_next_key;
                }
            }
            bl_key = bl_next_key;
        }

        for (int i = 0; i < expired_count; i++) {
            struct in_addr unban_ip;
            unban_ip.s_addr = expired_keys[i];

            bpf_map_delete_elem(blocklist_fd, &expired_keys[i]);
            printf("[i] AGING: IP %s has served its time. Unbanned.\n", inet_ntoa(unban_ip));

            blacklist_map_changed = 1; 
        }

        if (blacklist_map_changed) {
            save_blocklist_to_csv(blocklist_fd);
            printf("[i] Blocklist saved to disk.\n");
        }
        // ====================================================================
        // STATIC THREAT INTEL: periodic re-injection + TTL sweep
        // ====================================================================
        // Runs at most once per threat_intel_refresh_sec (default 24h), so this is the
        // only place static_blocklist gets walked in full -- keeping it off the 1/sec
        // dynamic aging path is the whole point of having split the two maps.
        if ((current_time - last_static_refresh) >= current_config.threat_intel_refresh_sec) {
            // Re-run threats.txt: a pure upsert, so entries still present just get their
            // ban_timestamp refreshed to "now". Entries no longer in the file simply stop
            // being refreshed and fall behind, which is what the sweep below acts on.
            inject_threat_intel(THREATS_INTEL_FILE, static_blocklist_fd);

            // Entries that missed a refresh cycle (delisted from the feed, or the feed/
            // download failed) age out here instead of staying blocked forever. The TTL is
            // a multiple of the refresh interval so one missed/late pull doesn't unban
            // something that's still legitimately on the list.
            uint64_t static_ttl = 2ULL * current_config.threat_intel_refresh_sec;

            struct lpm_ip_key st_key = { .prefixlen = 32, .ip = 0 }, st_next_key;
            struct ips_blocklist_data st_value;
            struct lpm_ip_key expired_static_keys[BATCH_SIZE];
            int expired_static_count = 0;

            while (bpf_map_get_next_key(static_blocklist_fd, &st_key, &st_next_key) == 0) {
                bpf_map_lookup_elem(static_blocklist_fd, &st_next_key, &st_value);

                if (st_value.ban_timestamp != 0 &&
                    (current_time - st_value.ban_timestamp) > static_ttl &&
                    expired_static_count < BATCH_SIZE) {
                    expired_static_keys[expired_static_count++] = st_next_key;
                }
                st_key = st_next_key;
            }

            for (int i = 0; i < expired_static_count; i++) {
                struct in_addr unban_ip;
                unban_ip.s_addr = expired_static_keys[i].ip;
                bpf_map_delete_elem(static_blocklist_fd, &expired_static_keys[i]);
                printf("[i] STATIC AGING: %s/%u missing from threats.txt for too long. Unbanned.\n",
                       inet_ntoa(unban_ip), expired_static_keys[i].prefixlen);
            }

            last_static_refresh = current_time;
        }

        // Dump the other maps for the monitoring TUI. Unlike the blocklist, these maps
        // (especially ip_tracker) can change on nearly every packet with no ring-buffer
        // event to key off of, so there's no cheap way to know "did it change" from
        // user-space. Just dump them every poll iteration instead -- the ring buffer poll
        // above already bounds this loop to ~1/sec when idle, same cadence as the aging check.
        save_tracker_to_csv(tracker_fd);
        save_allowlist_to_csv(allowlist_fd, ALLOWLIST_CSV_TEMP, ALLOWLIST_CSV_FILE);
        save_simple_map_to_csv(honeypot_fd, HONEYPOT_CSV_TEMP, HONEYPOT_CSV_FILE);
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    ips_bpf__destroy(skel);
    return 0;
}