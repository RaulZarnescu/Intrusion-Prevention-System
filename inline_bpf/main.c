#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include "ips.skel.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ips_fast_common.h"
#include "threat_intel.h"
#include "main.h"
#include "../local_analysis/sni_blocklist.h"
#include "../local_analysis/doh_resolver_blocklist.h"
#include "../local_analysis/recon_tracker.h"
#include <signal.h>

volatile sig_atomic_t keep_running = 1;
// Set by handle_sighup(), consumed once per loop iteration in main() -- forces an
// immediate threat-intel/SNI-blocklist reload without waiting out either timer, e.g.
// `kill -HUP <pid>` right after scripts/update_threat_intel.sh or update_sni_blocklist.sh.
volatile sig_atomic_t reload_requested = 0;



//------------------------------- Functions -----------------------------------------------------

void handle_signal(int sig) {
    keep_running = 0;
}

void handle_sighup(int sig) {
    reload_requested = 1;
}

static bool parse_long(const char *str, long *out_val) {
    char *endptr;
    errno = 0;

    long val = strtol(str, &endptr, 10);

    if (errno == ERANGE) { //overflow or underflow
        return false;
    }

    if (endptr == str) {
        return false;
    }
    // trailing data ex. "123abc"
    if (*endptr != '\0' && *endptr != '\n' && *endptr != '\r' && *endptr != ' ') {
        return false;
    }

    *out_val = val;
    return true;
}

// Copies an interface name from config.ini into a fixed-size ips_config field, truncating
// to fit, and logs it under the given label ("WAN"/"LAN").
static void set_interface_config_field(char *dest, size_t dest_size, const char *value, const char *label) {
    strncpy(dest, value, dest_size - 1);
    dest[dest_size - 1] = '\0';
    fprintf(stdout, "%s Interface: %s\n", label, dest);
}

// Parses a comma-separated CIDR list (e.g. "192.168.56.103/32,127.0.0.0/8") into
// config->excluded_srcs. Always resets the count first, so a config.ini value fully
// replaces whatever default was set before it, rather than appending to it.
static void parse_excluded_srcs(const char *value, struct ips_config *config) {
    config->excluded_srcs_count = 0;

    char buf[128];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok && config->excluded_srcs_count < MAX_EXCLUDED_SRCS) {
        char *slash = strchr(tok, '/');
        unsigned int prefixlen = 32;
        if (slash) {
            *slash = '\0';
            prefixlen = (unsigned int)atoi(slash + 1);
        }

        struct in_addr addr;
        if (inet_aton(tok, &addr)) {
            struct lpm_ip_key *entry = &config->excluded_srcs[config->excluded_srcs_count];
            entry->ip = addr.s_addr;
            entry->prefixlen = prefixlen;
            config->excluded_srcs_count++;
            fprintf(stdout, "Excluded source: %s/%u\n", tok, prefixlen);
        } else {
            fprintf(stderr, "[!] Invalid excluded_source_ips entry: %s\n", tok);
        }

        tok = strtok_r(NULL, ",", &saveptr);
    }
}

static void load_config(const char *filename, struct ips_config *config) {
    config->ban_duration_sec = 3600;
    config->token_bucket_max = 50;
    config->token_refill_rate = 10;
    config->max_tolerated_drops = 15;
    config->threat_intel_refresh_sec = 86400;
    config->allowlist_ttl_sec = 900;
    config->state_dump_interval_sec = 5;
    config->wan_interface[0] = '\0';
    config->lan_interface[0] = '\0';
    // Default: the router's own bridged traffic reflecting back, plus loopback -- otherwise
    // the greylist bootstrap in ips_xdp_main() would trust flows that never actually
    // crossed the monitored interface. Overridable via excluded_source_ips in config.ini.
    parse_excluded_srcs("192.168.56.103/32,10.0.2.15/32,127.0.0.0/8", config);

    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "[*] /config/config.ini not found. Using safe defaults.\n");
        return;
    }
    printf("Loading IPS with: \n");
    char line[256];
    char key[128], value[128];

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n') continue;

        if (sscanf(line, " %127[^= ] = %127s", key, value) == 2) {
            if (strcmp(key, "wan_interface") == 0) {
                set_interface_config_field(config->wan_interface, sizeof(config->wan_interface), value, "WAN");
                continue;
            }
            if (strcmp(key, "lan_interface") == 0) {
                set_interface_config_field(config->lan_interface, sizeof(config->lan_interface), value, "LAN");
                continue;
            }
            if (strcmp(key, "excluded_source_ips") == 0) {
                parse_excluded_srcs(value, config);
                continue;
            }

            long parsed_val;
            if (!parse_long(value, &parsed_val) || parsed_val < 0) {
                fprintf(stderr, "[!] Invalid or negative integer for key '%s': %s\n", key, value);
                continue;
            }

            if (strcmp(key, "ban_duration_seconds") == 0) {
                config->ban_duration_sec = (unsigned int)parsed_val;
                fprintf(stdout, "Ban Duration: %u seconds\n", config->ban_duration_sec);
            }
            else if (strcmp(key, "token_bucket_max") == 0) {
                if (parsed_val == 0) {
                    fprintf(stderr, "[!] config.ini is not valid. Max bucket tokens can not be 0. (Minimum is 1)\n");
                    fclose(file);
                    return;
                }
                config->token_bucket_max = (unsigned int)parsed_val;
                fprintf(stdout, "Bucket size: %u tokens\n", config->token_bucket_max);
            }
            else if (strcmp(key, "token_refill_rate") == 0) {
                config->token_refill_rate = (unsigned int)parsed_val;
                fprintf(stdout, "Token Refill Rate: %u tokens/sec\n", config->token_refill_rate);
            }
            else if (strcmp(key, "max_tolerated_drops") == 0) {
                config->max_tolerated_drops = (unsigned int)parsed_val;
                fprintf(stdout, "Max Tolerated Drops: %u drops\n", config->max_tolerated_drops);
            }
            else if (strcmp(key, "threat_intel_refresh_seconds") == 0) {
                config->threat_intel_refresh_sec = (unsigned int)parsed_val;
                fprintf(stdout, "Threat Intel Staleness Window: %u seconds (TTL basis only -- refresh is SIGHUP-driven)\n", config->threat_intel_refresh_sec);
            }
            else if (strcmp(key, "allowlist_ttl_seconds") == 0) {
                config->allowlist_ttl_sec = (unsigned int)parsed_val;
                fprintf(stdout, "Allowlist TTL: %u seconds\n", config->allowlist_ttl_sec);
            }
            else if (strcmp(key, "state_dump_interval_seconds") == 0) {
                config->state_dump_interval_sec = (unsigned int)parsed_val;
                fprintf(stdout, "State Dump Interval: %u seconds\n", config->state_dump_interval_sec);
            }
        }
    }
    fclose(file);

    if (config->allowlist_ttl_sec >= config->ban_duration_sec) {
        fprintf(stderr, "[!] WARNING: allowlist_ttl_seconds (%u) >= ban_duration_seconds (%u) -- "
                         "a flow could regain trust before a ban on the same IP would even expire.\n",
                config->allowlist_ttl_sec, config->ban_duration_sec);
    }

    printf("[+] Configuration loaded successfully.\n");
}

static void load_blocklist_from_csv(int dynamic_bans_fd) {
    FILE *fp = fopen(CSV_FILE, "r");
    if (!fp) {
        printf("[i] No existing blocklist.csv found. Starting fresh.\n");
        return;
    }

    char line[256];
    int count = 0;

    // Read the CSV line by line (Format: IP,Prefixlen,Timestamp,IsStatic). blocklist.csv only
    // ever holds dynamic bans (see filter_dynamic_only at the write side), so prefixlen is
    // always 32 here
    while (fgets(line, sizeof(line), fp)) {
        char ip_str[32];
        uint64_t ts;

        if (sscanf(line, "%31[^,],%*u,%lu,%*d", ip_str, &ts) == 2) {
            struct in_addr addr;
            int ok = inet_aton(ip_str, &addr);
            if (!ok) {
                fprintf(stderr, "[w] Warning, couldn't convert ip to binary: %s\n", ip_str);
                continue;
            }

            struct ips_blocklist_data val = { .ban_timestamp = ts, .is_static = 0 };

            // Push it down into the eBPF kernel map
            bpf_map_update_elem(dynamic_bans_fd, &addr.s_addr, &val, BPF_ANY);
            count++;
        }
    }
    fclose(fp);
    printf("[i] Loaded %d bans from %s\n", count, CSV_FILE);
}

typedef void (*csv_formatter_fn)(FILE *fp, const void *key, const void *value);
// Returns non-zero to include the row, 0 to skip it. NULL means "include everything".
typedef int (*csv_filter_fn)(const void *key, const void *value);

static void fmt_blocklist_row(FILE *fp, const void *key, const void *value) {
    const __u32 *k = key;
    const struct ips_blocklist_data *v = value;
    struct in_addr addr = { .s_addr = *k };
    fprintf(fp, "%s,%u,%llu,%llu\n", inet_ntoa(addr), 32U,
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

static void save_batch_map_to_csv(int fd, const char *temp_file, const char *final_file,
                            size_t key_size, size_t value_size, csv_formatter_fn fmt,
                            csv_filter_fn filter) {
    FILE *fp = fopen(temp_file, "w");
    if (!fp) {
        fprintf(stderr, "[!] Failed to open %s for writing: %s\n", temp_file, strerror(errno));
        return;
    }

    void *keys = calloc(BATCH_SIZE, key_size);
    void *values = calloc(BATCH_SIZE, value_size);
    if (!keys || !values) {
        fprintf(stderr, "[i] Could not allocate memory to save batch to csv: %s\n", strerror(errno));
        free(keys);
        free(values);
        fclose(fp);
        return;
    }

    __u32 batch_token;
    void *in_batch = NULL;          
    void *out_batch = &batch_token; 
    __u32 count;
    
    while (1) {
        int err;
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
    int rename_err = rename(temp_file, final_file);
    if (rename_err != 0) {
        fprintf(stderr, "[!] Failed to rename %s to %s: %s\n", temp_file, final_file, strerror(errno));
    }
}

static void save_blocklist_to_csv(int dynamic_bans_fd) {

    save_batch_map_to_csv(dynamic_bans_fd, CSV_TEMP, CSV_FILE,
                           sizeof(__u32), sizeof(struct ips_blocklist_data),
                           fmt_blocklist_row, NULL);
}

static void save_tracker_to_csv(int tracker_fd) {
    save_batch_map_to_csv(tracker_fd, TRACKER_CSV_TEMP, TRACKER_CSV_FILE,
                           sizeof(__u32), sizeof(struct ips_token_bucket), fmt_tracker_row, NULL);
}

static void save_simple_map_to_csv(int fd, const char *temp_file, const char *final_file) {
    save_batch_map_to_csv(fd, temp_file, final_file, sizeof(__u32), sizeof(__u8), fmt_flag_row, NULL);
}

// ------------------------------------------------------------------------------------------------------------
// Dedicated CSV Exporter for 5-Tuple Allowlist
// ------------------------------------------------------------------------------------------------------------
static void save_allowlist_to_csv(int fd, const char *temp_file, const char *final_file) {
    FILE *fp = fopen(temp_file, "w");
    if (!fp) {
        fprintf(stderr, "[!] Failed to open %s for writing: %s\n", temp_file, strerror(errno));
        return;
    }

    struct flow_key prev_key = {0};
    struct flow_key next_key;
    memset(&next_key, 0, sizeof(struct flow_key));
    struct ips_allowlist_data value;

    while (bpf_map_get_next_key(fd, &prev_key, &next_key) == 0) {
        bpf_map_lookup_elem(fd, &next_key, &value);

        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &next_key.source_ip, src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &next_key.dest_ip, dst_str, INET_ADDRSTRLEN);

        fprintf(fp, "%s,%s,%u,%u,%u,%llu\n",
                src_str, dst_str,
                ntohs(next_key.source_port), ntohs(next_key.dest_port),
                next_key.protocol, (unsigned long long)value.last_seen);

        prev_key = next_key;
    }
    
    fclose(fp);
    int rename_err = rename(temp_file, final_file);
    if (rename_err != 0) {
        fprintf(stderr, "[!] Failed to rename %s to %s: %s\n", temp_file, final_file, strerror(errno));
    }
}

void append_blocklist_entry_to_csv(__u32 ip, const struct ips_blocklist_data *block_data) {
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
        case IPS_BAN_REASON_MALFORMED_FLAGS: return "malformed TCP flags";
        default: return "unknown reason";
    }
}

static int handle_ban_event(void *ctx, void *data, size_t data_sz) {
    int dynamic_bans_fd = *(int *)ctx;
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
    int err = bpf_map_update_elem(dynamic_bans_fd, &event->src_ip, &block_data, BPF_ANY);

    if (err != 0) {
        fprintf(stderr, " [!] Bpf map was not updated (err=%d): %s\n", err, strerror(errno));
        return 1;
    }

    // O(1) append instead of an O(n) full blocklist dump
    append_blocklist_entry_to_csv(event->src_ip, &block_data);
    printf("[i] Ban appended to disk.\n");

    return 0;
}

static int load_skeleton(struct ips_bpf *skel, struct ips_config *config){
    load_config(CONFIG_FILE_PATH, config);

    if (!skel) { //check pointer
        fprintf(stderr, "[!] FATAL: Failed to open BPF skeleton.\n");
        return 1;
    }

    skel->rodata->burst_tokens = config->token_bucket_max;
    skel->rodata->max_tolerated_drops = config->max_tolerated_drops;
    if (config->token_refill_rate > 0) {
        skel->rodata->refill_interval_ns = 1000000000ULL / config->token_refill_rate;
    } else {
        skel->rodata->refill_interval_ns = 1000000000ULL;
    }
    if (ips_bpf__load(skel)) {
        fprintf(stderr, "[!] FATAL: Failed to load BPF skeleton.\n");
        ips_bpf__destroy(skel);
        return 1;
    }
    return 0;
}

// Resolves a configured interface name to its ifindex. Returns 0 (if_nametoindex's own
// "not found" value) on any failure, so callers can just check `== 0` without a separate
// error path -- fed by config, never a hardcoded guess, so an operator gets a clear error
// instead of the daemon silently attaching to the wrong NIC.
static unsigned int resolve_interface(const char *name) {
    if (!name || name[0] == '\0') {
        fprintf(stderr, "[!] FATAL: No interface configured.\n");
        return 0;
    }
    unsigned int ifindex = if_nametoindex(name);
    if (ifindex == 0) {
        fprintf(stderr, "[!] FATAL: Interface '%s' not found.\n", name);
        return 0;
    }
    printf("[i] Resolved interface %s (Index: %u)\n", name, ifindex);
    return ifindex;
}


struct xdp_attach_result {
    struct bpf_link *link; // non-NULL only when native mode succeeded
    bool skb_mode;         // true => attached via the generic/SKB-mode fallback below (link is NULL)
    bool ok;                // true if either mode succeeded
};

// Tries native XDP first (fastest, and gives us bpf_link's auto-detach-on-crash for free).
// A lot of NIC drivers don't implement native XDP at all -- USB Ethernet adapters especially
// (relevant on a Pi, where the second interface is very likely a USB adapter), but also
// several onboard ARM/embedded drivers -- so on failure this retries in generic/SKB mode,
// which every driver supports since it runs later in the stack, after skb allocation
// (slower, but functionally equivalent for our purposes).
// bpf_xdp_attach() (unlike bpf_program__attach_xdp()) isn't tied to a bpf_link, so a
// SKB-mode attach has to be torn down explicitly with bpf_xdp_detach() using the same
// flags -- see the wan_skb_mode/lan_skb_mode cleanup in main().
static struct xdp_attach_result attach_xdp(struct bpf_program *prog, unsigned int ifindex, const char *iface_name) {
    struct xdp_attach_result result = {0};

    result.link = bpf_program__attach_xdp(prog, ifindex);
    if (result.link) {
        printf("[+] XDP attached to %s (Index: %u, native mode)\n", iface_name, ifindex);
        result.ok = true;
        return result;
    }

    fprintf(stderr, "[!] Native XDP attach failed on %s (%s) -- retrying in generic/SKB mode "
                     "(expected on some USB/embedded NIC drivers without native XDP support)\n",
            iface_name, strerror(errno));

    int prog_fd = bpf_program__fd(prog);
    int err = bpf_xdp_attach((int)ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
    if (err != 0) {
        fprintf(stderr, "[!] Failed to attach XDP program to %s in either mode (err=%d): %s\n",
                iface_name, err, strerror(-err));
        return result; // ok stays false
    }

    printf("[+] XDP attached to %s (Index: %u, generic/SKB mode)\n", iface_name, ifindex);
    result.skb_mode = true;
    result.ok = true;
    return result;
}

struct network_interfaces {
    unsigned int wan_ifindex;
    unsigned int lan_ifindex;
    struct bpf_link *wan_link; // NULL if attached via SKB mode instead -- see wan_skb_mode
    struct bpf_link *lan_link; // NULL if attached via SKB mode instead -- see lan_skb_mode
    bool wan_skb_mode;
    bool lan_skb_mode;
    bool ok; // true only if both interfaces attached successfully, in either mode
};

// Resolves wan_interface/lan_interface from config and attaches ips_xdp_main to both.
// TODO: assumes both are already bridged (br0) at the OS level (netplan/systemd-networkd)
// -- this only attaches the XDP filter to each physical member, it doesn't create the
// bridge itself. Without that bridge existing, XDP_PASS on one NIC has nowhere to go and
// no traffic actually crosses the Pi.
// On any failure the relevant ifindex is 0 and/or ok is false;
// resolve_interface()/attach_xdp() already printed the specific error.

struct network_interfaces setup_network_interfaces(struct ips_bpf *skel, const struct ips_config *config) {
    struct network_interfaces ifaces = {0};

    ifaces.wan_ifindex = resolve_interface(config->wan_interface);
    ifaces.lan_ifindex = resolve_interface(config->lan_interface);
    if (ifaces.wan_ifindex == 0 || ifaces.lan_ifindex == 0) {
        return ifaces;
    }

    struct xdp_attach_result wan_result = attach_xdp(skel->progs.ips_xdp_main, ifaces.wan_ifindex, config->wan_interface);
    struct xdp_attach_result lan_result = attach_xdp(skel->progs.ips_xdp_main, ifaces.lan_ifindex, config->lan_interface);

    ifaces.wan_link = wan_result.link;
    ifaces.lan_link = lan_result.link;
    ifaces.wan_skb_mode = wan_result.skb_mode;
    ifaces.lan_skb_mode = lan_result.skb_mode;
    ifaces.ok = wan_result.ok && lan_result.ok;

    return ifaces;
}

static int pin_bpf_map(struct bpf_map *map, const char *pin_path) {
    // BPF filesystem define
    bpf_map__unpin(map, pin_path); //unpin in case we had a crash and it remained unpinned

    int err = bpf_map__pin(map, pin_path); // pin the common file
    if (err) {
        fprintf(stderr, "[!] FATAL: Failed to pin map: %d.\n", err);
        return 1;
    }
    fprintf(stderr, "[+] static_blocklist map pinned to %s.\n", pin_path);
    return 0;
}

// Pushes config->excluded_srcs (parsed from config.ini's excluded_source_ips) into the
// excluded_srcs BPF map once at startup. Unlike static_blocklist there's no periodic
// re-injection -- these are fixed deployment-topology addresses, not threat intel that
// changes over time.
static void load_excluded_srcs(int excluded_srcs_fd, const struct ips_config *config) {
    __u8 dummy = 1;
    for (unsigned int i = 0; i < config->excluded_srcs_count; i++) {
        struct lpm_ip_key key = config->excluded_srcs[i];
        if (bpf_map_update_elem(excluded_srcs_fd, &key, &dummy, BPF_ANY) != 0) {
            struct in_addr addr;
            addr.s_addr = key.ip;
            fprintf(stderr, "[!] Failed to add excluded source %s/%u: %s\n",
                    inet_ntoa(addr), key.prefixlen, strerror(errno));
        }
    }
}

static void allowlist_reconciliation(int allowlist_fd, int dynamic_bans_fd, int threat_intel_fd) {
    struct flow_key keys[BATCH_SIZE] = {0};
    struct ips_allowlist_data values[BATCH_SIZE] = {0};
    struct flow_key expired[BATCH_SIZE] = {0};

    __u32 batch_token;
    void *in_batch = NULL;
    void *out_batch = &batch_token;
    __u32 count;
    
    while (1) {
        int err;
        count = BATCH_SIZE;
        err = bpf_map_lookup_batch(allowlist_fd, in_batch, out_batch, keys, values, &count, NULL);

        __u32 expired_count = 0;
        for (__u32 i = 0; i < count; i++) {
            struct ips_blocklist_data dummy_val = {0};
            struct lpm_ip_key static_lookup_key = { .prefixlen = 32, .ip = keys[i].source_ip };

            bool is_blocked =
                bpf_map_lookup_elem(dynamic_bans_fd, &keys[i].source_ip, &dummy_val) == 0 ||
                bpf_map_lookup_elem(threat_intel_fd, &static_lookup_key, &dummy_val) == 0;

            if (is_blocked) {
                expired[expired_count++] = keys[i];
            }
        }

        if (expired_count > 0) {
            bpf_map_delete_batch(allowlist_fd, expired, &expired_count, NULL);
        }

        if (err != 0) break;
        in_batch = &batch_token;
    }
}

// Boot-monotonic seconds, matching bpf_ktime_get_ns()/1e9 used for ips_allowlist_data.last_seen
// in fast_path/ips.bpf.c -- NOT wall-clock time (see the comment on that struct).
static uint64_t monotonic_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static void age_allowlist_map(int allowlist_fd, const struct ips_config *config, uint64_t current_time) {
    struct flow_key keys[BATCH_SIZE];
    struct ips_allowlist_data values[BATCH_SIZE];
    struct flow_key expired[BATCH_SIZE];

    __u32 batch_token;
    void *in_batch = NULL;
    void *out_batch = &batch_token;
    __u32 count;

    while (1) {
        int err;
        count = BATCH_SIZE;
        err = bpf_map_lookup_batch(allowlist_fd, in_batch, out_batch, keys, values, &count, NULL);

        __u32 expired_count = 0;
        for (__u32 i = 0; i < count; i++) {
            if ((current_time - values[i].last_seen) > config->allowlist_ttl_sec) {
                expired[expired_count++] = keys[i];
            }
        }

        if (expired_count > 0) {
            bpf_map_delete_batch(allowlist_fd, expired, &expired_count, NULL);
        }

        if (err != 0) break;
        in_batch = &batch_token;
    }
}

static void age_blocklist_map(int dynamic_bans_fd, const struct ips_config *config, uint64_t current_time) {
    bool blacklist_map_changed = false;

    __u32 keys[BATCH_SIZE];
    struct ips_blocklist_data values[BATCH_SIZE];
    __u32 expired[BATCH_SIZE];

    __u32 batch_token;
    void *in_batch = NULL;
    void *out_batch = &batch_token;
    __u32 count;
    
    while (1) {
        int err;
        count = BATCH_SIZE;
        err = bpf_map_lookup_batch(dynamic_bans_fd, in_batch, out_batch, keys, values, &count, NULL);

        __u32 expired_count = 0;
        for (__u32 i = 0; i < count; i++) {
            if (values[i].ban_timestamp == 0) {
                // meaning pending fixup with current time
                // TODO: maybe an handling,
                // although idk this is usually a breaking point only if the IPS is under attack, that's why i added an if to not unban a timestamp of 0
                continue;
            }
            if ((current_time - values[i].ban_timestamp) > config->ban_duration_sec) {
                expired[expired_count++] = keys[i];
            }
        }

        if (expired_count > 0) {
            for (__u32 i = 0; i < expired_count; i++) {
                struct in_addr unban_ip;
                unban_ip.s_addr = expired[i];
                printf("[i] AGING: IP %s has served its time. Unbanned.\n", inet_ntoa(unban_ip));
            }
            __u32 del_count = expired_count;
            bpf_map_delete_batch(dynamic_bans_fd, expired, &del_count, NULL);
            blacklist_map_changed = true;
        }

        if (err != 0) break;
        in_batch = &batch_token;
    }

    if (blacklist_map_changed) {
        save_blocklist_to_csv(dynamic_bans_fd);
        printf("[i] Blocklist saved to disk.\n");
    }
}


// Re-injects threats.txt (a pure upsert -- entries still present just get their
// ban_timestamp bumped to "now") and sweeps out static entries that have gone stale.
// No internal timer: this runs once at boot and otherwise only on SIGHUP (see main()'s
// loop) -- scripts/update_threat_intel.sh refreshing the file on disk and then signaling
// the daemon is what drives this now, not a polling interval.
static void refresh_threat_intel(int threat_intel_fd, const struct ips_config *config, uint64_t current_time) {
    inject_threat_intel(THREATS_INTEL_FILE, threat_intel_fd);

    // An entry is stale once it's gone two refreshes' worth of time without being
    // re-injected -- threat_intel_refresh_sec is just the nominal cadence used for this
    // math now, not a literal polling interval.
    uint64_t static_ttl = 2ULL * config->threat_intel_refresh_sec;

    struct lpm_ip_key st_key = { .prefixlen = 32, .ip = 0 }, st_next_key;
    struct ips_blocklist_data st_value;
    struct lpm_ip_key expired_static_keys[BATCH_SIZE];
    int expired_static_count = 0;

    while (bpf_map_get_next_key(threat_intel_fd, &st_key, &st_next_key) == 0) {
        bpf_map_lookup_elem(threat_intel_fd, &st_next_key, &st_value);

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
        bpf_map_delete_elem(threat_intel_fd, &expired_static_keys[i]);
        printf("[i] STATIC AGING: %s/%u missing from threats.txt for too long. Unbanned.\n",
               inet_ntoa(unban_ip), expired_static_keys[i].prefixlen);
    }
}

static void state_dump(int tracker_fd, int allowlist_fd, int honeypot_fd, const struct ips_config *config, uint64_t current_time, uint64_t *last_state_dump) {
    if ((current_time - *last_state_dump) >= config->state_dump_interval_sec) {
        save_tracker_to_csv(tracker_fd);
        save_allowlist_to_csv(allowlist_fd, ALLOWLIST_CSV_TEMP, ALLOWLIST_CSV_FILE);
        save_simple_map_to_csv(honeypot_fd, HONEYPOT_CSV_TEMP, HONEYPOT_CSV_FILE);
        *last_state_dump = current_time;
    }
}

//------------------------------------------------------------------------------------------------------------
// MAIN
//------------------------------------------------------------------------------------------------------------
#define EXIT_SKELETON_FAILED       2 // ips_bpf__open()/ips_bpf__load() failed
#define EXIT_MAP_PIN_FAILED        3 // bpf_map__pin() on static_blocklist failed
#define EXIT_IFACE_SETUP_FAILED    4 // interface resolution or XDP attach failed for WAN and/or LAN
#define EXIT_SNIFFER_THREAD_FAILED 5 // pthread_create() failed for the WAN and/or LAN slow-path thread
#define EXIT_RINGBUF_FAILED        6 // ring_buffer__new() failed
#define EXIT_RINGBUF_POLL_FAILED   7 // ring_buffer__poll() failed inside the main event loop
#define EXIT_SAVE_DIR_FAILED       8 // mkdir() on IPS_SAVE_DIR failed for a reason other than "already exists"

// TODO: Place these defines into a dedicated file for codes. Also set the codes as per a law (like HTTP errors with those 4xx, 3xx type of errors)

int main(int argc, char **argv) {
    setbuf(stdout, NULL);   //disables buffering on stdout, writes straight in the file descriptor immediately, instead of accumulating in a buffer.
                            //stderr is already unbuffered from the lib
    struct ips_bpf *skel = ips_bpf__open();
    struct ips_config current_config;

    if (load_skeleton(skel, &current_config)) { //it also runs the config
        return EXIT_SKELETON_FAILED;
    }

    if (pin_bpf_map(skel->maps.threat_intel_map, STATIC_BLOCKLIST_PIN_PATH)) { //pin blacklist map for injection
        return EXIT_MAP_PIN_FAILED;
    }

    struct network_interfaces ifaces = setup_network_interfaces(skel, &current_config);
    if (!ifaces.ok) {
        return EXIT_IFACE_SETUP_FAILED;
    }

    fprintf(stdout, "IPS Fast-Path successfully attached to %s and %s!\n", current_config.wan_interface, current_config.lan_interface);
    fprintf(stdout, "XDP is active. Listening for traffic...\n");

    // ==============================================================================
    // #REQ-072: Bind L7 Protocol Parsers to jmp_table
    // ==============================================================================
    int jmp_table_fd = bpf_map__fd(skel->maps.jmp_table);
    
    int tls_prog_fd = bpf_program__fd(skel->progs.tls_parser);
    __u32 index = 0; // PROG_IDX_TLS_PARSER
    if (bpf_map_update_elem(jmp_table_fd, &index, &tls_prog_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to bind TLS parser to jmp_table: %s\n", strerror(errno));
    }
    
    int dns_prog_fd = bpf_program__fd(skel->progs.dns_parser);
    index = 1; // PROG_IDX_DNS_PARSER
    if (bpf_map_update_elem(jmp_table_fd, &index, &dns_prog_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to bind DNS parser to jmp_table: %s\n", strerror(errno));
    }
    
    int http_prog_fd = bpf_program__fd(skel->progs.http_parser);
    index = 2; // PROG_IDX_HTTP_PARSER
    if (bpf_map_update_elem(jmp_table_fd, &index, &http_prog_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to bind HTTP parser to jmp_table: %s\n", strerror(errno));
    }

    int tracker_fd = bpf_map__fd(skel->maps.ip_tracker);
    int dynamic_bans_fd = bpf_map__fd(skel->maps.dynamic_bans_map);               // dynamic bans (HASH)
    int threat_intel_fd = bpf_map__fd(skel->maps.threat_intel_map); // threat-intel (LPM_TRIE)
    int allowlist_fd = bpf_map__fd(skel->maps.allowlist);
    int honeypot_fd = bpf_map__fd(skel->maps.honeypot_map);
    int excluded_srcs_fd = bpf_map__fd(skel->maps.excluded_srcs);

    load_excluded_srcs(excluded_srcs_fd, &current_config);

    if (mkdir(IPS_SAVE_DIR, 0755) == 0) {
        printf("[i] Created new storage directory at %s\n", IPS_SAVE_DIR);
    } else if (errno != EEXIST) {
        fprintf(stderr, "[!] FATAL: Failed to create storage directory %s: %s\n", IPS_SAVE_DIR, strerror(errno));
        return EXIT_SAVE_DIR_FAILED;
    }

    load_blocklist_from_csv(dynamic_bans_fd);

    // --- REBUILD STATIC THREAT INTEL ---

    int sni_map_fd = bpf_map__fd(skel->maps.sni_blocklist_map);
    int doh_map_fd = bpf_map__fd(skel->maps.doh_blocklist_map);

    refresh_threat_intel(threat_intel_fd, &current_config, (uint64_t)time(NULL));
    load_sni_blocklist(SNI_BLOCKLIST_FILE, sni_map_fd);
    load_doh_resolver_blocklist(DOH_RESOLVER_BLOCKLIST_FILE, doh_map_fd);

    // Anchors the periodic re-check below so it doesn't immediately re-run at t=0.
    uint64_t last_state_dump = (uint64_t)time(NULL);

    // --- SETUP RING BUFFER ---
    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ban_events), handle_ban_event, &dynamic_bans_fd, NULL);
    if (!rb) {
        fprintf(stderr, "[!] Failed to create ban_events ring buffer\n");
        return EXIT_RINGBUF_FAILED;
    }
    
    struct recon_tracker_ctx recon_ctx = {
        .dynamic_bans_fd = dynamic_bans_fd,
        .threat_intel_fd = threat_intel_fd
    };
    if (ring_buffer__add(rb, bpf_map__fd(skel->maps.recon_events), handle_recon_event, &recon_ctx)) {
        fprintf(stderr, "[!] Failed to add recon_events to ring buffer\n");
        return EXIT_RINGBUF_FAILED;
    }
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGHUP, handle_sighup);

    printf("--- System Status: Event-Driven Mode Active ---\n");

    int exit_code = 0;

    while (keep_running) {
        int err = ring_buffer__poll(rb, 1000);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[!] Error polling ring buffer: %d\n", err);
            exit_code = EXIT_RINGBUF_POLL_FAILED;
            break;
        }
        if (err == -EINTR && !keep_running) {
            break; // SIGINT/SIGTERM interrupted the poll, exit gracefully
        }
        // Any other -EINTR (e.g. SIGHUP) falls through -- keep_running is still set, so the
        // loop just carries on into the periodic checks below instead of shutting down.

        uint64_t current_time = (uint64_t)time(NULL);
        uint64_t current_boot_time = monotonic_seconds();

        // ====================================================================
        // SIGHUP: force an immediate threat-intel + SNI blocklist reload
        // ====================================================================
        if (reload_requested) {
            reload_requested = 0;
            printf("[i] SIGHUP received -- forcing threat-intel and SNI blocklist reload.\n");
            refresh_threat_intel(threat_intel_fd, &current_config, current_time);
            load_sni_blocklist(SNI_BLOCKLIST_FILE, bpf_map__fd(skel->maps.sni_blocklist_map));
            load_doh_resolver_blocklist(DOH_RESOLVER_BLOCKLIST_FILE, bpf_map__fd(skel->maps.doh_blocklist_map));
        }

        // ====================================================================
        // ALLOWLIST/BLOCKLIST RECONCILIATION
        // ====================================================================

        allowlist_reconciliation(allowlist_fd, dynamic_bans_fd, threat_intel_fd); //any blocklisted ip found in allowlist, is deleted from allowed list

        // ====================================================================
        // AGING (Dynamic Blocklist + Allowlist Eviction)
        // ====================================================================

        age_blocklist_map(dynamic_bans_fd, &current_config, current_time); //aging logic for the blocklist map

        age_allowlist_map(allowlist_fd, &current_config, current_boot_time); //idle-flow eviction for the allowlist
        
        // ====================================================================
        // STATE DUMP: tracker/allowlist/honeypot CSVs
        // ====================================================================

        state_dump(tracker_fd, allowlist_fd, honeypot_fd, &current_config, current_time, &last_state_dump); // run per interval given by config file
        
        // Age the recon tracker (Token Regen)
        age_recon_tracker(dynamic_bans_fd);
    }

    printf("\n[i] Shutting down gracefully. Freeing resources...\n");

    ring_buffer__free(rb);
    // SKB-mode attaches aren't bpf_link-backed (see attach_xdp()), so they need the
    // matching bpf_xdp_detach() instead of bpf_link__destroy() -- calling bpf_link__destroy()
    // on a NULL link (the SKB-mode case) is a documented no-op, so no need to branch on that.
    if (ifaces.wan_skb_mode) {
        bpf_xdp_detach((int)ifaces.wan_ifindex, XDP_FLAGS_SKB_MODE, NULL);
    } else {
        bpf_link__destroy(ifaces.wan_link);
    }
    if (ifaces.lan_skb_mode) {
        bpf_xdp_detach((int)ifaces.lan_ifindex, XDP_FLAGS_SKB_MODE, NULL);
    } else {
        bpf_link__destroy(ifaces.lan_link);
    }
    ips_bpf__destroy(skel);
    return exit_code;
}