// ==============================================================================
// #REQ-073: Network Reconnaissance Tracking (Token Bucket)
// ==============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include "recon_tracker.h"
#include "../inline_bpf/ips_fast_common.h"

#define MAX_TRACKED_IPS 10240
#define STARTING_TOKENS 40
#define MAX_TOKENS 40
#define REGEN_SECONDS 300 // +1 token every 5 minutes
#define BAN_SUBNET_THRESHOLD 3      // distinct banned hosts in one /24 that trigger escalation
#define SUBNET_WINDOW_SECONDS 3600  // bans older than this no longer count towards escalation

// Slow-scan memory. The token bucket above only refills after a 300 s gap and is charged per
// probe, so a scan slower than one probe per 5 minutes is never banned (measured 2026-11-11).
// This second detector ignores speed: it remembers the distinct destination ports a source has
// touched over a long window and bans when that number passes a threshold.
// Both values can be overridden with IPS_SLOW_PORTS / IPS_SLOW_WINDOW (seconds) for short tests.
#define SLOW_PORTS_DEFAULT 100      // distinct TCP destination ports per source within the window
#define SLOW_WINDOW_DEFAULT 86400   // 24 h
#define SLOW_SLOTS 128              // ports remembered per source (must exceed the threshold)
#define MAX_SLOW_SOURCES 4096

struct recon_state {
    uint32_t src_ip;
    int tokens;
    time_t last_update;
    uint16_t recent_ports[16];
    int port_idx;
    uint32_t recent_hosts[16]; // ICMP echo destinations seen recently (network byte order)
    int host_idx;
};

// Subnet tracking for escalation
// One entry per /24: a 256-bit bitmap of the host octets banned in the current window. Escalation
// counts DISTINCT hosts, not bans: one noisy host that is banned again and again is one host.
struct subnet_state {
    uint32_t subnet;       // network byte order
    uint64_t hosts[4];     // bit h set = host .h of this /24 was banned in the window
    time_t window_start;   // time of the first ban counted in this window
    int escalated;         // /24 already blocked
};

static struct recon_state trackers[MAX_TRACKED_IPS];
static int tracker_count = 0;

struct slow_state {
    uint32_t src_ip;
    int used;
    struct { uint16_t port; time_t ts; } e[SLOW_SLOTS];
};
static struct slow_state slow_tab[MAX_SLOW_SOURCES];
static int slow_count = 0;
static int slow_ports_thr = 0;
static long slow_window = 0;

static struct subnet_state subnets[1024];
static int subnet_count = 0;

static int is_critical_port(uint16_t port) {
    switch (port) {
        case 21: case 22: case 23: case 25:
        case 139: case 445: case 3389: case 5985: case 5986:
            return 1;
        default: return 0;
    }
}

static struct recon_state *get_or_create_tracker(uint32_t src_ip) {
    for (int i = 0; i < tracker_count; i++) {
        if (trackers[i].src_ip == src_ip) {
            return &trackers[i];
        }
    }
    if (tracker_count < MAX_TRACKED_IPS) {
        struct recon_state *s = &trackers[tracker_count++];
        s->src_ip = src_ip;
        s->tokens = STARTING_TOKENS;
        s->last_update = time(NULL);
        s->port_idx = 0;
        memset(s->recent_ports, 0, sizeof(s->recent_ports));
        s->host_idx = 0;
        memset(s->recent_hosts, 0, sizeof(s->recent_hosts));
        return s;
    }
    return NULL;
}

static void slow_init(void) {
    if (slow_ports_thr) return;
    const char *p = getenv("IPS_SLOW_PORTS"), *w = getenv("IPS_SLOW_WINDOW");
    slow_ports_thr = p ? atoi(p) : SLOW_PORTS_DEFAULT;
    slow_window = w ? atol(w) : SLOW_WINDOW_DEFAULT;
    if (slow_ports_thr < 2 || slow_ports_thr >= SLOW_SLOTS) slow_ports_thr = SLOW_PORTS_DEFAULT;
    if (slow_window < 1) slow_window = SLOW_WINDOW_DEFAULT;
    printf("[i] Slow-scan memory: ban at %d distinct ports within %ld s\n", slow_ports_thr, slow_window);
}

// Records one TCP destination port for src_ip. Returns the number of distinct ports remembered
// for that source inside the window (after adding this one), or 0 if the table is full.
static int slow_record(uint32_t src_ip, uint16_t port, time_t now) {
    slow_init();
    struct slow_state *st = NULL;
    for (int i = 0; i < slow_count; i++)
        if (slow_tab[i].src_ip == src_ip) { st = &slow_tab[i]; break; }
    if (!st) {
        if (slow_count >= MAX_SLOW_SOURCES) return 0;
        st = &slow_tab[slow_count++];
        memset(st, 0, sizeof(*st));
        st->src_ip = src_ip;
    }
    int found = 0;
    for (int i = 0; i < st->used; ) {
        if (now - st->e[i].ts > slow_window) {            // expired: forget this port
            st->e[i] = st->e[--st->used];
            continue;
        }
        if (st->e[i].port == port) { st->e[i].ts = now; found = 1; }
        i++;
    }
    if (!found) {
        if (st->used == SLOW_SLOTS) {                     // full: drop the oldest
            int oldest = 0;
            for (int i = 1; i < st->used; i++) if (st->e[i].ts < st->e[oldest].ts) oldest = i;
            st->e[oldest] = st->e[--st->used];
        }
        st->e[st->used].port = port;
        st->e[st->used].ts = now;
        st->used++;
    }
    return st->used;
}

static void slow_forget(uint32_t src_ip) {
    for (int i = 0; i < slow_count; i++)
        if (slow_tab[i].src_ip == src_ip) { slow_tab[i] = slow_tab[--slow_count]; return; }
}

static int popcount256(const uint64_t h[4]) {
    return __builtin_popcountll(h[0]) + __builtin_popcountll(h[1]) +
           __builtin_popcountll(h[2]) + __builtin_popcountll(h[3]);
}

static void check_subnet_escalation(int threat_intel_fd, uint32_t src_ip) {
    uint32_t subnet = src_ip & htonl(0xFFFFFF00); // /24 mask
    unsigned host = ntohl(src_ip) & 0xFF;          // last octet = bit index in the bitmap
    time_t now = time(NULL);

    struct subnet_state *ss = NULL;
    for (int i = 0; i < subnet_count; i++) {
        if (subnets[i].subnet == subnet) {
            ss = &subnets[i];
            break;
        }
    }

    if (!ss && subnet_count < 1024) {
        ss = &subnets[subnet_count++];
        memset(ss, 0, sizeof(*ss));
        ss->subnet = subnet;
        ss->window_start = now;
    }

    if (ss && !ss->escalated) {
        // Old evidence expires: a window with no escalation starts over.
        if (now - ss->window_start > SUBNET_WINDOW_SECONDS) {
            memset(ss->hosts, 0, sizeof(ss->hosts));
            ss->window_start = now;
        }
        ss->hosts[host >> 6] |= 1ULL << (host & 63);
        if (popcount256(ss->hosts) >= BAN_SUBNET_THRESHOLD) {
            // Escalate! Ban the entire /24 subnet permanently via threat_intel_map
            struct lpm_ip_key key = { .prefixlen = 24, .ip = subnet };
            struct ips_blocklist_data val = { .ban_timestamp = now, .is_static = 1, .packets_dropped = 0 };
            bpf_map_update_elem(threat_intel_fd, &key, &val, BPF_ANY);

            struct in_addr addr = { .s_addr = subnet };
            printf("[!] RECON TRACKER: Subnet Escalation! Banned entire /24: %s (%d distinct hosts)\n",
                   inet_ntoa(addr), popcount256(ss->hosts));
            ss->escalated = 1;
        }
    }
}

int handle_recon_event(void *ctx, void *data, size_t data_sz) {
    struct recon_tracker_ctx *tctx = (struct recon_tracker_ctx *)ctx;
    struct ips_recon_event *event = (struct ips_recon_event *)data;
    
    struct recon_state *s = get_or_create_tracker(event->src_ip);
    if (!s) return 0;
    
    if (event->protocol == PROTO_TCP) {
        // Slow-scan memory sees every TCP probe, including ports the burst filter below skips.
        int distinct = slow_record(event->src_ip, event->dst_port, time(NULL));
        if (distinct >= slow_ports_thr) {
            struct ips_blocklist_data bd = { .ban_timestamp = time(NULL), .is_static = 0, .packets_dropped = 0 };
            if (bpf_map_update_elem(tctx->dynamic_bans_fd, &event->src_ip, &bd, BPF_ANY) == 0) {
                struct in_addr a = { .s_addr = event->src_ip };
                printf("[!] RECON TRACKER: Slow scan! %d distinct ports within %ld s. Banned IP %s\n",
                       distinct, slow_window, inet_ntoa(a));
                check_subnet_escalation(tctx->threat_intel_fd, event->src_ip);
            }
            slow_forget(event->src_ip);
            for (int i = 0; i < tracker_count; i++)
                if (trackers[i].src_ip == event->src_ip) { trackers[i] = trackers[--tracker_count]; break; }
            return 0;
        }
        int duplicate = 0;
        for (int i = 0; i < 16; i++) {
            if (s->recent_ports[i] == event->dst_port) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) return 0;
        
        s->recent_ports[s->port_idx] = event->dst_port;
        s->port_idx = (s->port_idx + 1) % 16;
    } else {
        // ICMP echo: a ping SWEEP is many different hosts, so charge one token per new
        // destination. Repeated pings to a host seen in the last 16 are free here (a ping
        // FLOOD to one host is the per-source rate limiter's job, Stage 2). Charging every
        // echo request banned a benign phone pinging ~9 times a minute (2026-11-04 S2 run).
        int seen = 0;
        for (int i = 0; i < 16; i++) {
            if (s->recent_hosts[i] == event->dst_ip) { seen = 1; break; }
        }
        if (seen) return 0;
        s->recent_hosts[s->host_idx] = event->dst_ip;
        s->host_idx = (s->host_idx + 1) % 16;
    }
    
    int cost = 1;
    if (event->protocol == PROTO_TCP && is_critical_port(event->dst_port)) {
        cost = 5;
    }
    
    s->tokens -= cost;
    s->last_update = time(NULL);
    
    if (s->tokens <= 0) {
        struct ips_blocklist_data block_data = { .ban_timestamp = time(NULL), .is_static = 0, .packets_dropped = 0 };
        if (bpf_map_update_elem(tctx->dynamic_bans_fd, &event->src_ip, &block_data, BPF_ANY) == 0) {
            struct in_addr addr = { .s_addr = event->src_ip };
            printf("[!] RECON TRACKER: Tokens depleted. Banned IP %s for port/ping sweeping!\n", inet_ntoa(addr));
            check_subnet_escalation(tctx->threat_intel_fd, event->src_ip);
        }
        
        for (int i = 0; i < tracker_count; i++) {
            if (trackers[i].src_ip == event->src_ip) {
                trackers[i] = trackers[--tracker_count];
                break;
            }
        }
    }
    return 0;
}

void age_recon_tracker(int dynamic_bans_fd) {
    time_t now = time(NULL);
    for (int i = 0; i < tracker_count; i++) {
        struct recon_state *s = &trackers[i];
        time_t passed = now - s->last_update;
        if (passed >= REGEN_SECONDS) {
            int earned = passed / REGEN_SECONDS;
            s->tokens += earned;
            if (s->tokens >= MAX_TOKENS) {
                trackers[i] = trackers[--tracker_count];
                i--;
            } else {
                s->last_update += (earned * REGEN_SECONDS);
            }
        }
    }
}
