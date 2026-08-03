#ifndef IPS_FAST_COMMON_H
#define IPS_FAST_COMMON_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#include "../config.h"

// ==============================================================================
// #REQ-010: Rate Limit Packets per Second
// ==============================================================================

struct ips_token_bucket {
    __u64 last_update;  // Nanosecond timestamp of the last refill
    __u32 tokens;       // Current tokens in the bucket
    __u32 drop_count;
};

struct ips_blocklist_data {
    __u64 ban_timestamp;
    __u64 is_static;      // 0 = Auto-banned (Dynamic), 1 = Threat Intel (Permanent)
    // is_static was made __64 from __8 to avoid padding
};

// Presence in the allowlist map means trusted; last_seen is refreshed on every packet
// fast_path_parser() observes for an already-trusted flow, so age_allowlist_map() only
// evicts flows that have genuinely gone idle, not ones still actively passing traffic.
// last_seen is boot-monotonic seconds (bpf_ktime_get_ns()/1e9 in-kernel, CLOCK_MONOTONIC
// in user-space) -- NOT wall-clock epoch time. XDP can't produce a wall-clock timestamp,
// and since allowlist state is never reloaded across a restart (unlike blocklist.csv), the
// only consumer of last_seen is age_allowlist_map()'s in-process TTL comparison, so the
// clock domain just needs to be self-consistent, not tied to wall time.
struct ips_allowlist_data {
    __u64 last_seen;
};

// Per-source-IP "5 clean observations -> trust" probation counter (the greylist). Presence
// alone means "on probation"; authorized=1 is a permanent fast-track that survives even if
// the flow's allowlist entry later ages out, so a proven-clean IP never has to re-earn trust
// unless this LRU map itself evicts the entry under memory pressure.
struct ips_greylist_data {
    __u32 count;
    __u8 authorized;
};

// ==============================================================================
// #REQ-XXX: Ring Buffer Event
// ==============================================================================

// What triggered the ban. Rate limiting is the only producer today, but the
// blocklist itself (and handle_ban_event in user-space) is reason-agnostic,
// so new detectors (honeypot hits, port scans, manual bans, ...) can submit
// events with their own reason without touching the consumer.
enum ips_ban_reason {
    IPS_BAN_REASON_RATE_LIMIT = 0,     // Token bucket exhausted (packet flood)
    IPS_BAN_REASON_MALFORMED_FLAGS = 1, // syn+fin / null scan / fin+psh+urg
};

struct ips_ban_event {
    __u32 src_ip;
    __u32 drop_count;
    __u32 reason; // enum ips_ban_reason
};

// ==============================================================================
// #REQ-XXX: Longest Prefix Match map
// used for the blacklist to prevent overflow by attaching the whole subnet to an ip with a prefix
//
// !!!!!!!!!!! POSSIBLE BOTTLENECK !!!!!!!!!!!!!!!!!!
// TODO: if needed, a hash map as well for frequent threats
// ==============================================================================

struct lpm_ip_key {
    __u32 prefixlen; // The subnet mask (e.g., 32 for single IP, 24 for a /24 subnet)
    __u32 ip;        // The actual IP address (in network byte order)
};

#define MAX_EXCLUDED_SRCS 16 // cap on excluded_source_ips entries parsed from config.ini

// ==============================================================================
// #REQ-XXX: .ini config file
// ==============================================================================

struct ips_config {
    unsigned int ban_duration_sec;
    unsigned int token_bucket_max;
    unsigned int token_refill_rate;
    unsigned int max_tolerated_drops;
    unsigned int threat_intel_refresh_sec; // How often to re-read threats.txt into static_blocklist
    unsigned int allowlist_ttl_sec; // How long a trusted flow survives with no traffic before it's aged out
    unsigned int state_dump_interval_sec; // How often the tracker/allowlist/honeypot CSVs are rewritten for monitor.py
    char wan_interface[16]; // matches IFNAMSIZ; upstream-facing physical interface (e.g. eth0)
    char lan_interface[16]; // matches IFNAMSIZ; internal-facing physical interface (e.g. eth1)
    // Source IPs/subnets exempt from the greylist bootstrap (e.g. the router's own bridged
    // traffic reflecting back) -- pushed into the excluded_srcs BPF map once at startup.
    struct lpm_ip_key excluded_srcs[MAX_EXCLUDED_SRCS];
    unsigned int excluded_srcs_count;
};

struct flow_key {
    __u32 source_ip;
    __u32 dest_ip;
    __u16 source_port;
    __u16 dest_port;
    __u8 protocol;
    __u8 padding[3]; // Required to keep the struct 4-byte aligned for eBPF
};

#endif /* IPS_FAST_COMMON_H */