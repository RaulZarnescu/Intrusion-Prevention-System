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

// ==============================================================================
// #REQ-XXX: Ring Buffer Event
// ==============================================================================

// What triggered the ban. Rate limiting is the only producer today, but the
// blocklist itself (and handle_ban_event in user-space) is reason-agnostic,
// so new detectors (honeypot hits, port scans, manual bans, ...) can submit
// events with their own reason without touching the consumer.
enum ips_ban_reason {
    IPS_BAN_REASON_RATE_LIMIT = 0, // Token bucket exhausted (packet flood)
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

// ==============================================================================
// #REQ-XXX: .ini config file
// ==============================================================================

struct ips_config {
    unsigned int ban_duration_sec;
    unsigned int token_bucket_max;
    unsigned int token_refill_rate;
    unsigned int max_tolerated_drops;
};

#endif /* IPS_FAST_COMMON_H */