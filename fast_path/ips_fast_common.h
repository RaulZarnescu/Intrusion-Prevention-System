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
struct ips_ban_event {
    __u32 src_ip;
    __u32 drop_count;
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