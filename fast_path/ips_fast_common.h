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

#endif /* IPS_FAST_COMMON_H */