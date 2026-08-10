#ifndef IPS_MAIN_H
#define IPS_MAIN_H

#include "ips_fast_common.h"

// Appends a single ban entry to CSV_FILE (O(1), vs. a full save_blocklist_to_csv() rewrite).
// Shared with slow_path/slow_path.c, which also bans IPs directly (malformed TCP flags)
// without going through the ring-buffer event path that handle_ban_event() uses.
void append_blocklist_entry_to_csv(__u32 ip, const struct ips_blocklist_data *block_data);

#endif /* IPS_MAIN_H */
