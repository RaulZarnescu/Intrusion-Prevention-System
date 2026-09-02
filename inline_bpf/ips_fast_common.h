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
    __u64 packets_dropped;
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

// Stage 0.5 quarantine entries need their own TTL, mirroring dynamic_bans_map's
// ban_timestamp/age_bans() pattern -- otherwise a source that once talked to a
// destination banned for unrelated reasons (e.g. that destination's own rate-limit
// ban, which self-expires) stays walled off forever, long after that destination's
// ban is gone. quarantine_start_ns is boot-monotonic (bpf_ktime_get_ns()), matching
// every other in-kernel-only timestamp in this codebase (allowlist's last_seen, the
// rate limiter's last_update) -- quarantine is never persisted to disk or touched by
// userspace, so it only needs to be self-consistent within one BPF program's
// lifetime, not tied to wall time.
struct ips_quarantine_data {
    __u64 quarantine_start_ns;
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
    IPS_BAN_REASON_MALICIOUS_SNI = 2,  // SNI blocked via BPF map
    IPS_BAN_REASON_PROTOCOL_MISMATCH = 3, // traffic on a well-known port didn't match that port's protocol
    IPS_BAN_REASON_FRAGMENTED = 4,     // IP fragment -- likely header-splitting scan evasion (nmap -f)
    IPS_BAN_REASON_OUT_OF_STATE_ACK = 5, // ACK/FIN-ACK with no prior SYN seen for this flow (ACK/Window/Maimon scan)
};

struct ips_ban_event {
    __u32 src_ip;
    __u32 drop_count;
    __u32 reason; // enum ips_ban_reason
};

// ==============================================================================
// #REQ-074: Recon Events Stream
// ==============================================================================
#define PROTO_TCP 6
#define PROTO_ICMP 1

struct ips_recon_event {
    __u32 src_ip;
    __u16 dst_port;
    __u8 protocol; // PROTO_TCP or PROTO_ICMP
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
    unsigned int threat_intel_refresh_sec; // Nominal cadence, used only for stale-entry TTL math (aged out past 2x this) -- re-injection itself is SIGHUP-driven, not polled
    unsigned int allowlist_ttl_sec; // How long a trusted flow survives with no traffic before it's aged out
    unsigned int state_dump_interval_sec; // How often the tracker/allowlist/honeypot CSVs are rewritten for monitor.py
    // Stage 2.6 out-of-state-ACK detection (ips_xdp_main) needs a prior SYN recorded in
    // conn_seen_map before it'll trust an ACK/FIN-ACK -- which conn_seen_map, freshly empty
    // on every restart, can't have for connections that were already established before this
    // restart (e.g. an existing SSH session into this very box). For this many seconds after
    // startup, stage 2.6 doesn't enforce, so those survive; only after it elapses does an
    // ACK/Window/Maimon scan actually get banned.
    unsigned int conn_track_grace_period_sec;
    // Stage 0.5 quarantine (ips_xdp_main): how long a source stays quarantined after being
    // caught talking to an already-banned destination, before it's re-evaluated on its own
    // merits again. Independent of ban_duration_sec on purpose -- quarantine and dynamic bans
    // guard against different failure modes (see quarantine_map's comment in ips.bpf.c).
    unsigned int quarantine_duration_sec;
    char wan_interface[16]; // matches IFNAMSIZ; upstream-facing physical interface (e.g. eth0)
    char lan_interface[16]; // matches IFNAMSIZ; internal-facing physical interface (e.g. eth1)
    // Stage 0.1 BCP38 anti-spoof (ips_xdp_main): drops any WAN-arriving packet whose source
    // looks like a private/RFC1918 address, on the assumption WAN means the real internet.
    // That assumption breaks on a nested test rig where the "WAN" side is itself just
    // another private LAN (e.g. a Tenda router's own 192.168.0.0/24) -- every legitimate
    // packet from that side looks "internal" and gets silently dropped, no logging at all.
    // Defaults on (correct for a real deployment); set anti_spoof_enabled = 0 in this
    // host's local config.ini to disable it for exactly that kind of test topology.
    unsigned int anti_spoof_enabled;
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
    __u8 tcp_flags;
    __u8 padding[2]; // Required to keep the struct 4-byte aligned for eBPF
};

#define SNI_MAX_LEN 256
struct sni_key {
    char sni[SNI_MAX_LEN];
};

static __always_inline int is_internal_ip(__u32 ip) {
    // ip is in network byte order
    __u8 *bytes = (__u8 *)&ip;
    if (bytes[0] == 10) return 1;
    if (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31)) return 1;
    if (bytes[0] == 192 && bytes[1] == 168) return 1;
    return 0;
}

#endif /* IPS_FAST_COMMON_H */