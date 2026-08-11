#!/usr/bin/env bash
# Refreshes fast_path/threats.txt from the Spamhaus DROP list (mirrored by FireHOL
# on GitHub, so we don't hit Spamhaus's own rate-limited servers directly).
# See lib_update_blocklist.sh for the shared fetch/validate/atomic-replace logic.
# Runs unprivileged: this only writes a text file, it never touches the BPF maps.
# Safe to run any time — a bad/short/empty download is rejected and the last
# known-good threats.txt is left untouched; the daemon's static-entry TTL aging
# already tolerates a stale or missing file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib_update_blocklist.sh"

run_update \
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset" \
    "$SCRIPT_DIR/../inline_bpf/threats.txt" \
    100 \
    '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
