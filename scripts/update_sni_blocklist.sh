#!/usr/bin/env bash
# Refreshes fast_path/sni_blocklist.txt from URLhaus's host-based malware blocklist.
# Reshapes their hosts-file format ("127.0.0.1 bad-domain.tld" per line) down to just
# the domain column via transform(), which slow_path's SNI matcher reads directly.
# See lib_update_blocklist.sh for the shared fetch/validate/atomic-replace logic.
# Runs unprivileged: this only writes a text file. The running daemon picks it up on
# its own timer (sni_blocklist_refresh_seconds in config.ini) or immediately on
# SIGHUP (kill -HUP <pid of ips_loader>) -- no restart needed either way.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib_update_blocklist.sh"

transform() { tr -d '\r' | awk '/^[0-9]/{print $2}'; }

run_update \
    "https://urlhaus.abuse.ch/downloads/hostfile/" \
    "$SCRIPT_DIR/../fast_path/sni_blocklist.txt" \
    200 \
    '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
