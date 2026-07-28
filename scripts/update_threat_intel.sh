#!/usr/bin/env bash
# Refreshes fast_path/threats.txt from the Spamhaus DROP list (mirrored by FireHOL
# on GitHub, so we don't hit Spamhaus's own rate-limited servers directly).
# Runs unprivileged: this only writes a text file, it never touches the BPF maps.
# Safe to run any time — a bad/short/empty download is rejected and the last
# known-good threats.txt is left untouched; the daemon's static-entry TTL aging
# already tolerates a stale or missing file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THREATS_FILE="$SCRIPT_DIR/../fast_path/threats.txt"
SOURCE_URL="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset"
MIN_ENTRIES=100 # spamhaus_drop currently runs ~1400 entries; well below that means a bad fetch

TMP_FILE="$(mktemp "${THREATS_FILE}.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

if ! curl -fsS --max-time 30 -o "$TMP_FILE" "$SOURCE_URL"; then
    echo "[!] Download failed, keeping existing threats.txt" >&2
    exit 1
fi

entry_count=$(grep -vc '^[[:space:]]*#\|^[[:space:]]*$' "$TMP_FILE" || true)

if [ "$entry_count" -lt "$MIN_ENTRIES" ]; then
    echo "[!] Downloaded file only has $entry_count entries (expected >= $MIN_ENTRIES), refusing to replace threats.txt" >&2
    exit 1
fi

if ! grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$TMP_FILE"; then
    echo "[!] Downloaded file doesn't look like an IP list, refusing to replace threats.txt" >&2
    exit 1
fi

chmod 644 "$TMP_FILE"
mv -f "$TMP_FILE" "$THREATS_FILE"
trap - EXIT

echo "[+] threats.txt updated: $entry_count entries from $SOURCE_URL"
