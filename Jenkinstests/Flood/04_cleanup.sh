#!/usr/bin/env bash
# Stops ips_loader, unpins its BPF map, and tears down the veth pair.
set -euo pipefail

# EDIT ME (or export IPS_REPO_ROOT before running) - must match 02_run_ips.sh:
REPO_ROOT="${IPS_REPO_ROOT:-/path/to/Intrusion-Prevention-System}"

WAN_IF="test-wan"
LAN_IF="test-lan"
PID_FILE="$REPO_ROOT/fast_path/ips_loader_test.pid"
CONFIG_INI="$REPO_ROOT/config/config.ini"
CONFIG_BACKUP="$REPO_ROOT/config/config.ini.bak"

if [ -f "$PID_FILE" ]; then
    echo "[*] Stopping ips_loader (PID $(cat "$PID_FILE"))"
    sudo kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
else
    echo "[*] No PID file found, skipping process kill."
fi

echo "[*] Removing pinned BPF map"
sudo rm -f /sys/fs/bpf/ips_static_blocklist

echo "[*] Tearing down veth pairs (deleting each victim side also removes its peer)"
sudo ip link del "$WAN_IF" 2>/dev/null || echo "    ($WAN_IF already gone)"
sudo ip link del "$LAN_IF" 2>/dev/null || echo "    ($LAN_IF already gone)"

if [ -f "$CONFIG_BACKUP" ]; then
    echo "[*] Restoring original config.ini"
    mv "$CONFIG_BACKUP" "$CONFIG_INI"
fi

echo "[+] Cleanup done."
