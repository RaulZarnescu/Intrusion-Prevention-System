#!/usr/bin/env bash
# Stops ips_loader, unpins its BPF map, and tears down the veth pair.
set -euo pipefail

# EDIT ME (or export IPS_REPO_ROOT before running) - must match 02_run_ips.sh:
REPO_ROOT="${IPS_REPO_ROOT:-/path/to/Intrusion-Prevention-System}"

VIC_IF="enp0s8"
PID_FILE="$REPO_ROOT/fast_path/ips_loader_test.pid"

if [ -f "$PID_FILE" ]; then
    echo "[*] Stopping ips_loader (PID $(cat "$PID_FILE"))"
    sudo kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
else
    echo "[*] No PID file found, skipping process kill."
fi

echo "[*] Removing pinned BPF map"
sudo rm -f /sys/fs/bpf/ips_static_blocklist

echo "[*] Tearing down veth pair (deleting $VIC_IF also removes its peer)"
sudo ip link del "$VIC_IF" 2>/dev/null || echo "    (already gone)"

echo "[+] Cleanup done."
