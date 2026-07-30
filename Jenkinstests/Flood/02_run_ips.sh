#!/usr/bin/env bash
# Launches the already-built ips_loader against the veth pair from
# 01_setup_veth.sh. Does NOT build anything - run `cmake --build build`
# yourself first if you haven't.
set -euo pipefail

# EDIT ME (or export IPS_REPO_ROOT before running):
REPO_ROOT="${IPS_REPO_ROOT:-/path/to/Intrusion-Prevention-System}"

IPS_BIN="$REPO_ROOT/build/fast_path/ips_loader"
PID_FILE="$REPO_ROOT/fast_path/ips_loader_test.pid"
LOG_FILE="$REPO_ROOT/fast_path/ips_loader_test.log"

if [ ! -x "$IPS_BIN" ]; then
    echo "[!] $IPS_BIN not found or not executable - build it first (cmake --build build)."
    exit 1
fi

if [ -f "$PID_FILE" ]; then
    OLD_PID="$(cat "$PID_FILE")"
    if sudo kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[!] ips_loader already running (PID $OLD_PID) - run 04_cleanup.sh first."
        exit 1
    else
        echo "[*] Stale PID file from a previous run (PID $OLD_PID not running) - removing it"
        rm -f "$PID_FILE"
    fi
fi

# Strip our test IPs from the persisted blocklist before starting - main.c's
# load_blocklist_from_csv() reloads this file into the live kernel map on
# every boot, so a ban left over from a previous test run would otherwise
# pre-ban this run before a single flood packet is sent. Done here (start),
# not in 04_cleanup.sh (end), because a crashed/aborted previous run would
# skip an end-of-run cleanup - resetting at the start is self-healing no
# matter how the last run finished.
BLOCKLIST_CSV="$REPO_ROOT/data/blocklist.csv"
if [ -f "$BLOCKLIST_CSV" ]; then
    echo "[*] Clearing test IPs (10.200.0.66, 10.200.0.67) from $BLOCKLIST_CSV"
    grep -v -E "^(10\.200\.0\.66|10\.200\.0\.67)," "$BLOCKLIST_CSV" > "$BLOCKLIST_CSV.tmp" \
        && mv "$BLOCKLIST_CSV.tmp" "$BLOCKLIST_CSV"
fi

# main.c pins static_blocklist to /sys/fs/bpf/... - that path has to actually
# be a mounted BPF filesystem, which a fresh container doesn't have by default.
if ! mount | grep -q "on /sys/fs/bpf type bpf"; then
    echo "[*] Mounting bpffs at /sys/fs/bpf"
    sudo mount -t bpf bpf /sys/fs/bpf
fi

# main.c resolves data/config paths as "../data", "../config/config.ini"
# relative to the CURRENT WORKING DIRECTORY, so it must be launched with
# fast_path/ as cwd regardless of where the binary itself lives.
cd "$REPO_ROOT/fast_path"

echo "[*] Starting ips_loader (logging to $LOG_FILE)"
sudo "$IPS_BIN" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

sleep 2
if ! sudo kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[!] ips_loader exited immediately - check $LOG_FILE"
    exit 1
fi

echo "[+] ips_loader running (PID $(cat "$PID_FILE")). Tail $LOG_FILE to watch it."
