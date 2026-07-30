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

# main.c now requires wan_interface/lan_interface from config.ini (no more
# hardcoded names) - point them at our test veth pair for this run only.
# config.ini is a real, shared file (holds actual deployment NIC names), so
# back it up first and restore it in 04_cleanup.sh. Only take the backup if
# one doesn't already exist: if a previous run crashed after patching but
# before restoring, config.ini.bak already holds the real original - copying
# over it again here would overwrite that with the patched (wrong) version.
CONFIG_INI="$REPO_ROOT/config/config.ini"
CONFIG_BACKUP="$REPO_ROOT/config/config.ini.bak"
if [ ! -f "$CONFIG_BACKUP" ]; then
    cp "$CONFIG_INI" "$CONFIG_BACKUP"
fi
grep -v -E "^(wan_interface|lan_interface)[[:space:]]*=" "$CONFIG_BACKUP" > "$CONFIG_INI.tmp"
{
    cat "$CONFIG_INI.tmp"
    echo "wan_interface = test-wan"
    echo "lan_interface = test-lan"
} > "$CONFIG_INI"
rm -f "$CONFIG_INI.tmp"

# main.c resolves data/config paths as "../data", "../config/config.ini"
# relative to the CURRENT WORKING DIRECTORY, so it must be launched with
# fast_path/ as cwd regardless of where the binary itself lives.
cd "$REPO_ROOT/fast_path"

echo "[*] Starting ips_loader (logging to $LOG_FILE)"
# `sudo "$IPS_BIN" &` then `echo $!` is unreliable: sudo can fork internally,
# so $! sometimes captures a wrapper process that exits right after handing
# off to the real (differently-PID'd) ips_loader - making a perfectly healthy
# daemon look dead. Instead, have the privileged shell write its OWN pid
# before exec-ing into the binary - exec keeps the same PID, so this is
# guaranteed to be the actual running process, not a wrapper around it.
sudo bash -c "echo \$\$ > '$PID_FILE'; exec '$IPS_BIN'" > "$LOG_FILE" 2>&1 &

sleep 2
if [ ! -f "$PID_FILE" ] || ! sudo kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[!] ips_loader exited immediately - check $LOG_FILE"
    exit 1
fi

echo "[+] ips_loader running (PID $(cat "$PID_FILE")). Tail $LOG_FILE to watch it."
