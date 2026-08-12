#!/bin/bash
set -e

# Define our isolated sandbox in the system temp folder
SANDBOX_DIR="/tmp/ips_xdp_sandbox"
DAEMON="$(pwd)/../../build/fast_path/ips_loader"

# --- SAFETY TRAP: Obliterate the sandbox and interfaces on exit ---
cleanup() {
    echo "[i] Cleaning up environment..."
    kill -s SIGTERM $DAEMON_PID 2>/dev/null || true
    wait $DAEMON_PID 2>/dev/null || true
    ip link del veth_wan 2>/dev/null || true
    ip link del veth_lan 2>/dev/null || true
    ip netns del attacker_ns 2>/dev/null || true
    rm -rf "$SANDBOX_DIR"
}
trap cleanup EXIT
# -----------------------------------------------------------------

echo "=================================================="
echo "[i] Starting eBPF Fast Path (XDP) Functional Test"
echo "=================================================="

if [ ! -f "$DAEMON" ]; then
    echo "[!] Error: ips_loader binary not found at $DAEMON"
    exit 1
fi

if ! command -v hping3 &> /dev/null; then
    echo "[!] Error: hping3 is not installed. Run: sudo apt install hping3"
    exit 1
fi

# ==============================================================================
# 1. Setup Virtual Network Environment
# ==============================================================================
echo "[i] Setting up isolated network namespaces..."

ip netns add attacker_ns 2>/dev/null || true

ip link add veth_wan type veth peer name veth_atk 2>/dev/null || true
ip link set veth_atk netns attacker_ns
ip link set dev veth_wan up
ip addr add 10.99.99.1/24 dev veth_wan

ip link add veth_lan type veth peer name veth_lan_peer 2>/dev/null || true
ip link set dev veth_lan up

ip netns exec attacker_ns ip addr add 10.99.99.2/24 dev veth_atk 
ip netns exec attacker_ns ip addr add 10.99.99.3/24 dev veth_atk 
ip netns exec attacker_ns ip addr add 10.99.99.4/24 dev veth_atk 
ip netns exec attacker_ns ip link set dev veth_atk up
ip netns exec attacker_ns ip route add 10.99.99.1 dev veth_atk

# ==============================================================================
# 2. Setup Sandbox & Start IPS Daemon
# ==============================================================================
echo "[i] Launching IPS daemon in isolated /tmp sandbox..."

mkdir -p "$SANDBOX_DIR/config"
mkdir -p "$SANDBOX_DIR/run"

cat << EOF > "$SANDBOX_DIR/config/config.ini"
wan_interface = veth_wan
lan_interface = veth_lan
token_bucket_max = 50
token_refill_rate = 10
ban_duration_seconds = 3600
EOF

# Move into the sandbox so the daemon's relative paths resolve inside /tmp
cd "$SANDBOX_DIR/run"

"$DAEMON" &
DAEMON_PID=$!
sleep 2 

if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo "[!] Fatal: Daemon failed to start."
    exit 1
fi

BLOCKLIST_CSV="$SANDBOX_DIR/data/blocklist.csv"

# ==============================================================================
# 3. Test Cases
# ==============================================================================

# --- TEST A: Rate Limiter (Flood) ---
echo "[i] Test A: Rate Limiter (Flooding from 10.99.99.2)..."
set +e
ip netns exec attacker_ns ping -c 100 -f -W 1 10.99.99.1 > /dev/null 2>&1
set -e

sleep 1 # Give the slow-path thread a moment to flush to disk

if grep -q "10.99.99.2" "$BLOCKLIST_CSV" 2>/dev/null; then
    echo "    [+] PASSED: eBPF detected the flood and wrote 10.99.99.2 to blocklist.csv."
else
    echo "    [!] FAILED: 10.99.99.2 was not found in blocklist.csv."
    FAILED=1
fi

# --- TEST B: Malformed TCP Flags (SYN + FIN) ---
echo "[i] Test B: Malformed TCP Flags - SYN+FIN (from 10.99.99.3)..."
set +e
ip netns exec attacker_ns hping3 -a 10.99.99.3 -c 1 --syn --fin -p 80 10.99.99.1 > /dev/null 2>&1
set -e

sleep 1

if grep -q "10.99.99.3" "$BLOCKLIST_CSV" 2>/dev/null; then
    echo "    [+] PASSED: eBPF detected SYN+FIN and wrote 10.99.99.3 to blocklist.csv."
else
    echo "    [!] FAILED: 10.99.99.3 was not found in blocklist.csv."
    FAILED=1
fi

# --- TEST C: Malformed TCP Flags (FIN + PSH + URG) ---
echo "[i] Test C: Malformed TCP Flags - FIN+PSH+URG (from 10.99.99.4)..."
set +e
ip netns exec attacker_ns hping3 -a 10.99.99.4 -c 1 --fin --push --urg -p 80 10.99.99.1 > /dev/null 2>&1
set -e

sleep 1

if grep -q "10.99.99.4" "$BLOCKLIST_CSV" 2>/dev/null; then
    echo "    [+] PASSED: eBPF detected FIN+PSH+URG and wrote 10.99.99.4 to blocklist.csv."
else
    echo "    [!] FAILED: 10.99.99.4 was not found in blocklist.csv."
    FAILED=1
fi

echo "=================================================="
if [ "$FAILED" == "1" ]; then
    echo "[!] eBPF Fast Path Tests FAILED!"
    exit 1
else
    echo "[+] eBPF Fast Path Tests PASSED!"
    exit 0
fi