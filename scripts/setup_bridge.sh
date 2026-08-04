#!/usr/bin/env bash
# Creates the OS-level Linux bridge (br0) spanning wan_interface/lan_interface from
# config.ini. ips_loader only ATTACHES XDP to whichever physical interfaces are already
# bridged -- it has never created the bridge itself (see the TODO above
# setup_network_interfaces() in fast_path/main.c). Without this, XDP_PASS on one NIC has
# nowhere to go and no traffic actually crosses the box, no matter what the daemon logs say.
#
# Intended to run once per boot, before ips_loader starts (see ips-loader.service's
# ExecStartPre). Safe to re-run: a bridge/membership that's already correct is left alone.
#
# This only sets up the bridge for the CURRENT boot -- it does not persist across reboots
# on its own. How to make it persistent depends on which network manager your Pi image
# uses (dhcpcd vs NetworkManager vs systemd-networkd differ significantly across Raspberry
# Pi OS versions), so that's intentionally left out of this script rather than guessed at.
#
# Also intentionally does NOT put an IP on br0 or on either member interface -- both
# wan_interface and lan_interface are meant to be a transparent inline pipe with nothing
# listening on them directly. For SSH/management access to the Pi itself, use a separate
# interface (e.g. onboard Wi-Fi) that isn't part of this bridge -- otherwise a bad filtering
# rule on the inline path could lock you out of the box that enforces it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_INI="$SCRIPT_DIR/../config/config.ini"
BRIDGE_IF="br0"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Must run as root (creates network interfaces)." >&2
    exit 1
fi

if [ ! -f "$CONFIG_INI" ]; then
    echo "[!] $CONFIG_INI not found." >&2
    exit 1
fi

# Reads a "key = value" line the same way main.c's load_config() parses config.ini --
# trims surrounding whitespace, takes the last match if a key appears more than once.
read_config_value() {
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$CONFIG_INI" | tail -1 | sed -E 's/^[^=]*=[[:space:]]*//' | tr -d '[:space:]'
}

WAN_IF="$(read_config_value wan_interface)"
LAN_IF="$(read_config_value lan_interface)"

if [ -z "$WAN_IF" ] || [ -z "$LAN_IF" ]; then
    echo "[!] wan_interface/lan_interface not set in $CONFIG_INI." >&2
    exit 1
fi

for iface in "$WAN_IF" "$LAN_IF"; do
    if ! ip link show "$iface" &>/dev/null; then
        echo "[!] Interface $iface (from config.ini) not found on this host." >&2
        exit 1
    fi
done

echo "[*] Bridging $WAN_IF <-> $LAN_IF via $BRIDGE_IF"

if ! ip link show "$BRIDGE_IF" &>/dev/null; then
    echo "[*] Creating $BRIDGE_IF"
    ip link add name "$BRIDGE_IF" type bridge
fi

# XDP is attached directly to WAN_IF/LAN_IF (not to br0), so it always sees a frame before
# the bridge's own logic does anything with it -- STP has nothing meaningful to negotiate on
# a fixed 2-port bridge with no possible loop, and just adds forwarding delay while a port
# sits in listening/learning state, so it's turned off here.
ip link set "$BRIDGE_IF" type bridge stp_state 0

for iface in "$WAN_IF" "$LAN_IF"; do
    current_master="$(ip -o link show "$iface" | grep -o 'master [^ ]*' | awk '{print $2}' || true)"
    if [ "$current_master" != "$BRIDGE_IF" ]; then
        echo "[*] Adding $iface to $BRIDGE_IF"
        # A bridge member must not hold its own IP -- only the bridge (or nothing, as here)
        # should be addressed.
        ip addr flush dev "$iface"
        ip link set "$iface" master "$BRIDGE_IF"
    fi
    ip link set "$iface" up
done

ip link set "$BRIDGE_IF" up

echo "[+] Bridge is up:"
ip -brief link show "$BRIDGE_IF"
ip -brief link show "$WAN_IF"
ip -brief link show "$LAN_IF"
bridge link show
