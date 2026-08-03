#!/usr/bin/env bash
# Creates two local veth pairs for the flood test: one for WAN, one for LAN.
# main.c now requires both wan_interface and lan_interface (read from
# config.ini) to resolve and successfully attach XDP, or it exits - so a
# single interface (the old enp0s8 setup) is no longer enough.
set -euo pipefail

WAN_IF="test-wan"
WAN_PEER="veth-attacker"
WAN_IP="10.200.0.1/24"
WAN_PEER_IP="10.200.0.2/24"

LAN_IF="test-lan"
LAN_PEER="veth-lan-peer"
LAN_IP="10.200.1.1/24"
LAN_PEER_IP="10.200.1.2/24"

setup_pair() {
    local vic_if="$1" att_if="$2" vic_ip="$3" att_ip="$4"

    if ip link show "$vic_if" &>/dev/null; then
        echo "[*] $vic_if already exists (leftover from a previous run) - removing it first"
        sudo ip link del "$vic_if"
    fi

    echo "[*] Creating veth pair: $vic_if <-> $att_if"
    sudo ip link add "$vic_if" type veth peer name "$att_if"
    sudo ip addr add "$vic_ip" dev "$vic_if"
    sudo ip addr add "$att_ip" dev "$att_if"
    sudo ip link set "$vic_if" up
    sudo ip link set "$att_if" up
}

setup_pair "$WAN_IF" "$WAN_PEER" "$WAN_IP" "$WAN_PEER_IP"
setup_pair "$LAN_IF" "$LAN_PEER" "$LAN_IP" "$LAN_PEER_IP"

echo "[+] Interfaces up:"
ip -brief addr show "$WAN_IF"
ip -brief addr show "$WAN_PEER"
ip -brief addr show "$LAN_IF"
ip -brief addr show "$LAN_PEER"
