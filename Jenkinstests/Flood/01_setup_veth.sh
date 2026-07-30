#!/usr/bin/env bash
# Creates a local veth pair for the flood test.
# VIC_IF is named enp0s8 on purpose - see README.txt.
set -euo pipefail

VIC_IF="enp0s8"
ATT_IF="veth-attacker"
VIC_IP="10.200.0.1/24"
ATT_IP="10.200.0.2/24"

if ip link show "$VIC_IF" &>/dev/null; then
    echo "[!] $VIC_IF already exists - run 04_cleanup.sh first."
    exit 1
fi

echo "[*] Creating veth pair: $VIC_IF <-> $ATT_IF"
sudo ip link add "$VIC_IF" type veth peer name "$ATT_IF"

sudo ip addr add "$VIC_IP" dev "$VIC_IF"
sudo ip addr add "$ATT_IP" dev "$ATT_IF"

sudo ip link set "$VIC_IF" up
sudo ip link set "$ATT_IF" up

echo "[+] Interfaces up:"
ip -brief addr show "$VIC_IF"
ip -brief addr show "$ATT_IF"
