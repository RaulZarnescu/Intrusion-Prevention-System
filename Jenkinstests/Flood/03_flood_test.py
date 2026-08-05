#!/usr/bin/env python3
"""
Flood-tests a running ips_loader instance over the local veth link set up
by 01_setup_veth.sh / 02_run_ips.sh.

Sends a fast burst of spoofed-source packets from ATTACKER_IP - enough to
exhaust the token bucket and cross max_tolerated_drops - then a light
trickle from CONTROL_IP, and checks data/blocklist.csv to confirm only the
attacker got banned.

Must be run as root (raw packet injection).
"""
import argparse
import csv
import sys
import time

from scapy.all import Ether, IP, UDP, sendp

# Defaults match the veth harness (01_setup_veth.sh) so the Jenkins pipeline
# keeps working unchanged; override via CLI flags to point this at real
# hardware instead (e.g. a laptop's own IP as attacker, a phone's IP as victim).
DEFAULT_ATTACKER_IP = "10.200.0.66"
DEFAULT_CONTROL_IP = "10.200.0.67"
DEFAULT_VICTIM_IP = "10.200.0.1"


def flood(iface, src_ip, dst_ip, count, dst_port=53):
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=40000, dport=dst_port)
        / b"flood-test"
    )
    sendp(pkt, iface=iface, count=count, inter=0, verbose=False)


def ip_is_banned(blocklist_csv, ip):
    try:
        with open(blocklist_csv, newline="") as f:
            return any(row and row[0] == ip for row in csv.reader(f))
    except FileNotFoundError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iface", default="veth-attacker")
    ap.add_argument(
        "--blocklist-csv",
        default="/path/to/Intrusion-Prevention-System/data/blocklist.csv",
        help="path to data/blocklist.csv in your repo checkout",
    )
    ap.add_argument("--packets", type=int, default=200,
                     help="packets to fire from the attacker IP (default comfortably exceeds default thresholds)")
    ap.add_argument("--settle-seconds", type=float, default=2.0,
                     help="how long to wait for ips_loader to process the ban event")
    ap.add_argument("--victim-ip", default=DEFAULT_VICTIM_IP,
                     help="destination IP to flood (override for real-hardware testing)")
    ap.add_argument("--attacker-ip", default=DEFAULT_ATTACKER_IP,
                     help="source IP expected to get banned (spoofed on veth; use your real IP on real hardware)")
    ap.add_argument("--control-ip", default=DEFAULT_CONTROL_IP,
                     help="source IP expected to stay unbanned")
    args = ap.parse_args()

    print(f"[*] Flooding {args.victim_ip} from {args.attacker_ip} via {args.iface} ({args.packets} packets, no delay)")
    flood(args.iface, args.attacker_ip, args.victim_ip, args.packets)

    print(f"[*] Sending 5 control packets from {args.control_ip} (should stay unbanned)")
    flood(args.iface, args.control_ip, args.victim_ip, 5)

    print(f"[*] Waiting {args.settle_seconds}s for ips_loader to process the ban event...")
    time.sleep(args.settle_seconds)

    attacker_banned = ip_is_banned(args.blocklist_csv, args.attacker_ip)
    control_banned = ip_is_banned(args.blocklist_csv, args.control_ip)

    print(f"[{'PASS' if attacker_banned else 'FAIL'}] Attacker IP {args.attacker_ip} banned: {attacker_banned}")
    print(f"[{'PASS' if not control_banned else 'FAIL'}] Control IP {args.control_ip} left alone: {not control_banned}")

    sys.exit(0 if (attacker_banned and not control_banned) else 1)


if __name__ == "__main__":
    main()
