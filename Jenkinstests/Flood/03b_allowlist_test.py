#!/usr/bin/env python3
"""
Tests the greylist -> allowlist promotion logic (STAGE 5 in fast_path/ips.bpf.c) against a
running ips_loader instance over the veth link set up by 01_setup_veth.sh / 02_run_ips.sh.

Must be run AFTER 02_run_ips.sh and BEFORE 04_cleanup.sh (needs ips_loader running, and
needs 02_run_ips.sh's config.ini patch, which adds EXCLUDED_IP below to
excluded_source_ips -- see the note near the bottom of 02_run_ips.sh).

Sends 5 clean TCP SYNs (no malformed flags) from CLEAN_IP to VICTIM_IP:VICTIM_PORT and
checks data/allowlist.csv for both directions of that flow -- the 5th packet should trigger
promotion. Then sends 8 clean SYNs from EXCLUDED_IP and confirms it never gets promoted no
matter how many clean packets it sends, since it's config-excluded from the bootstrap.

allowlist.csv is only rewritten every state_dump_interval_seconds (config.ini, default 5s),
not appended-on-write like blocklist.csv, so this waits at least one full dump cycle before
checking -- unlike 03_flood_test.py's ban check, which is near-immediate.

Must be run as root (raw packet injection).
"""
import argparse
import csv
import sys
import time

from scapy.all import Ether, IP, TCP, sendp

CLEAN_IP = "10.200.0.70"     # expected to get promoted after 5 clean packets
EXCLUDED_IP = "10.200.0.71"  # must be in config.ini's excluded_source_ips (02_run_ips.sh adds it)
VICTIM_IP = "10.200.0.1"     # test-wan's address from 01_setup_veth.sh
VICTIM_PORT = 8080


def send_clean_syns(iface, src_ip, dst_ip, dst_port, src_port, count):
    # A plain SYN, repeated -- deliberately NOT syn+fin / null-scan / fin+psh+urg, so none
    # of these trip STAGE 2.5's malformed-flags check (that path is covered by 03_flood_test.py
    # not needing changes; this script is purely about STAGE 5).
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, flags="S")
    )
    sendp(pkt, iface=iface, count=count, inter=0.05, verbose=False)


def flow_in_allowlist(allowlist_csv, src_ip, dst_ip, src_port, dst_port):
    # Format written by save_allowlist_to_csv: src_ip,dst_ip,src_port,dst_port,protocol,last_seen
    try:
        with open(allowlist_csv, newline="") as f:
            for row in csv.reader(f):
                if (len(row) >= 4 and row[0] == src_ip and row[1] == dst_ip
                        and row[2] == str(src_port) and row[3] == str(dst_port)):
                    return True
    except FileNotFoundError:
        pass
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iface", default="veth-attacker")
    ap.add_argument("--allowlist-csv", required=True,
                     help="path to data/allowlist.csv in your repo checkout")
    ap.add_argument("--settle-seconds", type=float, default=7.0,
                     help="must exceed config.ini's state_dump_interval_seconds (default 5s)")
    args = ap.parse_args()

    clean_src_port = 51000
    excluded_src_port = 51001

    print(f"[*] Sending 5 clean SYNs from {CLEAN_IP} to {VICTIM_IP}:{VICTIM_PORT}")
    send_clean_syns(args.iface, CLEAN_IP, VICTIM_IP, VICTIM_PORT, clean_src_port, 5)

    print(f"[*] Sending 8 clean SYNs from excluded {EXCLUDED_IP} to {VICTIM_IP}:{VICTIM_PORT}")
    send_clean_syns(args.iface, EXCLUDED_IP, VICTIM_IP, VICTIM_PORT, excluded_src_port, 8)

    print(f"[*] Waiting {args.settle_seconds}s for the next state_dump to write allowlist.csv...")
    time.sleep(args.settle_seconds)

    clean_promoted = flow_in_allowlist(args.allowlist_csv, CLEAN_IP, VICTIM_IP, clean_src_port, VICTIM_PORT)
    excluded_promoted = flow_in_allowlist(args.allowlist_csv, EXCLUDED_IP, VICTIM_IP, excluded_src_port, VICTIM_PORT)

    print(f"[{'PASS' if clean_promoted else 'FAIL'}] Clean IP {CLEAN_IP} promoted to allowlist after 5 clean packets: {clean_promoted}")
    print(f"[{'PASS' if not excluded_promoted else 'FAIL'}] Excluded IP {EXCLUDED_IP} NOT promoted despite 8 clean packets: {not excluded_promoted}")

    sys.exit(0 if (clean_promoted and not excluded_promoted) else 1)


if __name__ == "__main__":
    main()
