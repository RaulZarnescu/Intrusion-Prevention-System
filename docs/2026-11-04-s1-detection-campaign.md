# 2026-11-04 — S1 detection campaign (scientific paper, Table 1) and two unexplained Pi reboots

Raw data and harness live outside the repo, in `~/Documents/Scientific Paper/data/`
(`campaign.py`, `s1_results.jsonl`, `campaign.log`, `perf_and_fp.py`, `s1_escalation.json`).

## Setup
Attacker: dev laptop `192.168.0.100` on the Tenda side (wired). Victim: Huawei phone
`192.168.0.176` behind the TP-Link AP (adb-controlled, screen on, charging, mobile data off).
Pi: kernel `7.0.0-1020-raspi`, commit `b698300`, generic XDP on both NICs, 100 Mb/s links.
Test-only config on the Pi: `ban_duration_seconds = 20`, `quarantine_duration_seconds = 20`
(defaults 60 / 300), BCP38 off. **Restore before real use.**

## Result: 110/110 detected (10 reps x 11 techniques)
| Technique | Detector | Detected | Leaked probes |
|---|---|---|---|
| nmap -sN / -sF / -sX, hping3 SYN+FIN | malformed flags | 40/40 | 0 |
| nmap -f -sS | IP fragment | 10/10 | 0 |
| nmap -sA / -sW / -sM | out-of-state ACK | 30/30 | 0 |
| critical-port sweep (8 ports) | recon token bucket | 10/10 | 7 |
| standard-port sweep (1001-1060) | recon token bucket | 10/10 | 39 |
| ICMP sweep | recon token bucket | 10/10 | 39 |
Leaked = ports that got any victim reply. Sweeps leak exactly N-1 (ban fires on the Nth
distinct probe). Unprotected baseline (IPS stopped): every probed port answered.
Rate limiter (Stage 2) never interfered. BAN log line appears 1.6-2.3 s after the scan
(ring-buffer poll interval of the loader), the drop itself is immediate.

## Code finding
`check_subnet_escalation()` counts **bans, not distinct hosts**: three recon bans of one
attacker banned the whole `/24` (`Subnet Escalation! Banned entire /24: 192.168.0.0`).
Anything else in the `/24` (gateway, victim) counts toward the same counter, so a
benign false positive plus two attacker bans is enough to block the LAN. Not fixed.

## Harness pitfalls (so they are not rediscovered)
- nmap does its own ARP; a phone on WiFi power-save dropped ARP replies, nmap said
  "0 hosts up" and sent nothing. Fix: permanent neighbour entry + `nmap --send-ip`.
- `nmap -oG` collapses the majority port state; count leaked probes from `-oX`.
- bpftool prints map keys as decimal JSON (attacker 1677764800, victim 2952833216).
- Wait for the loader's "Event-Driven Mode Active" after a restart before scanning;
  bans made during init can be lost.
- The management link is WiFi (hotspot): retry ssh on timeout.

## Unexplained: Pi rebooted twice
03:28:39 and 03:34:00, each time seconds after a recon-tracker ban (the second right
after the `/24` escalation). The previous boot's journal ends at the ban line, with no
panic/oops/watchdog/shutdown message. Not seen during the 110-run campaign (about 60 recon bans).
`vcgencmd`: 5.12 V rail, 5 A supply reported, throttled `0x0` after reboot (flag resets).
User reports the power strip chargers are cold. Cause unknown; next step: serial console
or `pstore`, run escalation again with `dmesg -w` over a second path, check PSU.
Bridge and `ips-loader` come back by themselves after a reboot (`conn_seen_map` pin
does not survive a reboot, so Stage 2.6 relies on the 30 s grace period).

## RESOLVED (code fix, hardware re-test pending): the Pi reboots were a kernel panic
Cause: `ips.bpf.c` Stage 1 did `__sync_fetch_and_add(&static_blocked->packets_dropped, 1)` on a
`threat_intel_map` (BPF_MAP_TYPE_LPM_TRIE) value. `struct lpm_ip_key` is 8 B, so the
trie stores each value 4 bytes after the node data -> value base is 4 mod 8 -> 64-bit atomic
is misaligned -> arm64 alignment fault in the RX softirq -> oops -> `panic=10` reboot.
Reproduced 4x: (1) 3 recon bans -> /24 escalation, (2) 3rd ban again with a monitor
(last sample healthy: 45 C, 5.13 V, throttled 0x0), (3) manual insert of 192.168.0.0/24 +
one attacker packet, (4) manual insert of 203.0.113.0/24 + one spoofed packet from
203.0.113.5. Inserting an entry alone (no matching packet) is harmless. Not thermal
(44 C idle, critical trip 110 C, no thermal log), not watchdog (`bootstatus` 0x0).
Impact: ANY packet whose source matches a threat-intel entry (threats.txt, /24 escalation)
crashes the box. Never seen before because no earlier test sent such a packet.
Fix: plain `+= 1` instead of the atomic (commit 6f6cd48). The journal on disk lags ~30 s,
so panic text is never persisted; the 10 s gap before reboot matched `panic=10`.
Side effect: after the hard resets the Realtek USB NIC (0bda:8156) re-enumerated as
0bda:8151 "USB CD-ROM" mode and `enx00e04c68003b` disappeared; eject / deauthorize did not
switch it back, a physical replug was needed.
Still to verify on hardware: spoofed-source packet from an LPM-matching /24 is dropped,
`packets_dropped` increments, and no reboot. Then re-run S2/S3/S4.

## Fix verified on hardware (6f6cd48)
Spoofed packets from 203.0.113.5 matching an inserted 203.0.113.0/24 entry: 5/5 dropped
(`packets_dropped: 5`), no reboot. Full 3-bans -> /24 escalation scenario + 5 follow-up packets
from the banned prefix: no reboot (Pi uptime 701 s -> 833 s).

## S3 performance (phone victim over WiFi, laptop attacker, 100 Mb/s Pi links)
| | bare bridge | IPS |
|---|---|---|
| download, Chrome on phone from laptop http.server (Mbit/s) | 35.8 / 39.3 / 35.5 | 32.3 / 36.3 / 39.5 (limiter 2000/10000) |
| RTT, 30 echo requests (ms avg) | 6.5 | 6.0 (default limiter), 6.7 (2000/10000) |
| Pi CPU busy % under hping3 SYN flood (20 s) | 1.1 / 1.1 | 0.4 / 0.6 |
WiFi-bound; no IPS overhead resolvable. Flood CPU did not stress the Pi (offered pps not measured).
Raw: `perf_results.jsonl`, `perf_results_defaultlimiter.jsonl`.

## Finding: default rate-limiter parameters break any bulk transfer
`token_bucket_max = 50`, `token_refill_rate = 20` (per source IP) means ~20 pps sustained.
With the defaults the same download got **0.0 Mbit/s**: the laptop was banned every ~42 s
(`BAN: 192.168.0.100 (rate limit exceeded) Drops: 16`). A 100 Mb/s link carries ~8,000
full-size pps. Test runs used 2000 / 10000. The limiter must be sized to the link.

## Ops notes
- The laptop auto-joined the home WiFi (DIGI-xCC4) and lost the Pi, which only knows the phone
  hotspot (SSID Ronaldo, subnet changes per hotspot restart). Set NetworkManager autoconnect
  priority of Ronaldo to 100.
- The Pi's USB NIC came back in "USB CD-ROM" mode (0bda:8151) after the panics; only a
  physical replug restored 0bda:8156.

## S2 benign false positives, run 1 (60 min, phone driven over adb, WITH pings)
Workload: 149 page loads (Chrome, 12 URLs round-robin, one every ~23 s) + `ping -c 3 8.8.8.8` after each.
Result: the benign phone (192.168.0.176) was banned **3 times** by the recon tracker
("Tokens depleted ... port/ping sweeping") at 05:12:41, 05:17:58, 05:22:01, and the third ban
triggered `Subnet Escalation! Banned entire /24: 192.168.0.0` (LAN blocked for the rest of the
run until the loader was restarted at 06:08). Ban interval ~4.5 min matches the token budget:
ICMP echo costs 1 token each with no dedup (9 echoes/min vs 40 tokens, +1 token / 300 s regen).
So an ordinary host pinging ~9 times a minute is classed as a ping sweep; and since escalation
counts bans (not hosts), three such bans of ONE benign host take down the whole /24.
Run 2 (no pings, 20 min) separates the page-load contribution; see below.
Raw: `perf_results.jsonl`, `benign_with_ping.log`.
