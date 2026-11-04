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
