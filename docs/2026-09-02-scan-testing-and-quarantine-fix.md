# Today's session: scan-detection hardware testing + a real quarantine bug found and fixed

## What we set out to do

Pick up hardware testing on the Pi 5 rig after a chunk of new detection logic landed in
the previous dev session (uncommitted at the time, now committed as `c3b328f`, `1811b3b`,
`3366ab1`): protocol/port conformance checks (TLS/HTTP/SSH), a fix for bare-FIN scans
slipping past the malformed-flags check, IP-fragmentation blanket-drop with a whitelist
exemption, and new stateful ACK/Window/Maimon scan detection with a startup grace period.
None of it had been run against real traffic yet. Goal for today: verify basic
connectivity on the (slightly changed) rig, then confirm the malformed-TCP-flag scan
detection actually works end to end.

We also hit a real, previously-undiscovered bug along the way — a quarantine mechanism
with no expiry at all — found it, root-caused it, and fixed it same-session. That fix is
committed and live on the Pi as of tonight. Full story below.

---

## Part 0 — Topology, since it changed since the last hardware-test doc

```
Tenda router (attacker: dev laptop, 192.168.0.100/.134 on enp2s0)
   -> Pi 5 [eth0=WAN facing Tenda, enx002432176111=LAN facing TP-Link, XDP bridge]
   -> TP-Link (AP mode + WiFi)
   -> switch
   -> victim: second laptop, CachyOS, 192.168.0.126/24
```

The switch behind the TP-Link and the CachyOS laptop as victim are new this session —
previously the victim side was just a phone. Pi management is still out-of-band (phone
hotspot + SSH), unrelated to the bridge itself. `192.168.0.1` is the Tenda's own gateway
address, visible to both attacker and victim since they're all on the same
`192.168.0.0/24` L2/L3 segment bridged straight through by the Pi.

---

## Part 1 — Gotcha: `systemctl restart` does not rebuild anything

First attempt to get today's code onto the Pi: `git pull` + `sudo systemctl restart
ips-loader`. This looked like it worked (service came back up, no errors) but **it
wasn't actually running any new code** — two compounding reasons:

1. The Pi's checkout had a local, uncommitted edit to `local_analysis/recon_tracker.c`
   (an old `STARTING_TOKENS`/`MAX_TOKENS` 10→40 tweak from a prior session, done directly
   on the Pi and never committed/reconciled). This made `git pull` abort outright with a
   merge conflict, so the fetch happened but nothing merged — the working tree stayed on
   the old `d86906e` tip.
2. Independently of that: `ips-loader.service`'s `ExecStartPre` only runs
   `setup_bridge.sh` (idempotent bridge setup), and `ExecStart` runs the **already-built**
   `build/inline_bpf/ips_loader` binary directly. There is no build step anywhere in the
   unit. So even with a clean pull, a bare `systemctl restart` only reloads whatever
   binary happened to be sitting in `build/` already — it never recompiles.

Fixed by: `git stash` (dropping the stale local edit — it predated and was superseded by
what was already merged upstream), `git pull` (fast-forwarded `d86906e..3366ab1` cleanly),
then an explicit `cd build && cmake --build . --target ips_loader` **before** the
`systemctl restart`. Confirmed via the fast-forward's file list
(`ips.bpf.c`/`ips_fast_common.h`/`main.c`/`config.ini.example`, matching exactly what
changed this session) and a clean rebuild + native XDP re-attach on both interfaces in
the journal.

**Lesson for next time**: always pair a Pi-side `git pull` with an explicit rebuild step
before restarting — the service will happily restart on stale code with zero indication
anything is wrong.

---

## Part 2 — A red herring that turned into a real bug: the victim got banned before we even started

First test was a plain `ping 192.168.0.126` from the attacker box. It failed 100% —
before any scan had been run at all. ARP resolved fine both ways (`ip neigh` showed
`REACHABLE` for both `.126` and the gateway `.1`), but ICMP and a follow-up `nmap -Pn -sS`
both came back completely dead (every port `filtered`, no RST, no reply of any kind).

Checked the Pi's journal and found the actual cause: `.126` had been banned by **Stage 2
(the rate limiter)** — 16 drops, one over `max_tolerated_drops = 15` — apparently from its
own traffic, not from anything we sent. Likely a burst of normal join-time chatter from a
fresh Linux desktop associating to the AP (NetworkManager's connectivity check,
avahi/mDNS, IPv6 RA/DAD, etc.) tripping a rate limiter tuned for attack traffic. This
ban self-expired 60s later exactly as configured (`ban_duration_seconds` is set short on
this rig for fast iteration) — but connectivity *still* didn't come back.

Root cause of *that*: Stage 0.5 (quarantine). Its logic bans any source caught sending a
packet toward a destination that's currently in `dynamic_bans_map` — so the moment we
(the attacker box) sent anything toward the momentarily-banned `.126`, *we* got
quarantined too. That part is by design. The bug: `quarantine_map` had **no expiry
mechanism at all** — a plain `BPF_MAP_TYPE_HASH`, never touched anywhere in `main.c` (no
aging sweep, no CSV persistence, nothing), so once quarantined, a source stayed
quarantined **permanently**, until the next full `ips-loader` restart — long after the
destination's own ban (the reason for the quarantine in the first place) had expired.
This is exactly the "silently and permanently locks out something innocent" failure mode
the in-code comment already flagged for infrastructure devices specifically, just not
yet fixed for the general case.

### The fix (implemented and committed this session, `3366ab1`)

- `quarantine_map`'s value changed from a bare `__u8` flag to `struct ips_quarantine_data
  { __u64 quarantine_start_ns; }` (boot-monotonic, same clock domain as everything else
  in-kernel).
- New rodata `quarantine_duration_ns`, set from a new `quarantine_duration_sec` config
  field (`config.ini`'s `quarantine_duration_seconds`, default 300s, independent of
  `ban_duration_seconds` on purpose — different failure mode).
- Stage 0.5 now checks elapsed time on lookup; an expired entry gets deleted and the
  source is re-evaluated on the same packet — if the destination is *still* actively
  banned right now, it gets freshly re-quarantined (sliding-window style), otherwise it's
  treated like anyone else.

Verified via a full local `cmake --build` (clean) before pushing, and confirmed present
on the Pi after tonight's pull+rebuild (`git log` on the Pi now shows `3366ab1` as HEAD).
Not yet re-tested live on hardware against a fresh quarantine scenario — that's on the
list for tomorrow.

---

## Part 3 — Malformed-flag scan detection: clean 4-for-4

With today's code confirmed actually running, re-ran the ping test (0% loss, ~1ms RTT —
fine) and then the actual scan battery from the attacker box (`192.168.0.100`) against
`.126`:

- `nmap -sN` (NULL scan)
- `nmap -sF` (FIN scan)
- `nmap -sX` (Xmas scan)
- `hping3 -S -F` (SYN+FIN)

**All four got the attacker instantly banned** (`malformed TCP flags`, `Drops: 0` — this
reason bans on the very first offending packet, no drop-count accumulation, so `Drops: 0`
in the log is expected/correct here, not a bug). Every scan reported `open|filtered` on
every port as a direct consequence — our own probes got dropped before a real
open-vs-closed distinction could ever come back, which is the intended defensive outcome:
the scan's intelligence-gathering value is neutralized, not just logged after the fact.

This confirms both fixes from the prior session are working on real hardware: the
bare-FIN case (`is_malicious_tcp_flags()`'s `tcp->fin && !tcp->ack` branch) and the
original SYN+FIN/NULL/Xmas cases.

---

## Part 4 — New finding, not yet fixed: Stage 2.6 banned the gateway

Before we'd even started the scan battery (15:38:45, well after the 30s startup grace
period ended around 15:33:14), the journal showed:

```
[!] BAN: 192.168.0.1 (out-of-state ACK (ACK/Window/Maimon scan)) Drops: 0
```

`.1` is the Tenda gateway. Root cause: `conn_seen_map` (which Stage 2.6 checks to
validate a bare ACK/FIN-ACK belongs to a real handshake) starts completely empty on every
`ips_loader` restart. The startup grace period protects existing connections *for a fixed
30s window* after a restart, but if a legitimate long-lived connection through the
gateway goes quiet for exactly that long and then sends its next ACK afterward,
`conn_seen_map` never recorded its SYN (it happened before this process existed) and the
grace period has already closed — so it gets flagged as out-of-state and banned. Banning
the gateway itself is a real availability problem, not a cosmetic one.

Discussed two possible fixes:
- **Exclude-list exemption** (mirroring the `excluded_srcs` pattern already used in
  Stages 0.05/0.5): quick, low-risk, but only protects specifically-named IPs — any other
  legitimate host with the same restart-timing bad luck (e.g. a LAN server with a
  keepalive session) would hit the identical false positive and needs to be added by
  hand.
- **Persist `conn_seen_map` across restarts** (pin it to bpffs the same way
  `threat_intel_map` already is, and have `main.c` reuse the existing pinned map on load
  instead of always creating fresh): the actual root-cause fix — a SYN this process saw
  before a restart is still valid after one, for every host, not just named infra.
  Doesn't weaken the check itself (a real attacker still has to have produced a genuine
  SYN we witnessed at some point). More work: needs reuse-on-existing-pin logic in
  `main.c`, and a plan for what happens if `struct flow_key`'s layout changes in a future
  code update and the pinned map's schema no longer matches.

Also considered and **rejected**: having Stage 2.6 auto-add a flow to `conn_seen_map` the
first time it sees a bare ACK instead of requiring an actual prior SYN. This isn't a
fix — it defeats the whole check, since a real ACK/Window/Maimon scan's first probe would
just get itself silently whitelisted.

**Decision: hold off on both for now. The real fix (persisting `conn_seen_map` via
pinning) is next session's task, not tonight's.** Nothing has been implemented for this
finding yet — the gateway-ban issue is still live on the current code as of tonight.

---

## State at end of session

- Committed and pushed: `3366ab1` (quarantine aging fix), on top of `1811b3b` and
  `c3b328f` from the prior session (protocol conformance, fragmentation whitelist,
  ACK/Window/Maimon detection + grace period, bare-FIN fix). Working tree clean.
- Pi rebuilt and running `3366ab1` as of tonight (confirmed via `git log` on the Pi and a
  clean native XDP re-attach in the journal).
- Confirmed working on real hardware tonight: basic bridge connectivity (ping), and
  malformed-TCP-flag detection (NULL/FIN/Xmas/SYN+FIN, all four banned correctly).
- Confirmed (independently of anything we tested) that Stage 2's rate limiter + Stage
  0.5's quarantine cascade can still ban a device for its own ordinary background
  traffic — not a new bug, pre-existing behavior, just something to expect if a freshly-
  joined device looks unusually chatty for a few minutes.

## Pending for next session

1. **Implement the real fix for Part 4**: pin `conn_seen_map` to bpffs and have
   `main.c` reuse it across restarts instead of recreating it fresh each time. This is
   the agreed next task — start here.
2. Re-test the quarantine aging fix (Part 2) against a fresh live quarantine scenario on
   hardware — today only confirmed it compiles/builds and is running, not that the TTL
   itself behaves correctly against a real repeat scenario.
3. Still not tested this session (carried over from before): IP fragmentation defense
   (`nmap -f`/`--mtu`), protocol/port conformance (TLS/HTTP/SSH banner mismatch on
   80/443/22), recon/port-sweep tracker, DNS/TLS/HTTP blocklist matching, allowlist
   bootstrap.
4. Still open from earlier sessions, not touched at all this session: dynamic (not
   static-config-based) infrastructure-IP discovery for quarantine/greylist exemption.
5. Full synproxy/SYN-cookie implementation remains explicitly deferred by the user until
   after more eBPF verifier experience is built up — not on the near-term list.

See also `docs/2026-08-05-first-hardware-test.md` for the first-ever hardware session
and the recurring "silent XDP_DROP path" bug class documented there — unrelated to
today's findings, but worth checking if a future session hits an unexplained
connectivity dead end again.
