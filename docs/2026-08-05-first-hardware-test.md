# Today's session: first real-hardware test of the IPS

## What we set out to do

Up to this point, the IPS had only ever been tested against a fake network built with
`veth` pairs (`Jenkinstests/Flood/01_setup_veth.sh`) — two virtual interfaces on one
machine, never a real bridge, never real traffic. Today's goal was to run it for the
first time on the actual physical rig — Raspberry Pi with two NICs, a Tenda router, a
TP-Link router repurposed as a wifi access point, a laptop, and a phone — and prove two
things: that traffic actually flows through the Pi inline (bridge works), and that the
filter actually detects and blocks a real attack (flood/ban logic works).

We ended up spending most of the session chasing why devices on the network couldn't
get an IP address at all. That turned into a genuine debugging investigation with a few
false leads before finding the real cause. This document walks through the whole thing.

---

## Part 1 — Getting `ips_loader` running as a real service

Early on, we switched from running `ips_loader` by hand in an SSH terminal (which dies
the moment the SSH session drops) to running it as a proper background service
(`systemctl enable --now ips-loader.service`). This mattered because later in the
session we needed to disconnect the phone (which was providing the Pi's only internet/
SSH connection) without killing the filter.

Two small problems came up immediately:
- The systemd service file didn't exist on the Pi yet — it lived in the repo but had
  never been copied into `/etc/systemd/system/`.
- Once copied, it failed to start because the file still had **hardcoded paths from the
  developer's machine** (`/home/raul/CLionProjects/...`) instead of the Pi's actual path
  (`/home/MLC/Intrusion-Prevention-System`). We fixed this with `sed`, and this
  "path baked into a config file" theme came back later (see Part 3).

Once fixed, the service started cleanly and confirmed both NICs attached in **native
XDP mode** — the fast path for packet filtering, meaning the filter runs at the earliest
possible point in the network driver, before the normal Linux networking stack even
sees the packet.

---

## Part 2 — The big mystery: why can't anything get an IP address?

### The setup

The physical topology for testing was:

```
Laptop --(wifi)--> Tenda router --(LAN cable)--> Pi eth0 [XDP] --br0 (bridge)--
   Pi enx002432176111 [XDP] --(cable)--> TP-Link (in "dumb AP" mode) --(wifi)--> Phone
```

The Pi doesn't route or NAT anything — it's a transparent bridge (`br0`) with a packet
filter (XDP) inspecting traffic on each of its two network cards as it passes through.
The Tenda is the only thing on the network handing out IP addresses (DHCP). The
TP-Link's own DHCP server was deliberately turned off, and its own router/NAT logic was
bypassed by connecting it via one of its **LAN** ports instead of its **WAN** port —
turning it from a router into a dumb wifi bridge.

### First symptom

The phone couldn't connect to the TP-Link's wifi at all — "unable to connect." To debug
this without needing the finicky wifi radio, we substituted the laptop on a wired cable
into the TP-Link instead, since a wired connection is much easier to inspect than wifi.

### False lead #1 — is it a wrong cable/port?

The laptop got a network **link** (carrier detected, cable is good) but never got an
**IP address** — DHCP requests timed out with no reply, ever. Since we'd just learned
that AP-mode routers often disable their WAN port entirely, the first suspicion was
"wrong port." We checked, moved cables around (LAN1 → LAN2 → LAN3), and none of it
helped. This ruled out "wrong port" as the cause.

### False lead #2 — is the TP-Link's bridge config wrong?

We logged into the TP-Link's admin panel directly (had to temporarily give the laptop a
manual static IP just to reach it, since with no DHCP anywhere yet, nothing could
normally reach it). Confirmed: DHCP server off, static management IP set correctly.
This looked like a properly configured "dumb AP." Not the cause either.

### False lead #3 — is the Pi's own bridge broken?

We checked the Pi's own view of its two network interfaces directly (`ip link show`,
`bridge link show`) — both showed healthy, both were members of the bridge, both in
"forwarding" state. The bridge itself looked completely fine.

### Turning point — watching the actual packets

Rather than keep guessing, we used `tcpdump` on the Pi to literally watch DHCP traffic
live as we triggered a request from the laptop. This showed something unexpected: the
Pi's **own** `enx002432176111` network interface was sending out DHCP requests **for
itself** — using its own MAC address, not the laptop's. That's not supposed to happen;
a bridge member interface should have no identity of its own, it should just pass
frames through silently.

### False lead #4 — NetworkManager fighting the bridge

The suspicion was that Ubuntu's network manager still considered these interfaces
"its business" and kept trying to DHCP them in the background, undoing the bridge setup
behind the scenes. We checked — `nmcli device status` showed everything as
`unmanaged`. NetworkManager wasn't touching anything. Ruled out.

### The real cause, round 1 — `systemd-networkd`'s hidden fallback rule

Ubuntu doesn't just use NetworkManager — it can also use a second, separate system
called `systemd-networkd` to manage interfaces, and this Pi image used that instead.
Buried in `/run/systemd/network/`, we found a file called `zzzz-dracut-default.network`
(installed by the base OS image itself, not something we ever wrote) containing:

```
[Match]
Kind=!*
Type=!loopback
[Network]
DHCP=yes
```

In plain terms: "for literally any real network interface that isn't otherwise
configured, try to get it a DHCP address." Since nothing else claimed `eth0` or
`enx002432176111` by name, this generic fallback rule quietly grabbed both of them and
tried to run its own independent DHCP client on each — fighting the bridge setup the
whole time. We fixed this with a small override file
(`/etc/netplan/05-ips-bridge-members.yaml`) that explicitly tells the system "leave
these two interfaces alone, no DHCP" — a name-specific rule takes priority over the
generic fallback.

This fixed **half** the mystery: the Pi stopped fighting itself. But laptop DHCP
requests *still* timed out.

### The real cause, round 2 — the filter itself was the problem

With `tcpdump` running again, we could now clearly see the laptop's DHCP request
correctly crossing the bridge (`arrives on enx002432176111` → `leaves via eth0` →
towards the Tenda), microseconds apart. The bridge was proven completely healthy. But
still, no reply ever came back.

The key insight: XDP in **native mode** runs so early in the network driver that a tool
like `tcpdump` — which taps in further up the stack — **cannot see packets that get
dropped by XDP**. If our own filter was silently dropping the Tenda's reply on the way
back in, it would look exactly like "nobody replied," indistinguishable from the
outside.

We tested this directly: stopped the filter entirely (`systemctl stop
ips-loader.service`), tried DHCP again — and it worked immediately, with a real,
correctly-formed DHCP reply from the Tenda. That confirmed: **our own filter was
dropping the return traffic.**

### Finding the exact reason — a dummy test file shipped as if it were real

Digging into the filter's logic (`ips.bpf.c`), one code path stood out: a **static
threat-intel blocklist**, meant to hold known-malicious IP ranges fed in from
`fast_path/threats.txt`. A match there gets dropped instantly, with **zero logging** —
unlike other ban types, which at least get written to a log file. That silence matched
everything we'd seen: no ban ever showed up anywhere, yet the block was instant and
consistent.

Checking `fast_path/threats.txt` on the Pi confirmed it: the file was **explicitly
labeled as dummy test data** ("Dummy OSINT Threat Feed — Designed to test the C
parser"), never meant to ship to a real device. It contained the line `192.168.0/16` —
a private IP range covering `192.168.0.0` through `192.168.255.255`. That single line
was silently banning the Tenda (`192.168.0.1`), the TP-Link (`192.168.0.250`), and the
laptop itself — essentially the entire local network — the instant the filter saw any
of their traffic.

We removed the bogus entries from `threats.txt` and restarted the filter. DHCP worked
immediately, filter fully active. The phone's wifi — which had been failing with a
generic "unable to connect" the whole time — also started working the moment we fixed
this, confirming it was the exact same root cause all along (many phones report a DHCP
timeout as a generic connection failure).

---

## Part 3 — The actual tests (finally!)

With everything working, we ran the two tests we'd originally set out to do:

**Ping test (does the bridge pass real traffic?)** — from the laptop (now properly on
the Tenda, simulating an "internet-side" attacker) to the phone (on the TP-Link's wifi,
simulating a protected home device): **0% packet loss**. Real traffic proven to cross
`Tenda → Pi (bridge + filter) → TP-Link → phone` and back, for the first time on real
hardware.

**Flood test (does the filter actually detect and block an attack?)** — ran a scripted
packet flood from the laptop at the phone. Result: the laptop's real IP got banned —
confirmed both in the Pi's live filter state and in its persisted ban log
(`data/blocklist.csv`) — and a follow-up ping from the laptop timed out completely
(100% loss), proving the block wasn't just *logged*, it was actually *enforced*.

We agreed the allowlist bootstrap ("5 clean packets → trusted") test is still
outstanding for a future session.

---

## Part 4 — Cleaning up git (the "why did pushing get complicated" part)

Once the tests passed, you asked to save the fixes. This surfaced a design problem: a
handful of files in the repo were being treated as normal shared source code, but their
*correct* values are actually different on every machine that runs this project:

| File | Why it's machine-specific |
|---|---|
| `config/config.ini` | Network interface names (`eth0`/`enx0024...` on the Pi vs. different names on any other box) |
| `scripts/ips-loader.service` | Absolute filesystem paths (`/home/MLC/...` on the Pi vs. `/home/raul/...` on the dev laptop) |
| `data/*.csv` | Live ban/allowlist state — this machine's runtime output, not source code |
| `fast_path/vmlinux.h` | Regenerated per target kernel via `bpftool`, not portable between machines |

Before today, all of these were tracked in git — meaning every time someone pushed,
they risked overwriting the *next* machine's real settings with their own, or
accidentally publishing another device's live ban list. We fixed this properly:

1. Added all of them to `.gitignore`, so git stops watching them entirely, on every
   machine, going forward.
2. Added two `.example` template files (`config.ini.example`,
   `ips-loader.service.example`) with placeholder values and comments, so a fresh clone
   still knows what to fill in.
3. Used `git rm --cached` (not a normal delete!) on each file — this tells git "stop
   tracking this," while leaving the actual file completely untouched on disk. Nothing
   about the Pi's real, working configuration was ever deleted.

### Why the push/pull got messy

This is the part that probably felt confusing, so here's the plain version:

- The laptop pushed its changes to GitHub first (the `.gitignore` update).
- The Pi's local copy of the repo hadn't caught up yet, *and* it had its own
  uncommitted local edits sitting in several of those same files (its real IP
  addresses, real paths, today's real ban list). Git refused to blindly overwrite that
  local data — it stopped and asked us to sort it out first. That's git behaving
  correctly and safely, not a bug.
- We resolved it by explicitly telling git on the Pi, too, "stop tracking these files"
  (mirroring what we'd already done on the laptop), which reconciled the two sides.
- Along the way, git also needed a one-time "how do you want conflicts resolved,
  merge or rebase?" setting (a newer git default that isn't auto-decided), and there
  was one specific naming conflict (the old `ips-loader.service` file being renamed to
  `ips-loader.service.example` on one side, deleted on the other) that needed a manual
  "yes, keep the new template file" confirmation.
- One side effect: your original `threats.txt` fix had been sitting "staged but not
  committed" since a much earlier failed commit attempt (git wasn't configured with
  your name/email yet at that point). When the merge was finally committed, it swept
  that pending change in along with it. Functionally harmless — the fix is confirmed
  live on GitHub — just bundled under a commit message that doesn't mention it by name.

### End state

Everything of value from today is now saved on GitHub:
- The real `threats.txt` fix (dummy dangerous test data removed).
- The flood-test script's new ability to target real IPs instead of only the fake test
  network.
- The `.gitignore`/`.example` restructuring, so this class of problem — one machine's
  local settings overwriting another's — can't happen again.

Nothing machine-specific (the Pi's real interface names, its real file paths, today's
real ban list) was ever pushed anywhere. It all stays local to the Pi, exactly as it
should.

---

## Open items for next time

- Allowlist bootstrap test (5 clean packets from one source → that flow gets trusted
  and skips future inspection) — not yet run on real hardware.
- The dummy `threats.txt` should eventually be replaced by the real automated
  threat-intel feed (`ips-threat-intel-update.timer`, already built, just not the
  active data source on this Pi yet).
- Persisting the bridge setup across a reboot is still unresolved (`setup_bridge.sh`
  intentionally doesn't handle this — it re-runs on every service start instead, which
  is sufficient as long as the systemd service itself is enabled to start on boot, but
  wasn't verified today).
