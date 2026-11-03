# 2026-11-04 — XDP attach mode finding, rig changes, and requirements for the embedded target

Context: preparing the hardware test campaign for the scientific paper (detection matrix,
false positives, performance, restart robustness). This note records what turned up while
bringing the rig back to a testable state, and turns the main finding into requirements for
the final embedded device. The Pi 5 is a **prototype platform**; the product target is a
dedicated embedded device whose hardware is still to be chosen.

---

## 1. Main finding: XDP runs in generic (SKB) mode on both NICs

`bpftool net` on the Pi shows `eth0(2) generic` and `enx00e04c68003b(3) generic`;
`ip link` shows `xdpgeneric`. Earlier logs and notes (including `2026-08-05-first-hardware-test.md`)
said "native mode". That was wrong, for two reasons:

1. **Neither driver implements native XDP on this kernel.** Kernel `7.0.0-1020-raspi`:
   - `eth0` = `macb` (Pi 5 built-in, RP1). `/proc/kallsyms` lists 97 `macb_*` symbols,
     none XDP/BPF related.
   - `enx00e04c68003b` = `r8152` (Realtek RTL8156B USB 2.5GbE adapter, here linked at
     100 Mb/s). 12 `r8152_*` symbols, none XDP related.
2. **The log message was misleading.** `attach_xdp()` in `inline_bpf/main.c` called
   `bpf_program__attach_xdp()`, which passes no mode flags. For a driver without
   `ndo_bpf`, the kernel then attaches in generic mode instead of failing, so the
   "native" branch was taken and printed "native mode" regardless. The explicit
   `XDP_FLAGS_SKB_MODE` fallback was therefore never reached.

Fix (this session): after a successful attach, `attach_xdp()` now calls `bpf_xdp_query()`
and logs the mode the kernel actually chose (native / generic / hardware offload).

### Consequences

- In generic mode the `sk_buff` is **already allocated** when the XDP program runs. The
  drop happens before the protocol stack, but **not** before `sk_buff` allocation.
  Any statement in the paper or documentation that XDP drops "before `sk_buff`
  allocation" is not true for this prototype and must not be used for it.
- Detection logic and results are unaffected. CPU/throughput numbers measured on the
  Pi are a conservative **lower bound** on what a native-mode device would achieve.
- Mixed modes on one bridge are legal (one port native, one generic) but make
  performance harder to reason about; both ports should be native on the product.

### Other rig facts recorded today (for the paper's setup section)

- Pi 5 Model B Rev 1.1, 8 GB RAM (7931 MiB), 4 cores, kernel `7.0.0-1020-raspi`.
- WAN `eth0` (`macb`) and LAN adapter (`r8152`, RTL8156B, firmware `rtl8156b-2 v3`)
  both negotiated **100 Mb/s**, so the throughput ceiling is about 94 Mbit/s.
- The LAN adapter changed since 2026-09-02 (`enx002432176111` -> `enx00e04c68003b`);
  `lan_interface` in the Pi's `config/config.ini` was updated.
- `unattended-upgrades` ran a ~150-package batch (including the kernel, libc and
  `sudo-rs`) while the rig was idle and blocked `poweroff`. Disabled via
  `/etc/apt/apt.conf.d/99-no-auto-upgrade` for the duration of the test campaign.
  Re-enable afterwards, or at least pin the kernel for any measurement run.

---

## 2. Requirements for the embedded target (input for the traceability matrix)

Proposed new requirements. IDs are placeholders; assign real IDs in
`Matrice_Trasabilitate_Cerinte_IPS` when merging.

| ID (proposed) | Requirement | Rationale |
|---|---|---|
| HW-NATIVE-01 | Both bridged data-plane NICs shall use drivers with **native XDP** (`ndo_bpf`, `XDP_DRV`) support in the shipped kernel. | Generic mode runs after `sk_buff` allocation; the zero-allocation drop path is the performance premise of the design. Not met by Pi 5 `macb` or USB `r8152`. |
| HW-NATIVE-02 | The loader shall report the **actual** XDP attach mode per interface at startup, and shall be configurable to refuse to start (or to alarm) when native mode is unavailable. | The prototype silently ran generic mode while logging "native". |
| HW-NATIVE-03 | Native-mode support shall be verified on the target kernel/driver combination (e.g. `bpftool net`, `ip link` showing `xdp`/`xdpdrv`, not `xdpgeneric`) as part of acceptance testing, not assumed from the driver family. | Support varies per kernel version and driver build. |
| HW-LINK-01 | Data-plane links shall run at the rated line speed (target to be set; the prototype ran at 100 Mb/s). Throughput claims shall state the negotiated link speed. | Link speed capped all prototype throughput measurements. |
| HW-LINK-02 | Both bridge ports shall be on the same driver family or have documented, measured behaviour when they differ. | Mixed native/generic ports complicate performance reasoning. |
| HW-MGMT-01 | Management access shall be on an interface that is not part of the bridge (out of band). | Already true on the prototype (Wi-Fi); keep as a hard requirement. |
| SW-STATE-01 | Connection-tracking state (`conn_seen_map`) shall survive a loader restart (pinned map) and the Stage 2.6 startup grace period shall remain as a fallback. | Gateway false-ban found on 2026-09-02; fix in `ab537f3`/`d9c41e2`. |
| SW-OPS-01 | Unattended OS updates shall not run unsupervised on the production device, or shall be limited to security updates that do not change the kernel or networking stack without a controlled reboot. | A kernel/libc update plus an auto-reboot would silently change driver and XDP behaviour. |

### Candidate families to evaluate (must be verified per kernel before relying on them)

Drivers known to have in-tree native XDP support in recent mainline kernels include
Intel (`igb`, `igc`, `ixgbe`, `i40e`, `ice`), Mellanox (`mlx5`), Marvell (`mvneta`,
`mvpp2`), NXP (`enetc`, `dpaa2`), `stmmac` (STM32MP / Intel embedded SoCs) and `veth`
(virtual, useful for CI). Realtek USB (`r8152`) and, on the current Raspberry Pi kernel,
`macb` do not. This list is from general knowledge, **not verified in this session**;
treat it as a shortlist to check, not a guarantee.

Option for the prototype if native-mode numbers are wanted for the paper: a PCIe NIC on the
Pi 5 (M.2 HAT / PCIe adapter) with an Intel `igb`/`igc` card, run once as an additional
data point (native vs generic CPU under flood).

---

## 3. Process notes (so they are not rediscovered)

- **`sudo-rs` on the Pi** (Ubuntu, `sudo-rs 0.2.13`): `/etc/sudoers-rs`, if it exists,
  **replaces** `/etc/sudoers`. Creating it with a single rule (via `visudo -f
  /etc/sudoers-rs`) silently removed every other rule, including the `%sudo` group, and
  locked the user out of sudo. Recovery required editing the SD card from another
  machine. Do not create `/etc/sudoers-rs` unless it contains a complete ruleset.
- A `NOPASSWD: ALL` rule for `MLC` was still not honoured by `sudo -n` even after that
  was fixed (`sudo -l` lists only the `%sudo` rule); not root-caused. Workaround for the
  test campaign: privileged commands over SSH use `sudo -S` with a password on stdin
  (test device only).
- `systemctl restart ips-loader` does not rebuild; always `cmake --build` first
  (see `2026-09-02-scan-testing-and-quarantine-fix.md`).
- Raw-socket tools on the attacker laptop (`nmap`, `hping3`, `arp-scan`) were given
  `cap_net_raw,cap_net_admin+eip` via `setcap`; revert with `sudo setcap -r <file>` after
  testing.
