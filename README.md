# Linux Traffic Guard

[![CI](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Ubuntu](https://img.shields.io/badge/Target-Ubuntu-orange.svg)

Languages: English | [简体中文](README.zh-CN.md)

Linux Traffic Guard (`ltg`) is a server traffic and protection operations tool for Ubuntu/Debian hosts. It gives operators one terminal UI for answering three practical questions:

- Which ports are moving traffic, and which IPs are behind that traffic?
- Which sources are being blocked by UFW, and which ports are they probing?
- Are the fail2ban policies actually loaded, banning, and landing deny rules in UFW?

It is not a passive dashboard and it is not a wrapper around shell scripts. LTG is a modular C++17 program with a pure ANSI TUI, prebuilt release binaries, self-tests, reliability checks, and conservative confirmation prompts for actions that modify `nftables`, UFW, or fail2ban.

## What It Solves

On a small or self-managed Linux server, the useful information is often split across unrelated tools:

- `vnstat` shows traffic over time, but not per service port and source IP.
- `ufw` shows firewall rules, but not a clear attacker/source analysis view.
- `fail2ban-client status` tells you jails exist, but not whether a ban really becomes a UFW deny rule.
- `journalctl`, `/var/log/ufw.log`, `nft list ruleset`, and `conntrack` are accurate, but slow to read during an incident.

LTG joins those paths into one workflow:

1. Track chosen service ports with nftables counters.
2. Snapshot counters every 5 minutes into a local history store.
3. Show port-level vnStat-style day/month/year traffic with optional IP detail drilldown.
4. Parse UFW BLOCK/AUDIT/ALLOW logs with cache-backed source and port analysis.
5. Install, repair, and verify fail2ban policies for SSH and slow UFW port scans.
6. Run reliability checks that distinguish "configured" from "actually working".

## Quick Install

Most users should install the prebuilt Linux x86_64 binary from the latest GitHub Release:

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o ltg
chmod +x ltg
sudo install -Dm755 ltg /usr/local/bin/ltg
ltg bootstrap
```

`ltg bootstrap` is the first-install path. It auto-escalates with `sudo`, checks for required runtime tools, installs only the missing runtime dependencies, writes the two built-in fail2ban policies (`sshd` and `ufw-slowscan-global`), enables/reloads fail2ban, runs a temporary ban probe to verify that rule 2 lands in UFW and is cleaned up, and auto-enables traffic accounting for detected externally listening ports. It does not silently enable UFW because that can lock out SSH; if UFW is inactive, the bootstrap result will say which layer is not fully effective.

Open the TUI after bootstrap completes:

```bash
ltg
```

In an interactive terminal, `ltg` auto-re-runs itself through `sudo` when root is required. You can still run `sudo ltg` directly if you prefer. Normal confirmation pages use single-key decisions (`y`, `n`, `q`, `Esc`, or `Enter` for the default), result pages return with `Enter`, `Backspace`, `q`, or `Esc`, and long previews keep vim-style scrolling, so remote sessions do not need extra prompt round trips.

If you open the TUI before running `ltg bootstrap`, LTG now detects an incomplete first-run environment and shows a compact one-click setup page. That page installs missing runtime tools, configures the two default fail2ban protections, starts/reloads fail2ban, verifies the temporary UFW landing path, and auto-enables traffic accounting for detected externally listening ports. Normal ready systems skip this page and go straight to the dashboard.

The same setup page also appears when protection is already ready but traffic accounting is still off and LTG can detect externally listening ports. In that case it skips the repeated fail2ban active probe and only repairs the missing pieces.

The same repair path is available later from the TUI main menu as `One-click repair`. It installs packages only when core tools are missing; otherwise it skips apt and goes straight to validating and repairing the fail2ban protection stack and traffic accounting chain. The dependency check page also offers this repair path directly when it sees missing core tools or auto-detectable traffic ports.

Common actions also check their own prerequisites before doing work. For example, traffic accounting and UFW analysis offer to install missing runtime tools before showing a command failure. UFW analysis also offers to install the optional DB-IP Lite country database when the country/region column would otherwise be empty. Fail2ban actions such as IP disposition, dual-log audit, UFW sync, ban details, and active probes can repair missing or unloaded default jails in place. Fail2ban configuration edits also run `fail2ban-client -t` and `fail2ban-client reload` automatically after a successful write, so users do not need to remember a separate restart step.

Traffic accounting setup is also repair-friendly: first-run setup auto-detects externally listening ports and enables sampling for them. If ports are already being tracked, pressing Enter on the port prompt reuses the existing port set, refreshes the nftables rules and systemd timer, and records a fresh snapshot instead of forcing you to retype the same ports.

Update later with the built-in updater:

```bash
ltg update
```

`ltg update` is the unified entry point. If it is not already running as root, LTG re-runs itself through `sudo` in an interactive terminal and through `sudo -n` in remote/non-interactive automation, so sudo cannot wait forever for a password prompt. If you explicitly prefix the command with sudo yourself, use `sudo -n ltg update` in remote runners because sudo runs before LTG can choose the safer mode. The updater also bounds download, checksum, install, and version-probe steps with timeouts, so a network stall should report failure instead of leaving a busy remote process behind.

You can also repeat the direct download command to overwrite the installed binary:

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg
sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
```

## One-Off Root SSH Setup Script

This repository also includes `setup-root-ssh-once.sh`, a standalone one-time helper for initializing root SSH access on a new or temporary server.

It:

- Requires a manually entered non-`22` SSH port.
- Asks for the full public key line from a `.pub` file, rejects private keys, file paths, and broken keys, and validates the key with `ssh-keygen -l -f`.
- Writes the key to `/root/.ssh/authorized_keys`.
- Adds an early SSH drop-in for `PermitRootLogin prohibit-password`, `PubkeyAuthentication yes`, and `AuthorizedKeysFile .ssh/authorized_keys`, which covers hosts that disabled public-key login.
- Ensures `/etc/ssh/sshd_config` includes `/etc/ssh/sshd_config.d/*.conf` near the top so the managed key-login settings are read early.
- Keeps detected existing SSH entry ports in the managed config, including the current SSH connection port, existing sshd effective ports, ssh.socket `ListenStream` ports, and `22` when it is available as a rescue port.
- Runs both `sshd -t` and `sshd -T -C user=root,host=localhost,addr=127.0.0.1` to verify root's effective SSH config.
- Handles `ssh.socket` systems with a systemd socket override.
- Opens the new port in UFW/firewalld before validating and reloading SSH; it restarts only when reload is unavailable.
- Rolls back SSH config and socket overrides if validation, service update, new-port listen checks, or preserved-entry listen checks fail. Firewall rules added by the script are left for manual cleanup.
- Never closes `22` or any detected existing SSH entry port. Tighten old ports manually only after the new port is confirmed stable.

Run it directly:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/furina123123123/linux-traffic-guard/main/setup-root-ssh-once.sh)
```

If the current user is not root:

```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/furina123123123/linux-traffic-guard/main/setup-root-ssh-once.sh)
```

Example Windows client key generation:

```powershell
ssh-keygen -t ed25519 -f C:\Users\furina\.ssh\gcp_root_ed25519
```

Paste the full single-line contents of the `.pub` file:

```text
C:\Users\furina\.ssh\gcp_root_ed25519.pub
```

After the script finishes, keep the current SSH session open and test from a new terminal:

```bash
ssh -p NEW_PORT root@YOUR_SERVER_IP
```

The script does not close `22`. After the new port is stable, manually review the cloud firewall, UFW, and `/etc/ssh/` config before tightening old ports.

For cloud servers, also open the new TCP port in the provider security group or cloud firewall. The script can only update firewall rules inside the server.

## Main Workflows

### 1. Port-Level Traffic Accounting

LTG is meant to behave like a port-level vnStat with IP visibility:

- Add or remove tracked ports without rebuilding the whole accounting table by default.
- Auto-detect externally listening service ports and prefill them as the recommended first tracking set.
- Keep historical day/month/year data when appending new ports.
- Sample nftables counters every 5 minutes through a systemd timer.
- View day/month/year traffic in rolling-window or absolute-period mode.
- Read each period as `period + port` rows: host inbound, host outbound, total, and packets.
- Drill down from a port into IP-level outbound/inbound details.

Example TUI path:

```text
sudo ltg
Traffic accounting -> Add/append ports
Traffic accounting -> Day traffic / Month traffic / Year traffic
```

Internal storage:

- History directory: `/var/tmp/linux_traffic_guard_traffic_history_v1/`
- SQLite when available, TSV fallback in no-SQLite builds.
- systemd timer: `linux-traffic-guard-traffic-snapshot.timer`

### 2. UFW Threat Analysis

LTG parses UFW kernel log events and turns them into an operator-readable investigation view:

- Top source IPs.
- Top probed ports.
- Per-IP port distribution.
- Raw evidence summary: source, time window, matched lines, public SRC rows, filtered private/invalid rows, BLOCK/AUDIT/ALLOW counts, and missing-DPT counts.
- Cache-backed repeated analysis so the second load does not rescan old rotated logs.
- Optional country/region labels using DB-IP Lite MMDB.

Example commands:

```bash
sudo ltg --ufw-analyze 24h
sudo ltg --ufw-analyze 7d
```

Cache directory:

```text
/var/tmp/linux_traffic_guard_ufw_cache_v2/
```

The cache is only an analysis accelerator. It does not affect firewall or fail2ban decisions.

### 3. fail2ban Protection Management

LTG manages two default protection policies:

- `sshd`: SSH brute-force protection.
- `ufw-slowscan-global`: slow multi-port scan escalation based on UFW BLOCK/AUDIT logs.

The policy repair flow can, after confirmation:

- Install missing `fail2ban` and `ufw` packages on Ubuntu/Debian.
- Write or repair fail2ban filter/action/jail config.
- Run `fail2ban-client -t`.
- Enable and reload the fail2ban service.
- Verify both default jails are loaded.
- Run a reversible test ban for `203.0.113.254`.
- Confirm the test ban appears in the jail banned list and lands as a UFW deny rule.
- Unban and clean up the temporary UFW rule.

LTG only reports the policies as effective when the whole chain passes.

### 4. Reliability Checks

The reliability check is for "prove it is working" moments:

```bash
sudo ltg --reliability-check
sudo ltg --reliability-check --active-probes
```

The default check is read-only. Active probes are explicit and can perform temporary ban/snapshot/diagnostic write tests, then attempt cleanup. Results are grouped by dependency, update, protection, traffic accounting, UFW analysis, diagnostics, and TUI terminal state.

## CLI Reference

```bash
ltg --help
ltg --version
ltg --self-test
sudo ltg --status
sudo ltg --ip-traffic
sudo ltg --traffic-snapshot
sudo ltg --ufw-analyze 24h
sudo ltg --f2b-audit
sudo ltg --doctor
sudo ltg --export-report
sudo ltg --reliability-check
ltg update
```

Commands except `--help`, `--version`, and `--self-test` require root privileges. The interactive TUI and `ltg update` can be run without a sudo prefix; LTG will choose interactive sudo or non-interactive `sudo -n` based on the terminal. The TUI uses the alternate screen and restores the terminal on normal exit or signal handling.

## Requirements

Target platform:

- Ubuntu 22.04/24.04 or compatible Debian/Ubuntu servers.
- systemd-based hosts are expected for timer/service workflows.

Runtime/build dependencies:

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl mmdb-bin
```

From a source checkout:

```bash
make deps
```

`make deps` performs the same missing-only package check used by `make bootstrap`; ready systems skip apt instead of reinstalling packages.

At runtime, LTG calls system tools such as `nft`, `ufw`, `fail2ban-client`, `journalctl`, `ss`, `conntrack`, `systemctl`, and optionally `mmdblookup`.

## Optional IP Country Lookup

LTG can show country/region labels beside source IPs in UFW source tables and traffic IP detail tables. This uses the free [DB-IP IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite) database in MMDB format, but LTG intentionally reads only country fields because city-level accuracy is not reliable enough for the default operator view.

Install or update the local database from the TUI:

```text
sudo ltg
Diagnostics -> Install/update IP country database
```

The database is stored at:

```text
/var/lib/linux-traffic-guard/dbip-city-lite.mmdb
```

The database is not bundled in this repository or in release binaries. If the database or `mmdblookup` is missing, LTG keeps working and shows `-` in the country/region column.

Attribution: IP geolocation data is provided by [DB-IP.com](https://db-ip.com) through the free IP to City Lite database, licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). The free Lite database has reduced accuracy compared with DB-IP commercial databases.

## Build From Source

```bash
git clone https://github.com/furina123123123/linux-traffic-guard.git
cd linux-traffic-guard
make
```

Install from source:

```bash
sudo make install
```

Bootstrap from a fresh Ubuntu/Debian checkout:

```bash
make bootstrap
```

`make bootstrap` checks build/runtime dependencies, installs only missing packages, builds `ltg`, installs it under `PREFIX` (`/usr/local` by default), and then runs the same fail2ban protection bootstrap. Non-root users will be prompted through `sudo`.

Update a source checkout:

```bash
cd linux-traffic-guard
make update
```

`make update` performs `git pull --ff-only`, checks for newly missing packages, rebuilds, reinstalls `ltg`, and runs the same installed protection bootstrap with dependency installation skipped. Ordinary `make install` does not access the network or change system packages.

Uninstall:

```bash
sudo make uninstall
```

Default install path is `/usr/local/bin/ltg`. Override it with `PREFIX`:

```bash
sudo make PREFIX=/opt/ltg install
```

## Testing

```bash
make check
make check-nosqlite
make check-root-guard
make release-check
```

`--self-test` is the quick non-root regression entry:

```bash
ltg --self-test
```

## Release Assets

GitHub Actions builds and uploads:

- `ltg-linux-x86_64`
- `ltg-linux-x86_64-nosqlite`
- `linux-traffic-guard-<version>-linux-x86_64`
- `linux-traffic-guard-<version>-linux-x86_64-nosqlite`
- `linux-traffic-guard-<version>.tar.gz`
- `SHA256SUMS`

Maintainers release a new version by updating `include/ltg/version.hpp`, implementation files, and `CHANGELOG.md`, then pushing a version tag:

```bash
git tag v4.12.24
git push origin v4.12.24
```

## Safety Notes

LTG can modify nftables, UFW, fail2ban config, systemd units, and diagnostic files under `/tmp`.

- Dangerous operations require confirmation.
- UFW enablement performs SSH lockout checks and may require a strong confirmation phrase.
- fail2ban config writes create `.ltg.<timestamp>.bak` backups.
- Diagnostic exports may include source IPs, ports, listeners, process names, and log snippets.
- Reliability checks are read-only unless `--active-probes` is explicitly selected.

Before first use on a production server:

```bash
sudo ltg --doctor
sudo ltg --status
sudo ltg --reliability-check
```

## Project Layout

```text
include/ltg/       Public headers and module interfaces
src/               C++17 implementation files
tests/             Self-test entry support
linux_traffic_guard.hpp
                   Legacy umbrella header
makefile           Build, install, check, release packaging
```

The TUI navigation model lives in `include/ltg/tui_routes.hpp` and
`src/tui_routes.cpp`, so user-facing paths can evolve separately from command
execution. Runtime repair policy such as core tools, apt package mapping, and
first-run bootstrap decisions lives in `include/ltg/runtime_repair.hpp` and
`src/runtime_repair.cpp`. fail2ban/UFW protection bootstrap templates and
command builders live in `include/ltg/protection_bootstrap.hpp` and
`src/protection_bootstrap.cpp`. Traffic accounting constants, history paths,
nft command builders, and tracked-port rule generation live in
`include/ltg/traffic_accounting.hpp` and `src/traffic_accounting.cpp`.

## License

MIT License. See `LICENSE`.
