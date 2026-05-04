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
3. Show port-level vnStat-style day/month/year traffic with Top IP drilldown.
4. Parse UFW BLOCK/AUDIT/ALLOW logs with cache-backed source and port analysis.
5. Install, repair, and verify fail2ban policies for SSH and slow UFW port scans.
6. Run reliability checks that distinguish "configured" from "actually working".

## Quick Install

Most users should install the prebuilt Linux x86_64 binary from the latest GitHub Release:

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o ltg
chmod +x ltg
sudo install -Dm755 ltg /usr/local/bin/ltg
```

Open the TUI:

```bash
sudo ltg
```

Update later with the built-in updater:

```bash
sudo ltg update
```

You can also repeat the direct download command to overwrite the installed binary:

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg
sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
```

## Main Workflows

### 1. Port-Level Traffic Accounting

LTG is meant to behave like a port-level vnStat with IP visibility:

- Add or remove tracked ports without rebuilding the whole accounting table by default.
- Keep historical day/month/year data when appending new ports.
- Sample nftables counters every 5 minutes through a systemd timer.
- View day/month/year traffic in rolling-window or absolute-period mode.
- Read each period as `period + port` rows: host outbound/upload, host inbound/download, total, packets, and Top IPs.
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
sudo ltg update
```

All commands except `--help`, `--version`, and `--self-test` require root privileges. The TUI uses the alternate screen and restores the terminal on normal exit or signal handling.

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

`make bootstrap` runs `apt-get update`, installs build/runtime dependencies, builds `ltg`, and installs it under `PREFIX` (`/usr/local` by default). Non-root users will be prompted through `sudo`.

Update a source checkout:

```bash
cd linux-traffic-guard
make update
```

`make update` performs `git pull --ff-only`, rebuilds, and reinstalls `ltg`. Ordinary `make install` does not access the network or change system packages.

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
git tag v4.12.19
git push origin v4.12.19
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

## License

MIT License. See `LICENSE`.
