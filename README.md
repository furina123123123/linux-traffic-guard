# Linux Traffic Guard

[![CI](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Ubuntu](https://img.shields.io/badge/Target-Ubuntu-orange.svg)

Languages: English | [简体中文](README.zh-CN.md)

Linux Traffic Guard is a modular C++17 operations tool for Ubuntu servers. It combines traffic accounting, UFW source analysis, fail2ban policy management, remediation workflows, diagnostics, and a pure ANSI full-screen TUI without requiring external `.sh` or `.py` scripts.

## One-Line Install

For most users, download the prebuilt Linux x86_64 binary from the latest GitHub Release:

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o ltg && chmod +x ltg && sudo install -Dm755 ltg /usr/local/bin/ltg
```

To update the installed binary later, use the built-in updater:

```bash
sudo ltg update
```

You can also repeat the direct download command:

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg && sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
```

For source-based installation on Ubuntu/Debian:

```bash
git clone https://github.com/furina123123123/linux-traffic-guard.git && cd linux-traffic-guard && make bootstrap
```

`make bootstrap` runs `apt-get update`, installs build/runtime dependencies, builds `ltg`, and installs it under `PREFIX` (`/usr/local` by default). Non-root users will be prompted through `sudo`.

## Features

- Dashboard: recent 31-day port traffic Top 10 plus cached UFW security analysis, clear empty states, and next-step guidance; live service and dependency probes are kept out of the first render for faster loading.
- Traffic accounting: append/remove tracked ports without rebuilding by default, visible tracked-port lists, background snapshots every 5 minutes, and day/month/year queries with rolling-window or absolute-period mode plus per-period port and IP:port detail.
- Reliability checks: `sudo ltg --reliability-check` verifies dependencies, update readiness, fail2ban/UFW, traffic accounting, diagnostics, and TUI terminal behavior; add `--active-probes` only for explicit temporary real probes.
- Security center: daily workflows organized as overview, investigation, policy configuration, remediation, service checks, and diagnostics.
- UFW analysis: parses UFW `BLOCK`/`AUDIT`/`ALLOW` events, aggregates by IP/port/time period, supports IP tracing, and can display country/region labels from the optional DB-IP Lite MMDB database.
- fail2ban effectiveness checks: verifies that jails are really loaded after repair and can run a reversible test ban to confirm UFW rule landing.
- Cache: stores parsed UFW events in `/var/tmp/linux_traffic_guard_ufw_cache_v2/events.sqlite3` for faster repeated analysis.
- Traffic history: stores sampled traffic deltas in `/var/tmp/linux_traffic_guard_traffic_history_v1/` with SQLite when available and a TSV fallback for no-SQLite builds.
- Diagnostics: exports service status, rules, logs, nft counters, listeners, and connection snapshots to `/tmp`.

## Requirements

Target platform: Ubuntu 22.04/24.04 or compatible Debian/Ubuntu servers.

Dependencies:

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl mmdb-bin
```

From a source checkout, you can install dependencies with:

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

The database is stored at `/var/lib/linux-traffic-guard/dbip-city-lite.mmdb`. It is not bundled in this repository or in the release binary. If the database or `mmdblookup` is missing, LTG keeps working and shows `-` in the country/region column.

Attribution: IP geolocation data is provided by [DB-IP.com](https://db-ip.com) through the free IP to City Lite database, licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). The free Lite database has reduced accuracy compared with DB-IP commercial databases.

## Build And Check

```bash
make
make check
make check-nosqlite
make check-root-guard
```

Equivalent manual build command:

```bash
make
```

## Usage

Interactive TUI:

```bash
sudo ltg
```

Common CLI commands:

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
sudo ltg update
```

All commands except `--help`, `--version`, and `--self-test` require root privileges. The TUI uses the alternate screen and restores the terminal when it exits or receives a signal.

## Install, Update, Uninstall

Prebuilt binary install or update:

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg
sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
ltg --version
```

Source checkout first install:

```bash
make bootstrap
ltg --help
```

Manual source install:

```bash
make deps
make
sudo make install
```

Update an existing source checkout:

```bash
cd linux-traffic-guard
make update
ltg --version
```

`make update` performs `git pull --ff-only`, rebuilds, and reinstalls `ltg`. This is the common source-checkout workflow; ordinary `make install` does not implicitly access the network or change system packages.

Uninstall:

```bash
sudo make uninstall
```

Default install path is `/usr/local/bin/ltg`. Override it with `PREFIX`:

```bash
sudo make PREFIX=/opt/ltg install
```

## Release Assets

Maintainers release a new version by updating `include/ltg/version.hpp`, implementation files, and `CHANGELOG.md`, then pushing a tag:

```bash
git tag v4.12.8
git push origin v4.12.8
```

GitHub Actions builds and uploads:

- `ltg-linux-x86_64` / `linux-traffic-guard-<version>-linux-x86_64`
- `ltg-linux-x86_64-nosqlite` / `linux-traffic-guard-<version>-linux-x86_64-nosqlite`
- `linux-traffic-guard-<version>.tar.gz`
- `SHA256SUMS`

Local release check:

```bash
make release-check
```

## Maintenance Notes

- CI builds on Ubuntu, checks root-guard behavior, tests SQLite and no-SQLite builds, and runs root smoke checks.
- `CONTRIBUTING.md` documents development constraints and PR checks.
- `SECURITY.md` documents vulnerability reporting and safety expectations.
- UFW analysis cache is only an analysis accelerator. It does not affect firewall or fail2ban decisions.
- Dangerous operations use confirmation prompts and create `.ltg.<timestamp>.bak` backups before writing fail2ban configuration.

## License

MIT License. See `LICENSE`.
