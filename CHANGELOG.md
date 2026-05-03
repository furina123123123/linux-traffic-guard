# Changelog

## 4.11.1 - 2026-05-03

### Fixed

- Tightened IPv4/IPv6/CIDR validation so malformed addresses such as `::::`, `2001:::1`, bare `abcd`, and out-of-range prefixes are rejected before they reach ban, whitelist, inspect, or analysis flows.
- Rejected invalid calendar dates before `mktime` normalization, preventing custom UFW analysis ranges like `2026-13-01` or `2026-02-31` from silently rolling into another date.
- Split single-port validation from port-list/range validation so firewall and focused-inspect flows no longer accept `80,443` or `80-90` where only one port is meaningful.
- Rejected zero-valued fail2ban numeric inputs such as `0.0` and `00` through stricter positive-number validation.
- Filtered invalid `SRC=` values while parsing UFW logs so malformed or spoofed log lines do not enter Top IP, risk, cache, or audit summaries.

### Changed

- Expanded `--self-test` coverage for invalid IPv6, invalid dates, zero factors, single-port/list separation, and invalid UFW sources.

## 4.11.0 - 2026-05-03

### Added

- `--self-test` non-root command for pure logic coverage: validation, UTF-8 width, UFW parsing, nft parsing, range merging, SQLite fallback mode, and in-memory INI handling.
- `IniConfig::loadString()` and `IniConfig::toString()` to make fail2ban config edits testable without touching `/etc`.
- `LTG_FORCE_NO_SQLITE=1` self-test coverage in `make check-nosqlite`.

### Changed

- CLI status, traffic, doctor, audit, and export-report paths now render through `ScreenBuffer` instead of the old prompt-style UI helpers.
- Removed legacy interactive menu/action functions that were superseded by the unified `TuiApp` loop.
- `make check` now runs `./ltg --self-test`.

## 4.10.1 - 2026-05-03

### Added

- GitHub Actions CI for Ubuntu build, basic checks, root guard, SQLite fallback compile, root smoke tests, and release package generation.
- `CONTRIBUTING.md`, `SECURITY.md`, issue templates, and pull request template.
- `make check-nosqlite`, `make check-root-guard`, and `make release-check`.

### Changed

- Added `LTG_FORCE_NO_SQLITE=1` compile mode to keep the text-cache fallback testable.
- README now includes CI/license/platform badges and project-maintenance notes.

## 4.10.0 - 2026-05-03

### Added

- Unified fail2ban policy overview for the two built-in policies and user-defined jails.
- Custom fail2ban policy wizard for creating jail sections, reusing or generating filters, and setting log path, threshold, window, ban time, and action.
- Generic policy editing and custom-policy disable flow inside the TUI.

### Changed

- Dashboard now shows an existing snapshot immediately while refreshing in the background.
- Dashboard loading now reads traffic, UFW source posture, and service state in parallel.
- UFW source posture no longer falls back to live journal scanning when the SQLite cache covers the range but has no matching events.

## 4.9.0 - 2026-05-03

### Added

- SQLite-backed UFW threat-analysis cache for Ubuntu builds.
- Indexed event storage under `/var/tmp/linux_traffic_guard_ufw_cache_v1/events.sqlite3`.
- Dashboard source posture table with source IP, hits, primary port, risk, and suggested action.
- Dashboard component status table with state meaning and next-step guidance.
- Open-source release files: `README.md`, `LICENSE`, `.gitignore`, and `CHANGELOG.md`.
- `make check` and `make dist` release helper targets.

### Changed

- Security Center is organized as a single workflow: overview, analysis, policy, response/repair, and diagnostics.
- UFW analysis uses SQLite `GROUP BY` aggregation when available, with TSV fallback only when SQLite headers are unavailable.
- Ubuntu build links `-lsqlite3` by default.
- Help output now includes dependencies, install/uninstall commands, and release-oriented usage notes.

### Notes

- The tool remains a single C++17 header and does not call external `.sh` or `.py` helper scripts.
- All commands except `--help` and `--version` require root privileges.
