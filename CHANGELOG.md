# Changelog

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
