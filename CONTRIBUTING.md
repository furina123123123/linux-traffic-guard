# Contributing

Thanks for helping improve Linux Traffic Guard.

This project is intentionally small in shape: one C++17 header, one makefile, no runtime helper scripts. Please keep changes aligned with that design unless there is a strong reason to change it.

## Development Setup

Ubuntu is the primary target:

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep
make
make check
```

Useful checks before opening a pull request:

```bash
make clean all
make check
make check-nosqlite
make release-check
```

`make check-root-guard` verifies that root-only commands are rejected when run without root. It is skipped automatically when the check itself runs as root.
`./ltg --self-test` is non-root and covers pure parsing, validation, rendering-width, range, and in-memory config behavior.

## Project Constraints

- Keep the tool single-header: production logic lives in `linux_traffic_guard.hpp`.
- Do not add runtime `.sh` or `.py` helper scripts.
- Keep the TUI pure ANSI; do not add ncurses or third-party UI libraries.
- Ubuntu is the main runtime environment.
- Except `--help`, `--version`, and `--self-test`, commands should remain root-only unless there is a clear maintenance reason.
- Keep CLI output on the `ScreenBuffer` path where practical, so command-line and TUI rendering do not drift.
- Dangerous actions must use clear `y/N` or `Y/n` confirmation and should create backups before writing service configuration.

## Code Style

- Prefer small, local helpers over broad abstractions.
- Preserve existing Chinese user-facing text unless the change improves clarity.
- Use structured parsing where practical; avoid relying on raw command output in normal pages.
- Keep command-line modes plain-text and script-friendly.
- Keep interactive mode inside the unified full-screen TUI.

## Pull Request Checklist

- Build passes on Ubuntu.
- `make check` passes.
- If touching SQLite/cache logic, `make check-nosqlite` still passes.
- README or CHANGELOG is updated for user-visible changes.
- No new runtime dependency is introduced without documenting it.
