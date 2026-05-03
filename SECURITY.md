# Security Policy

Linux Traffic Guard is an operations tool that can modify nftables, UFW, and fail2ban configuration. Treat bugs that may weaken firewall rules, bypass confirmations, corrupt fail2ban configuration, or expose sensitive logs as security-sensitive.

## Supported Versions

The `main` branch is the supported development line. Please test against the latest commit before reporting a security issue.

## Reporting a Vulnerability

Please do not open a public issue for exploitable vulnerabilities.

Use GitHub private vulnerability reporting if it is enabled for the repository. If it is not enabled, open a minimal public issue asking for a private contact path without including exploit details.

Helpful details:

- Linux distribution and version.
- Linux Traffic Guard version or commit SHA.
- Exact command or TUI workflow involved.
- Whether the process was run as root.
- Expected result and observed result.
- Redacted logs or config snippets when relevant.

## Safety Expectations

- Configuration writes should create timestamped backups.
- Destructive operations should ask for `y/N` or `Y/n` confirmation.
- The program should restore terminal state after normal exit, Ctrl+C, and common termination signals.
- Runtime behavior must not depend on external `.sh` or `.py` helper scripts.
