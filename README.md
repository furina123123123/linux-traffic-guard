# Linux Traffic Guard

[![CI](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Ubuntu](https://img.shields.io/badge/Target-Ubuntu-orange.svg)

Linux Traffic Guard is a single-header C++17 operations tool for Ubuntu servers. It combines traffic accounting, UFW source analysis, fail2ban policy management, remediation workflows, diagnostics, and a pure ANSI full-screen TUI without requiring external `.sh` or `.py` scripts.

Chinese documentation is available below: [中文说明](#中文说明).

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

- Dashboard: port-grouped traffic, UFW blocked-source risk ranking, fail2ban/UFW state, and suggested operations.
- Traffic accounting: nftables-based IPv4/IPv6 upload/download counters, grouped by port by default, with IP and IP+port drill-down views.
- Security center: daily workflows organized as overview, investigation, policy configuration, remediation, service checks, and diagnostics.
- UFW analysis: parses UFW `BLOCK`/`AUDIT`/`ALLOW` events, aggregates by IP/port/time period, and supports IP tracing.
- fail2ban effectiveness checks: verifies that jails are really loaded after repair and can run a reversible test ban to confirm UFW rule landing.
- Cache: stores parsed UFW events in `/var/tmp/linux_traffic_guard_ufw_cache_v2/events.sqlite3` for faster repeated analysis.
- Diagnostics: exports service status, rules, logs, nft counters, listeners, and connection snapshots to `/tmp`.

## Requirements

Target platform: Ubuntu 22.04/24.04 or compatible Debian/Ubuntu servers.

Dependencies:

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl
```

From a source checkout, you can install dependencies with:

```bash
make deps
```

At runtime, LTG calls system tools such as `nft`, `ufw`, `fail2ban-client`, `journalctl`, `ss`, `conntrack`, and `systemctl`.

## Build And Check

```bash
make
make check
make check-nosqlite
make check-root-guard
```

Equivalent manual build command:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -x c++ linux_traffic_guard.hpp -o ltg -lsqlite3
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

Maintainers release a new version by updating `linux_traffic_guard.hpp` and `CHANGELOG.md`, then pushing a tag:

```bash
git tag v4.12.7
git push origin v4.12.7
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

## 中文说明

Linux Traffic Guard 是一个面向 Ubuntu 服务器的单头文件 C++17 运维工具。它把流量统计、UFW 来源分析、fail2ban 策略管理、处置修复和诊断报告放在同一个纯 ANSI 全屏 TUI 中，不依赖外部 `.sh` 或 `.py` 脚本。

## 一条命令安装

普通用户推荐直接下载 Release 里编译好的 Linux x86_64 二进制：

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o ltg && chmod +x ltg && sudo install -Dm755 ltg /usr/local/bin/ltg
```

以后更新编译好的版本，推荐使用内置更新命令：

```bash
sudo ltg update
```

也可以重复执行下载命令覆盖安装：

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg && sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
```

Ubuntu/Debian 源码安装：

```bash
git clone https://github.com/furina123123123/linux-traffic-guard.git && cd linux-traffic-guard && make bootstrap
```

`make bootstrap` 会执行 `apt-get update`、安装构建和运行依赖、编译 `ltg`，然后安装到 `PREFIX` 指定的位置。默认 `PREFIX=/usr/local`；非 root 用户会自动使用 `sudo`。

## 功能概览

- 仪表盘：展示端口分组流量、UFW 拦截风险来源 Top、防护组件状态和建议动作。
- 流量统计：基于 nftables 记录 IPv4/IPv6、上传/下载，默认按端口分组，并保留 IP 与 IP+端口明细。
- 安全中心：按安全总览、分析追查、策略配置、处置修复、服务诊断组织日常运维路径。
- 威胁分析：解析 UFW `BLOCK`/`AUDIT`/`ALLOW` 日志，按 IP、端口、时间段聚合，并支持指定 IP 下钻。
- fail2ban 实效核验：策略安装/修复后检查 jail 是否真正加载，并可用临时测试 IP 验证 UFW deny 是否落地。
- SQLite 缓存：使用 `/var/tmp/linux_traffic_guard_ufw_cache_v2/events.sqlite3` 缓存日志事件。
- 诊断导出：收集服务状态、规则、日志、nft 统计和连接快照到 `/tmp`。

## 支持环境

目标环境是 Ubuntu 22.04/24.04 或兼容 Debian/Ubuntu 服务器。

依赖：

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl
```

仓库目录内也可以运行：

```bash
make deps
```

运行时会调用系统工具：`nft`、`ufw`、`fail2ban-client`、`journalctl`、`ss`、`conntrack`、`systemctl`。

## 构建与检查

```bash
make
make check
make check-nosqlite
make check-root-guard
```

手动编译：

```bash
g++ -std=c++17 -O2 -Wall -Wextra -x c++ linux_traffic_guard.hpp -o ltg -lsqlite3
```

## 使用

交互 TUI：

```bash
sudo ltg
```

常用命令：

```bash
ltg --help
ltg --version
ltg --self-test
sudo ltg --status
sudo ltg --ip-traffic
sudo ltg --ufw-analyze 24h
sudo ltg --f2b-audit
sudo ltg --doctor
sudo ltg --export-report
sudo ltg update
```

除 `--help`、`--version` 和 `--self-test` 外，工具必须以 root 权限运行。交互模式会进入 alternate screen，并在退出或收到信号时恢复终端状态。

## 安装、更新、卸载

Release 二进制安装或更新：

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg
sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
ltg --version
```

源码 checkout 首次安装：

```bash
make bootstrap
ltg --help
```

源码 checkout 更新：

```bash
cd linux-traffic-guard
make update
ltg --version
```

卸载：

```bash
sudo make uninstall
```

## 发布包

维护者发布新版本时，先更新 `linux_traffic_guard.hpp` 和 `CHANGELOG.md`，再推送 tag：

```bash
git tag v4.12.7
git push origin v4.12.7
```

GitHub Actions 会自动编译并上传 Release 附件：

- `ltg-linux-x86_64`
- `ltg-linux-x86_64-nosqlite`
- `linux-traffic-guard-<version>.tar.gz`
- `SHA256SUMS`

## 安全提示

Linux Traffic Guard 会修改 nftables、UFW 和 fail2ban 配置。危险操作会使用确认提示，并在写入 fail2ban 配置前生成 `.ltg.<timestamp>.bak` 备份。首次在生产环境使用前，建议先运行：

```bash
sudo ltg --doctor
sudo ltg --status
```

## License

MIT License. See `LICENSE`.
