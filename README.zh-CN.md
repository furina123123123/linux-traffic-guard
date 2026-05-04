# Linux Traffic Guard / Linux 流量守卫

[![CI](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Ubuntu](https://img.shields.io/badge/Target-Ubuntu-orange.svg)

语言：[English](README.md) | 简体中文

Linux Traffic Guard 是一个面向 Ubuntu 服务器的模块化 C++17 运维工具。它把流量统计、UFW 来源分析、fail2ban 策略管理、处置修复和诊断报告放在同一个纯 ANSI 全屏 TUI 中，不依赖外部 `.sh` 或 `.py` 脚本。

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

- 仪表盘：默认展示最近 31 天端口流量 Top 10 和缓存的 UFW 安全分析，并提供清晰空状态和下一步建议；实时服务和依赖探测不阻塞首屏。
- 流量统计：默认不重建，支持追加/删除统计端口，展示已统计端口列表，后台每 5 分钟采样；日/月/年查询支持滚动窗口和绝对时间两种模式，并在每个周期直接显示端口和 IP:端口明细。
- 可靠性自检：`sudo ltg --reliability-check` 会验证依赖、更新、UFW 分析证据、防护实效、流量统计规则语义、诊断和 TUI 终端状态；只有显式加 `--active-probes` 才执行临时真实探测。
- 安全中心：按安全总览、分析追查、策略配置、处置修复、服务诊断组织日常运维路径。
- 威胁分析：解析 UFW `BLOCK`/`AUDIT`/`ALLOW` 日志，展示原始/有效日志证据，按 IP、端口、时间段聚合，支持指定 IP 下钻，并可用可选 DB-IP Lite MMDB 显示国家/地区。
- fail2ban 实效核验：策略安装/修复后检查 jail 是否真正加载，并可用临时测试 IP 验证 UFW deny 是否落地。
- SQLite 缓存：使用 `/var/tmp/linux_traffic_guard_ufw_cache_v2/events.sqlite3` 缓存日志事件。
- 流量历史：使用 `/var/tmp/linux_traffic_guard_traffic_history_v1/` 保存采样增量；有 SQLite 时使用 SQLite，无 SQLite 编译路径使用 TSV fallback。
- 诊断导出：收集服务状态、规则、日志、nft 统计和连接快照到 `/tmp`。

## 支持环境

目标环境是 Ubuntu 22.04/24.04 或兼容 Debian/Ubuntu 服务器。

依赖：

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl mmdb-bin
```

仓库目录内也可以运行：

```bash
make deps
```

运行时会调用系统工具：`nft`、`ufw`、`fail2ban-client`、`journalctl`、`ss`、`conntrack`、`systemctl`，以及可选的 `mmdblookup`。

## 可选 IP 国家库

LTG 可以在 UFW 来源表和流量 IP 明细表中显示国家/地区。这个能力使用免费的 [DB-IP IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite) 数据库，格式为 MMDB，但 LTG 默认只读取国家字段，因为城市级精度不适合作为运维默认判断依据。

在 TUI 中安装或更新本地数据库：

```text
sudo ltg
诊断 -> 安装/更新 IP 国家库
```

数据库保存到 `/var/lib/linux-traffic-guard/dbip-city-lite.mmdb`。仓库和 Release 二进制不会内置这份数据库；如果数据库或 `mmdblookup` 不存在，LTG 仍正常运行，国家/地区列显示 `-`。

鸣谢：IP 国家/地区数据来自 [DB-IP.com](https://db-ip.com) 的免费 IP to City Lite 数据库，使用 [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) 许可。免费 Lite 数据库相比 DB-IP 商业库精度更低。

## 构建与检查

```bash
make
make check
make check-nosqlite
make check-root-guard
```

手动编译：

```bash
make
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
sudo ltg --traffic-snapshot
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

手动源码安装：

```bash
make deps
make
sudo make install
```

源码 checkout 更新：

```bash
cd linux-traffic-guard
make update
ltg --version
```

`make update` 会执行 `git pull --ff-only`，然后重新编译并覆盖安装 `ltg`。这是源码型开源项目常见做法；普通 `make install` 不会隐式联网或修改系统包。

卸载：

```bash
sudo make uninstall
```

默认安装到 `/usr/local/bin/ltg`。可以通过 `PREFIX` 修改：

```bash
sudo make PREFIX=/opt/ltg install
```

## 发布包

维护者发布新版本时，先更新 `include/ltg/version.hpp`、实现文件和 `CHANGELOG.md`，再推送 tag：

```bash
git tag v4.12.8
git push origin v4.12.8
```

GitHub Actions 会自动编译并上传 Release 附件：

- `ltg-linux-x86_64`
- `ltg-linux-x86_64-nosqlite`
- `linux-traffic-guard-<version>.tar.gz`
- `SHA256SUMS`

本地发布检查：

```bash
make release-check
```

## 维护说明

- CI 会在 Ubuntu 上编译、检查 root guard、测试 SQLite 与 no-SQLite 构建，并做 root 命令烟测。
- `CONTRIBUTING.md` 说明开发约束和 PR 检查项。
- `SECURITY.md` 说明漏洞报告方式和安全期望。
- UFW 分析缓存只用于加速分析，不参与防火墙或 fail2ban 决策。
- 危险操作会使用确认提示，并在写入 fail2ban 配置前生成 `.ltg.<timestamp>.bak` 备份。

## 安全提示

Linux Traffic Guard 会修改 nftables、UFW 和 fail2ban 配置。首次在生产环境使用前，建议先运行：

```bash
sudo ltg --doctor
sudo ltg --status
```

## License

MIT License. See `LICENSE`.
