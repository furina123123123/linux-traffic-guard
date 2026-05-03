# Linux Traffic Guard / Linux 流量守卫

[![CI](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Ubuntu](https://img.shields.io/badge/Target-Ubuntu-orange.svg)

Linux Traffic Guard 是一个面向 Ubuntu 服务器的单头文件 C++17 运维工具。它把流量统计、UFW 来源分析、fail2ban 策略管理、处置修复和诊断报告放在同一个纯 ANSI 全屏 TUI 中，不依赖外部 `.sh` 或 `.py` 脚本。

## 一条命令安装

普通用户推荐直接下载 Release 里编译好的 Linux x86_64 二进制：

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o ltg && chmod +x ltg && sudo install -Dm755 ltg /usr/local/bin/ltg
```

以后更新编译好的版本，重复执行同一条命令即可覆盖 `/usr/local/bin/ltg`：

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg && sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
```

安装后也可以直接使用内置更新命令：

```bash
sudo ltg update
```

Ubuntu 服务器上可以直接克隆，并让 makefile 自动安装依赖、编译、安装到 `/usr/local/bin/ltg`：

```bash
git clone https://github.com/furina123123123/linux-traffic-guard.git && cd linux-traffic-guard && make bootstrap
```

`make bootstrap` 会在 Ubuntu/Debian 上执行 `apt-get update`、安装构建和运行依赖、编译 `ltg`，然后安装到 `PREFIX` 指定的位置。默认 `PREFIX=/usr/local`；非 root 用户会自动使用 `sudo`。

只想拉取单头文件时：

```bash
curl -fsSLO https://raw.githubusercontent.com/furina123123123/linux-traffic-guard/main/linux_traffic_guard.hpp
```

## 功能概览

- 仪表盘：展示端口分组流量、兼容 `ufw_analyze.py` 口径的 UFW 拦截风险来源 Top、防护组件状态和建议动作。
- 流量统计：基于 nftables `inet usp_ip_traffic` 记录 IPv4/IPv6、TCP/UDP、上传/下载，默认按端口分组，并保留 IP 与 IP+端口明细。
- 安全中心：按 `安全总览 -> 分析追查 -> 策略配置 -> 处置修复 -> 服务诊断` 组织日常运维路径。
- 威胁分析：解析 UFW BLOCK/AUDIT/ALLOW 日志，按 IP、端口、时间段聚合，并支持指定 IP 下钻。
- fail2ban 实效核验：策略安装/修复后检查 jail 是否真正加载，并可用临时测试 IP 验证 UFW deny 是否落地。
- SQLite 缓存：使用 `/var/tmp/linux_traffic_guard_ufw_cache_v2/events.sqlite3` 缓存日志事件，按 `ts/src/dpt/action` 建索引。
- fail2ban 管理：统一维护默认 `sshd`、`ufw-slowscan-global` 两个策略，以及用户自定义 jail；支持白名单、封禁时长、阈值、指数封禁、filter/logpath 和全端口动作。
- 诊断导出：收集服务状态、规则、日志、nft 统计和连接快照到 `/tmp`。

## 支持环境

目标环境是 Ubuntu 服务器。推荐 Ubuntu 22.04/24.04 或兼容环境。

依赖：

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl
```

也可以在仓库目录里运行：

```bash
make deps
```

运行时会调用系统工具：`nft`、`ufw`、`fail2ban-client`、`journalctl`、`ss`、`conntrack`、`systemctl`。

## 构建

```bash
make
```

等价手动编译命令：

```bash
g++ -std=c++17 -O2 -Wall -Wextra -x c++ linux_traffic_guard.hpp -o ltg -lsqlite3
```

基础自检：

```bash
make check
```

## 使用

交互 TUI：

```bash
sudo ./ltg
```

常用命令行模式：

```bash
./ltg --help
./ltg --version
./ltg --self-test
sudo ./ltg --status
sudo ./ltg --ip-traffic
sudo ./ltg --ufw-analyze 24h
sudo ./ltg --f2b-audit
sudo ./ltg --doctor
sudo ./ltg --export-report
```

除 `--help`、`--version` 和 `--self-test` 外，工具必须以 root 权限运行。交互模式会进入 alternate screen，并在退出或收到信号时恢复终端状态。

## 代码结构

发布物仍然是一个单头文件，但内部按维护边界组织：

- 基础工具：字符串、时间、校验、文件和命令执行。
- 数据模型：流量、UFW 事件、fail2ban 策略和仪表盘快照。
- 解析与缓存：nft 统计解析、UFW 日志分析、SQLite/文本 fallback 缓存。
- 渲染与 TUI：UTF-8 宽度处理、表格、全屏视口、输入事件和页面栈。
- CLI：非交互命令输出复用 `ScreenBuffer`，便于脚本和 CI 验证。

纯逻辑自测不需要 root：

```bash
./ltg --self-test
```

## 安装与卸载

Release 二进制安装或更新：

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg
sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
ltg --version
```

安装后更新到最新 Release：

```bash
sudo ltg update
```

源码 checkout 首次安装：

```bash
make bootstrap
ltg --help
```

手动分步安装：

```bash
make deps
make
sudo make install
ltg --help
```

以后更新到 GitHub 最新版：

```bash
cd linux-traffic-guard
make update
ltg --version
```

`make update` 使用 `git pull --ff-only`，然后重新编译并覆盖安装 `ltg`。这是源码型开源项目常见做法：首次安装负责补齐依赖，后续更新只在已有 checkout 中快进拉取、重新构建、重新安装；不会在普通 `make install` 里隐式联网或改系统包。

卸载：

```bash
sudo make uninstall
```

默认安装到 `/usr/local/bin/ltg`。可以通过 `PREFIX` 修改：

```bash
sudo make PREFIX=/opt/ltg install
```

## 发布包

维护者发布新版本时，先更新 `linux_traffic_guard.hpp` 中的版本号和 `CHANGELOG.md`，再推送 tag：

```bash
git tag v4.12.6
git push origin v4.12.6
```

GitHub Actions 会自动编译并上传 Release 附件：

- `ltg-linux-x86_64` / `linux-traffic-guard-<version>-linux-x86_64`
- `ltg-linux-x86_64-nosqlite` / `linux-traffic-guard-<version>-linux-x86_64-nosqlite`
- `linux-traffic-guard-<version>.tar.gz`
- `SHA256SUMS`

本地生成源码发布包：

```bash
make release-check
```

发布包只包含：

- `linux_traffic_guard.hpp`
- `makefile`
- `README.md`
- `LICENSE`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `SECURITY.md`

旧迁移脚本和本地编译产物通过 `.gitignore` 排除，不属于 release。

## 项目维护

仓库包含基础开源维护文件：

- CI：`.github/workflows/ci.yml` 会在 Ubuntu 上编译、检查 root guard、测试 SQLite fallback，并做 root 命令烟测。
- 贡献指南：`CONTRIBUTING.md` 说明开发约束、检查命令和 PR 清单。
- 安全策略：`SECURITY.md` 说明漏洞报告方式和安全期望。
- Issue / PR 模板：帮助复现问题、说明环境和记录验证结果。

## 缓存说明

威胁分析使用 SQLite 缓存：

- 数据库：`/var/tmp/linux_traffic_guard_ufw_cache_v2/events.sqlite3`
- 表：`events`、`loaded_ranges`、`meta`
- 自动清理：读取 `meta.last_activity`，超过 14 天未使用时，下次进入威胁分析会清空事件和范围缓存并重建。

这不是后台定时任务；它是“使用时顺手清理”的惰性清理机制，不需要额外守护进程。

## 安全提示

Linux Traffic Guard 会修改 nftables、UFW 和 fail2ban 配置。所有危险操作都使用 `y/N` 或 `Y/n` 确认，并在写入 fail2ban 配置前生成 `.ltg.<timestamp>.bak` 备份。首次在生产环境使用前，建议先运行：

```bash
sudo ./ltg --doctor
sudo ./ltg --status
```

## License

MIT License. See `LICENSE`.
