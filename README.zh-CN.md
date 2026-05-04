# Linux Traffic Guard / Linux 流量守卫

[![CI](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/furina123123123/linux-traffic-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Ubuntu](https://img.shields.io/badge/Target-Ubuntu-orange.svg)

语言：[English](README.md) | 简体中文

Linux Traffic Guard（`ltg`）是一个面向 Ubuntu/Debian 服务器的流量与防护运维工具。它想解决的不是“再做一个状态面板”，而是让运维人员在一个终端 TUI 里回答三个实际问题：

- 哪些服务端口正在产生流量？这些流量背后是哪些 IP？
- UFW 最近拦了哪些来源？这些来源在扫哪些端口？
- fail2ban 策略是不是真的加载了、能封禁、并且能落地成 UFW deny 规则？

它不是被动看板，也不是 `.sh` / `.py` 脚本集合的包装。LTG 是一个模块化 C++17 程序，提供纯 ANSI 全屏 TUI、Release 编译好二进制、自测、可靠性自检，以及对 nftables、UFW、fail2ban 高风险动作的保守确认流程。

## 它解决什么问题

小型或自维护 Linux 服务器上的关键信息通常散在多个工具里：

- `vnstat` 能看时间维度流量，但看不到服务端口和 IP 明细。
- `ufw` 能看防火墙规则，但不擅长做攻击来源和被扫端口分析。
- `fail2ban-client status` 能告诉你 jail 是否存在，但不能证明封禁真的落地成 UFW deny。
- `journalctl`、`/var/log/ufw.log`、`nft list ruleset`、`conntrack` 都准确，但排障时阅读成本高、速度慢。

LTG 把这些路径合成一条工作流：

1. 用 nftables counter 跟踪指定服务端口。
2. 每 5 分钟把 counter 采样进本地历史库。
3. 用端口级 vnStat 视图查看日/月/年流量，并下钻 Top IP。
4. 解析 UFW BLOCK/AUDIT/ALLOW 日志，缓存后做来源和端口分析。
5. 安装、修复、验证 SSH 防护和 UFW 慢扫升级两条 fail2ban 策略。
6. 用可靠性自检区分“配置存在”和“链路真的生效”。

## 快速安装

普通用户建议直接安装 GitHub Release 里编译好的 Linux x86_64 二进制：

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o ltg
chmod +x ltg
sudo install -Dm755 ltg /usr/local/bin/ltg
```

打开 TUI：

```bash
sudo ltg
```

以后更新推荐使用内置更新命令：

```bash
sudo ltg update
```

也可以重复执行下载命令覆盖安装：

```bash
curl -fL https://github.com/furina123123123/linux-traffic-guard/releases/latest/download/ltg-linux-x86_64 -o /tmp/ltg
sudo install -Dm755 /tmp/ltg /usr/local/bin/ltg
```

## 主要工作流

### 1. 端口级流量统计

LTG 的流量统计目标是“端口级 vnStat + IP 明细”：

- 默认追加统计端口，不重建整张统计表。
- 追加新端口时保留已有历史日/月/年数据。
- 通过 systemd timer 每 5 分钟采样 nftables counter。
- 日/月/年支持滚动窗口和绝对时间两种查询。
- 每个周期按 `周期 + 端口` 展示入站、出站、合计、包数、Top IP。
- 可以从端口继续展开 IP 级出站/入站明细。

TUI 路径示例：

```text
sudo ltg
流量统计 -> 开启/追加端口
流量统计 -> 日流量 / 月流量 / 年流量
```

内部数据：

- 历史目录：`/var/tmp/linux_traffic_guard_traffic_history_v1/`
- 有 SQLite 时使用 SQLite；no-SQLite 构建使用 TSV fallback。
- systemd timer：`linux-traffic-guard-traffic-snapshot.timer`

### 2. UFW 威胁分析

LTG 会解析 UFW 内核日志，把原始 BLOCK/AUDIT/ALLOW 事件整理成能直接排查的视图：

- 来源 IP Top。
- 被扫端口 Top。
- 单个 IP 的端口分布。
- 原始证据摘要：读取来源、时间窗口、匹配行数、有效公网 SRC、过滤掉的私网/非法来源、BLOCK/AUDIT/ALLOW 分布、无 DPT 计数。
- 缓存重复分析结果，第二次加载不会重新扫旧轮转日志。
- 可选使用 DB-IP Lite MMDB 显示国家/地区。

命令示例：

```bash
sudo ltg --ufw-analyze 24h
sudo ltg --ufw-analyze 7d
```

缓存目录：

```text
/var/tmp/linux_traffic_guard_ufw_cache_v2/
```

UFW 分析缓存只用于加速分析，不参与防火墙或 fail2ban 决策。

### 3. fail2ban 防护策略管理

LTG 维护两条默认防护策略：

- `sshd`：SSH 爆破防护。
- `ufw-slowscan-global`：基于 UFW BLOCK/AUDIT 日志的跨端口慢扫升级封禁。

策略安装/修复流程在用户确认后可以：

- 自动安装缺失的 `fail2ban` 和 `ufw`。
- 写入或修复 fail2ban filter/action/jail 配置。
- 执行 `fail2ban-client -t`。
- 启动并 reload fail2ban 服务。
- 验证两条默认 jail 都已加载。
- 对测试 IP `203.0.113.254` 执行可回滚临时 ban。
- 确认测试 IP 进入 jail banned list，并且 UFW 出现 deny 规则。
- 执行 unban，并清理临时 UFW 残留。

只有整条链路通过，LTG 才会显示防护策略已经真正生效。

### 4. 可靠性自检

可靠性自检用于回答“它到底有没有真的工作”：

```bash
sudo ltg --reliability-check
sudo ltg --reliability-check --active-probes
```

默认自检只读，不修改系统状态。主动探测必须显式选择，会执行临时 ban、流量采样、诊断写入等测试，并尝试清理。结果会按依赖、更新、防护、流量统计、UFW 分析、诊断、TUI 终端状态分组展示。

## 常用命令

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

除 `--help`、`--version` 和 `--self-test` 外，工具必须以 root 权限运行。交互模式会进入 alternate screen，并在退出或收到信号时恢复终端状态。

## 支持环境

目标环境：

- Ubuntu 22.04/24.04 或兼容 Debian/Ubuntu 服务器。
- systemd 主机用于后台 timer/service 工作流。

依赖：

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep curl mmdb-bin
```

源码目录内也可以运行：

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

数据库保存到：

```text
/var/lib/linux-traffic-guard/dbip-city-lite.mmdb
```

仓库和 Release 二进制不会内置这份数据库；如果数据库或 `mmdblookup` 不存在，LTG 仍正常运行，国家/地区列显示 `-`。

鸣谢：IP 国家/地区数据来自 [DB-IP.com](https://db-ip.com) 的免费 IP to City Lite 数据库，使用 [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) 许可。免费 Lite 数据库相比 DB-IP 商业库精度更低。

## 源码构建

```bash
git clone https://github.com/furina123123123/linux-traffic-guard.git
cd linux-traffic-guard
make
```

源码安装：

```bash
sudo make install
```

在新的 Ubuntu/Debian 环境中可以直接 bootstrap：

```bash
make bootstrap
```

`make bootstrap` 会执行 `apt-get update`、安装构建和运行依赖、编译 `ltg`，然后安装到 `PREFIX` 指定的位置。默认 `PREFIX=/usr/local`；非 root 用户会自动使用 `sudo`。

源码 checkout 更新：

```bash
cd linux-traffic-guard
make update
```

`make update` 会执行 `git pull --ff-only`，然后重新编译并覆盖安装 `ltg`。普通 `make install` 不会隐式联网或修改系统包。

卸载：

```bash
sudo make uninstall
```

默认安装到 `/usr/local/bin/ltg`。可以通过 `PREFIX` 修改：

```bash
sudo make PREFIX=/opt/ltg install
```

## 测试

```bash
make check
make check-nosqlite
make check-root-guard
make release-check
```

`--self-test` 是最快的非 root 回归入口：

```bash
ltg --self-test
```

## Release 资产

GitHub Actions 会自动编译并上传：

- `ltg-linux-x86_64`
- `ltg-linux-x86_64-nosqlite`
- `linux-traffic-guard-<version>-linux-x86_64`
- `linux-traffic-guard-<version>-linux-x86_64-nosqlite`
- `linux-traffic-guard-<version>.tar.gz`
- `SHA256SUMS`

维护者发布新版本时，先更新 `include/ltg/version.hpp`、实现文件和 `CHANGELOG.md`，再推送 tag：

```bash
git tag v4.12.21
git push origin v4.12.21
```

## 安全说明

LTG 可以修改 nftables、UFW、fail2ban 配置、systemd units，以及 `/tmp` 下的诊断文件。

- 高风险动作会要求确认。
- 启用 UFW 前会检查 SSH 锁定风险，并在风险较高时要求强确认词。
- 写入 fail2ban 配置前会生成 `.ltg.<timestamp>.bak` 备份。
- 诊断导出可能包含来源 IP、端口、监听进程、进程名和日志片段。
- 可靠性自检默认只读；只有显式选择 `--active-probes` 才执行主动探测。

生产服务器首次使用前建议先运行：

```bash
sudo ltg --doctor
sudo ltg --status
sudo ltg --reliability-check
```

## 项目结构

```text
include/ltg/       公开头文件和模块接口
src/               C++17 实现文件
tests/             自测入口支持
linux_traffic_guard.hpp
                   旧版兼容聚合头
makefile           构建、安装、检查、发布打包
```

## License

MIT License. See `LICENSE`.
