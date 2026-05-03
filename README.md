# Linux Traffic Guard / Linux 流量守卫

Linux Traffic Guard 是一个面向 Ubuntu 服务器的单头文件 C++17 运维工具。它把流量统计、UFW 来源分析、fail2ban 策略管理、处置修复和诊断报告放在同一个纯 ANSI 全屏 TUI 中，不依赖外部 `.sh` 或 `.py` 脚本。

## 一条命令安装

Ubuntu 服务器上可以直接克隆、编译并安装到 `/usr/local/bin/ltg`：

```bash
git clone https://github.com/furina123123123/linux-traffic-guard.git && cd linux-traffic-guard && make && sudo make install
```

只想拉取单头文件时：

```bash
curl -fsSLO https://raw.githubusercontent.com/furina123123123/linux-traffic-guard/main/linux_traffic_guard.hpp
```

## 功能概览

- 仪表盘：展示 IP/端口流量、近期来源态势、防护组件状态和建议动作。
- 流量统计：基于 nftables `inet usp_ip_traffic` 记录 IPv4/IPv6、TCP/UDP、上传/下载、IP+端口细粒度流量。
- 安全中心：按 `安全总览 -> 分析追查 -> 策略配置 -> 处置修复 -> 服务诊断` 组织日常运维路径。
- 威胁分析：解析 UFW BLOCK/AUDIT/ALLOW 日志，按 IP、端口、时间段聚合，并支持指定 IP 下钻。
- SQLite 缓存：使用 `/var/tmp/linux_traffic_guard_ufw_cache_v1/events.sqlite3` 缓存日志事件，按 `ts/src/dpt/action` 建索引。
- fail2ban 管理：统一维护默认 `sshd`、`ufw-slowscan-global` 两个策略，以及用户自定义 jail；支持白名单、封禁时长、阈值、指数封禁、filter/logpath 和全端口动作。
- 诊断导出：收集服务状态、规则、日志、nft 统计和连接快照到 `/tmp`。

## 支持环境

目标环境是 Ubuntu 服务器。推荐 Ubuntu 22.04/24.04 或兼容环境。

依赖：

```bash
sudo apt update
sudo apt install -y g++ make libsqlite3-dev fail2ban ufw nftables iproute2 conntrack gawk grep
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
sudo ./ltg --status
sudo ./ltg --ip-traffic
sudo ./ltg --ufw-analyze 24h
sudo ./ltg --f2b-audit
sudo ./ltg --doctor
sudo ./ltg --export-report
```

除 `--help` 和 `--version` 外，工具必须以 root 权限运行。交互模式会进入 alternate screen，并在退出或收到信号时恢复终端状态。

## 安装与卸载

```bash
sudo make install
ltg --help
sudo make uninstall
```

默认安装到 `/usr/local/bin/ltg`。可以通过 `PREFIX` 修改：

```bash
sudo make PREFIX=/opt/ltg install
```

## 发布包

生成源码发布包：

```bash
make dist
```

发布包只包含：

- `linux_traffic_guard.hpp`
- `makefile`
- `README.md`
- `LICENSE`
- `CHANGELOG.md`

旧迁移脚本和本地编译产物通过 `.gitignore` 排除，不属于 release。

## 缓存说明

威胁分析使用 SQLite 缓存：

- 数据库：`/var/tmp/linux_traffic_guard_ufw_cache_v1/events.sqlite3`
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
