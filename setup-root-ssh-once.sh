#!/bin/bash

set -Eeuo pipefail

readonly SCRIPT_NAME="Root SSH 一次性配置脚本"
readonly CONF_DIR="/etc/ssh/sshd_config.d"
readonly MANAGED_CONF="${CONF_DIR}/00-root-public-key-login.conf"
readonly LEGACY_MANAGED_CONF="${CONF_DIR}/99-root-public-key-login.conf"
readonly MANAGED_SOCKET_DIR="/etc/systemd/system/ssh.socket.d"
readonly MANAGED_SOCKET_CONF="${MANAGED_SOCKET_DIR}/10-listen-port.conf"

readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly GREEN='\033[0;32m'
readonly NC='\033[0m'

SSH_PORT=""
PUBLIC_KEY=""
BACKUP_DIR=""
SSHD_BIN=""
SSH_SOCKET_MANAGED="false"
FIREWALL_RULE_ADDED="false"
PRESERVED_SSH_PORTS=""

info() {
    echo -e "${BLUE}==>${NC} $*"
}

ok() {
    echo -e "${GREEN}完成:${NC} $*"
}

warn() {
    echo -e "${YELLOW}注意:${NC} $*"
}

die() {
    echo -e "${RED}错误:${NC} $*" >&2
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

systemd_available() {
    command_exists systemctl && [ -d /run/systemd/system ]
}

service_exists() {
    local unit="$1"
    systemctl list-unit-files "$unit" --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$unit" \
        || systemctl status "$unit" >/dev/null 2>&1
}

service_active_or_enabled() {
    local unit="$1"
    systemctl is-active --quiet "$unit" 2>/dev/null || systemctl is-enabled --quiet "$unit" 2>/dev/null
}

current_ssh_server_port() {
    if [ -n "${SSH_CONNECTION:-}" ]; then
        printf '%s\n' "$SSH_CONNECTION" | awk '{print $4}'
    fi
}

find_sshd_bin() {
    if command_exists sshd; then
        command -v sshd
        return
    fi

    if [ -x /usr/sbin/sshd ]; then
        echo /usr/sbin/sshd
        return
    fi

    return 1
}

need_preflight() {
    if [ "$(id -u)" -ne 0 ]; then
        die "请用 root 运行，例如: sudo bash setup-root-ssh-once.sh"
    fi

    systemd_available || die "当前系统没有可用的 systemd，脚本无法安全重载 SSH 服务。"
    [ -f /etc/ssh/sshd_config ] || die "找不到 /etc/ssh/sshd_config，请先安装 openssh-server。"
    command_exists ssh-keygen || die "找不到 ssh-keygen，请先安装 openssh-client。"
    command_exists ss || die "找不到 ss，请先安装 iproute2。"

    SSHD_BIN="$(find_sshd_bin)" || die "找不到 sshd，请先安装 openssh-server。"
}

show_intro() {
    echo "============================================================"
    echo "$SCRIPT_NAME"
    echo "============================================================"
    echo "这个脚本只配置 root 的 SSH 公钥登录和 SSH 监听端口。"
    echo
    echo "你需要准备客户端生成出来的公钥文件内容。"
    echo "例如 Windows 客户端生成:"
    echo '  ssh-keygen -t ed25519 -f C:\Users\furina\.ssh\gcp_root_ed25519'
    echo
    echo "生成后要复制的是 .pub 结尾文件里的那一整行，例如:"
    echo '  C:\Users\furina\.ssh\gcp_root_ed25519.pub'
    echo
    echo "不是没有 .pub 的私钥文件，也不是 .pub 文件路径。"
    echo "公钥内容通常以 ssh-ed25519 / ssh-rsa / ecdsa-sha2-* 开头。"
    echo
    warn "脚本会先放行新端口，再验证并重载 SSH；默认保留 22 端口，避免远程执行时断线后回不来。"
    warn "如果是 AWS / GCP / Azure，还需要你在云厂商安全组/防火墙里手动放行新端口。"
    echo
}

port_listener_lines() {
    local port="$1"
    ss -H -tlpn 2>/dev/null | awk -v port=":${port}" '$4 ~ port "$" {print}'
}

extract_port_from_address() {
    local value="$1"
    value="${value%%#*}"
    value="${value//[[:space:]]/}"
    value="${value#[}"
    value="${value%]}"

    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
        return
    fi

    value="${value##*:}"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    fi
}

append_preserved_port() {
    local port="$1"
    local existing

    [[ "$port" =~ ^[0-9]+$ ]] || return
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return

    for existing in $PRESERVED_SSH_PORTS; do
        [ "$existing" = "$port" ] && return
    done

    PRESERVED_SSH_PORTS="${PRESERVED_SSH_PORTS}${PRESERVED_SSH_PORTS:+ }${port}"
}

port_used_by_non_ssh() {
    local port="$1"
    local lines
    lines="$(port_listener_lines "$port")"

    [ -n "$lines" ] || return 1
    printf '%s\n' "$lines" | grep -Eiq 'users:\(\("ssh(d)?",' && return 1
    return 0
}

ssh_socket_declares_port() {
    local target_port="$1"
    local listen_value
    local port

    service_active_or_enabled ssh.socket || return 1

    while IFS= read -r listen_value; do
        port="$(extract_port_from_address "$listen_value" || true)"
        [ "$port" = "$target_port" ] && return 0
    done < <(systemctl cat ssh.socket 2>/dev/null | awk -F= '/^[[:space:]]*ListenStream=/ {print $2}')

    return 1
}

collect_preserved_ssh_ports() {
    local current_port
    local port
    local address
    local listen_value

    PRESERVED_SSH_PORTS=""

    current_port="$(current_ssh_server_port || true)"
    if [ -n "$current_port" ]; then
        append_preserved_port "$current_port"
    fi

    if ssh_socket_declares_port 22 || ! port_used_by_non_ssh 22; then
        append_preserved_port 22
    else
        warn "22 端口已被非 SSH 进程占用，脚本不会强行加入 22 作为救援监听。"
    fi

    while IFS= read -r port; do
        append_preserved_port "$port"
    done < <("$SSHD_BIN" -T -f /etc/ssh/sshd_config -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | awk '$1 == "port" {print $2}')

    while IFS= read -r address; do
        port="$(extract_port_from_address "$address" || true)"
        append_preserved_port "$port"
    done < <(ss -H -tlpn 2>/dev/null | grep -E 'users:\(\("ssh(d)?",' | awk '{print $4}')

    if service_active_or_enabled ssh.socket; then
        while IFS= read -r listen_value; do
            port="$(extract_port_from_address "$listen_value" || true)"
            append_preserved_port "$port"
        done < <(systemctl cat ssh.socket 2>/dev/null | awk -F= '/^[[:space:]]*ListenStream=/ {print $2}')
    fi

    if [ -n "$PRESERVED_SSH_PORTS" ]; then
        ok "将保留现有 SSH 入口端口: ${PRESERVED_SSH_PORTS}"
    else
        warn "未能识别现有 SSH 入口端口；脚本仍会新增 ${SSH_PORT}，但请确认云防火墙已放行。"
    fi
}

prompt_port() {
    local current_port
    current_port="$(current_ssh_server_port || true)"

    while true; do
        read -r -p "请输入新的 SSH 端口，必须手动输入，不能留空，不能用默认 22: " SSH_PORT
        SSH_PORT="${SSH_PORT//[[:space:]]/}"

        if [ -z "$SSH_PORT" ]; then
            warn "端口不能留空。"
            continue
        fi

        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
            warn "端口只能是数字。"
            continue
        fi

        if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
            warn "端口范围必须是 1-65535。"
            continue
        fi

        if [ "$SSH_PORT" -eq 22 ]; then
            warn "这里要求修改为非默认 SSH 端口，请不要填 22。"
            continue
        fi

        if [ -n "$current_port" ] && [ "$SSH_PORT" = "$current_port" ]; then
            warn "你当前 SSH 连接已经在使用 ${current_port}，请输入一个新的备用端口。"
            continue
        fi

        if port_used_by_non_ssh "$SSH_PORT"; then
            warn "端口 ${SSH_PORT} 已被非 SSH 进程监听，请换一个端口。"
            port_listener_lines "$SSH_PORT" || true
            continue
        fi

        break
    done
}

looks_like_private_key() {
    local text="$1"
    [[ "$text" =~ BEGIN[[:space:]]+(OPENSSH|RSA|DSA|EC)[[:space:]]+PRIVATE[[:space:]]+KEY ]]
}

valid_public_key_with_ssh_keygen() {
    local key="$1"
    local tmp_key
    tmp_key="$(mktemp)"
    chmod 600 "$tmp_key"
    printf '%s\n' "$key" > "$tmp_key"

    if ssh-keygen -l -f "$tmp_key" >/dev/null 2>&1; then
        rm -f "$tmp_key"
        return 0
    fi

    rm -f "$tmp_key"
    return 1
}

prompt_public_key() {
    while true; do
        echo
        echo "请粘贴 .pub 结尾公钥文件里的完整一行内容。"
        echo "示例: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@pc"
        read -r -p "公钥内容: " PUBLIC_KEY

        PUBLIC_KEY="$(printf '%s' "$PUBLIC_KEY" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

        if [ -z "$PUBLIC_KEY" ]; then
            warn "公钥内容不能为空。"
            continue
        fi

        if looks_like_private_key "$PUBLIC_KEY"; then
            warn "你粘贴的是私钥内容。这里必须粘贴 .pub 公钥文件里的那一整行。"
            continue
        fi

        if [[ "$PUBLIC_KEY" =~ \.pub$ ]] || [[ "$PUBLIC_KEY" =~ ^[A-Za-z]:\\.*\.pub$ ]] || [[ "$PUBLIC_KEY" =~ ^/.*\.pub$ ]]; then
            warn "你粘贴的像是 .pub 文件路径。这里要粘贴 .pub 文件里面那一整行内容。"
            continue
        fi

        if ! valid_public_key_with_ssh_keygen "$PUBLIC_KEY"; then
            warn "ssh-keygen 无法识别这段公钥。请确认复制的是 .pub 文件里的完整一行。"
            continue
        fi

        break
    done
}

make_backup() {
    local now
    now="$(date +%Y%m%d-%H%M%S)"
    BACKUP_DIR="/root/ssh-root-setup-backup-${now}"
    mkdir -p "$BACKUP_DIR"

    [ -f /etc/ssh/sshd_config ] && cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config"
    [ -f "$MANAGED_CONF" ] && cp -a "$MANAGED_CONF" "$BACKUP_DIR/00-root-public-key-login.conf"
    [ -f "$LEGACY_MANAGED_CONF" ] && cp -a "$LEGACY_MANAGED_CONF" "$BACKUP_DIR/99-root-public-key-login.conf"
    [ -f "$MANAGED_SOCKET_CONF" ] && cp -a "$MANAGED_SOCKET_CONF" "$BACKUP_DIR/10-listen-port.conf"

    ok "已备份现有配置到 $BACKUP_DIR"
}

atomic_replace() {
    local source="$1"
    local target="$2"
    local mode="${3:-644}"
    local owner_group="${4:-root:root}"

    chown "$owner_group" "$source"
    chmod "$mode" "$source"
    mv -f "$source" "$target"
}

install_root_key() {
    info "写入 root 的 authorized_keys"

    install -d -m 700 -o root -g root /root/.ssh
    touch /root/.ssh/authorized_keys
    chown root:root /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys

    if grep -qxF "$PUBLIC_KEY" /root/.ssh/authorized_keys; then
        ok "root 公钥已经存在，跳过重复写入"
    else
        printf '%s\n' "$PUBLIC_KEY" >> /root/.ssh/authorized_keys
        ok "root 公钥已追加到 /root/.ssh/authorized_keys"
    fi
}

ensure_sshd_include_dir() {
    local tmp_conf
    install -d -m 755 "$CONF_DIR"

    if grep -Eq '^[[:space:]]*# Added by setup-root-ssh-once\.sh$' /etc/ssh/sshd_config; then
        return
    fi

    warn "正在把 Include /etc/ssh/sshd_config.d/*.conf 放到 sshd_config 顶部，确保密钥登录配置优先生效。"
    cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.before-managed-include"
    tmp_conf="$(mktemp)"
    {
        echo "# Added by setup-root-ssh-once.sh"
        echo "Include /etc/ssh/sshd_config.d/*.conf"
        echo
        grep -Ev '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf[[:space:]]*$' /etc/ssh/sshd_config || true
    } > "$tmp_conf"
    atomic_replace "$tmp_conf" /etc/ssh/sshd_config 644 root:root
}

write_managed_sshd_config() {
    local tmp_conf
    local port
    info "写入 SSH 配置 drop-in"
    ensure_sshd_include_dir

    tmp_conf="$(mktemp)"
    cat > "$tmp_conf" <<EOF
# Managed by setup-root-ssh-once.sh
# Named 00-* so these values are read before cloud/provider SSH drop-ins.
# Existing SSH entry ports are kept to avoid remote lockout.
EOF

    for port in $PRESERVED_SSH_PORTS; do
        printf 'Port %s\n' "$port" >> "$tmp_conf"
    done

    if ! printf '%s\n' "$PRESERVED_SSH_PORTS" | tr ' ' '\n' | grep -qx "$SSH_PORT"; then
        printf 'Port %s\n' "$SSH_PORT" >> "$tmp_conf"
    fi

    cat >> "$tmp_conf" <<EOF
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

    atomic_replace "$tmp_conf" "$MANAGED_CONF" 644 root:root
    rm -f "$LEGACY_MANAGED_CONF"
}

write_socket_override() {
    local tmp_conf
    local port

    install -d -m 755 "$MANAGED_SOCKET_DIR"
    tmp_conf="$(mktemp)"
    {
        echo "# Managed by setup-root-ssh-once.sh"
        echo "[Socket]"
        echo "ListenStream="
        for port in $PRESERVED_SSH_PORTS; do
            echo "ListenStream=${port}"
        done
        echo "ListenStream=${SSH_PORT}"
    } > "$tmp_conf"
    atomic_replace "$tmp_conf" "$MANAGED_SOCKET_CONF" 644 root:root
}

write_socket_override_if_needed() {
    if service_active_or_enabled ssh.socket; then
        info "检测到 ssh.socket 已启用，写入 socket 监听端口覆盖配置"
        write_socket_override
        SSH_SOCKET_MANAGED="true"
    else
        info "ssh.socket 未启用，使用 sshd_config 的 Port ${SSH_PORT} 生效"
    fi
}

restore_file_or_remove() {
    local backup_file="$1"
    local target="$2"

    if [ -f "$backup_file" ]; then
        cp -a "$backup_file" "$target"
    else
        rm -f "$target"
    fi
}

rollback_config() {
    warn "正在回滚本次写入的 SSH 配置。"

    if [ -f "$BACKUP_DIR/sshd_config.before-managed-include" ]; then
        cp -a "$BACKUP_DIR/sshd_config.before-managed-include" /etc/ssh/sshd_config
    elif [ -f "$BACKUP_DIR/sshd_config" ]; then
        cp -a "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
    fi

    restore_file_or_remove "$BACKUP_DIR/00-root-public-key-login.conf" "$MANAGED_CONF"
    restore_file_or_remove "$BACKUP_DIR/99-root-public-key-login.conf" "$LEGACY_MANAGED_CONF"
    restore_file_or_remove "$BACKUP_DIR/10-listen-port.conf" "$MANAGED_SOCKET_CONF"
    systemctl daemon-reload >/dev/null 2>&1 || true
}

run_sshd_test() {
    "$SSHD_BIN" -t -f /etc/ssh/sshd_config
}

effective_sshd_config() {
    "$SSHD_BIN" -T -f /etc/ssh/sshd_config -C user=root,host=localhost,addr=127.0.0.1
}

get_effective_value() {
    local key="$1"
    awk -v key="$key" '$1 == key { $1=""; sub(/^ /, ""); print; exit }'
}

line_contains_value() {
    local text="$1"
    local value="$2"
    printf '%s\n' "$text" | tr ' ' '\n' | grep -Fqx "$value"
}

authentication_methods_allow_publickey_only() {
    local methods="$1"
    local method

    for method in $methods; do
        if [ "$method" = "publickey" ]; then
            return 0
        fi
    done

    return 1
}

validate_effective_root_config() {
    local effective
    local port_values
    local preserved_port
    local permit_root
    local pubkey_auth
    local auth_keys
    local auth_methods

    if ! effective="$(effective_sshd_config)"; then
        warn "无法读取 sshd -T 有效配置。"
        return 1
    fi

    port_values="$(printf '%s\n' "$effective" | awk '$1 == "port" {print $2}')"
    permit_root="$(printf '%s\n' "$effective" | get_effective_value permitrootlogin)"
    pubkey_auth="$(printf '%s\n' "$effective" | get_effective_value pubkeyauthentication)"
    auth_keys="$(printf '%s\n' "$effective" | get_effective_value authorizedkeysfile)"
    auth_methods="$(printf '%s\n' "$effective" | get_effective_value authenticationmethods)"

    if ! printf '%s\n' "$port_values" | grep -qx "$SSH_PORT"; then
        warn "root 有效 SSH 配置里没有监听端口 ${SSH_PORT}。"
        return 1
    fi

    for preserved_port in $PRESERVED_SSH_PORTS; do
        if ! printf '%s\n' "$port_values" | grep -qx "$preserved_port"; then
            warn "root 有效 SSH 配置里丢失了原有入口端口 ${preserved_port}。"
            return 1
        fi
    done

    if [ "$permit_root" != "prohibit-password" ]; then
        warn "root 有效配置 PermitRootLogin=${permit_root:-空}，没有变成 prohibit-password。"
        return 1
    fi

    if [ "$pubkey_auth" != "yes" ]; then
        warn "root 有效配置 PubkeyAuthentication=${pubkey_auth:-空}，密钥登录仍未开启。"
        return 1
    fi

    if ! line_contains_value "$auth_keys" ".ssh/authorized_keys"; then
        warn "root 有效配置 AuthorizedKeysFile=${auth_keys:-空}，没有包含 .ssh/authorized_keys。"
        return 1
    fi

    if [ -n "$auth_methods" ] && [ "$auth_methods" != "any" ] && ! authentication_methods_allow_publickey_only "$auth_methods"; then
        warn "AuthenticationMethods=${auth_methods} 没有提供单独 publickey 登录方案，请先人工处理该配置。"
        return 1
    fi

    ok "root 的 SSH 有效配置检查通过"
}

validate_sshd_config() {
    info "检查 SSH 配置语法和 root 有效配置"

    if ! run_sshd_test; then
        rollback_config
        die "SSH 配置语法检查失败，已回滚配置；当前 SSH 服务没有被重载。"
    fi

    if ! validate_effective_root_config; then
        rollback_config
        die "root SSH 有效配置检查失败，已回滚配置；当前 SSH 服务没有被重载。"
    fi
}

open_firewall_first() {
    info "先放行新 SSH 端口，避免重载后新端口无法连接"

    if command_exists ufw; then
        if ufw status 2>/dev/null | grep -qi '^Status: active'; then
            ufw allow "${SSH_PORT}/tcp" comment "root ssh ${SSH_PORT}" >/dev/null
            FIREWALL_RULE_ADDED="true"
            ok "UFW 已放行 ${SSH_PORT}/tcp"
        else
            warn "UFW 未启用，跳过 ufw allow。"
        fi
    else
        warn "未安装 ufw，跳过 ufw allow。"
    fi

    if command_exists firewall-cmd && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
        FIREWALL_RULE_ADDED="true"
        ok "firewalld 已放行 ${SSH_PORT}/tcp"
    fi
}

reload_or_restart_service() {
    local unit="$1"

    if systemctl reload "$unit" >/dev/null 2>&1; then
        ok "${unit} 已 reload"
        return 0
    fi

    warn "${unit} 不支持 reload 或 reload 失败，尝试 restart。"
    systemctl restart "$unit"
    ok "${unit} 已 restart"
}

restart_known_ssh_units_best_effort() {
    systemctl daemon-reload >/dev/null 2>&1 || true

    if service_active_or_enabled ssh.socket; then
        systemctl restart ssh.socket >/dev/null 2>&1 || true
    fi

    if service_exists ssh.service; then
        systemctl restart ssh.service >/dev/null 2>&1 || true
    fi

    if service_exists sshd.service; then
        systemctl restart sshd.service >/dev/null 2>&1 || true
    fi
}

force_restart_ssh_units() {
    if service_active_or_enabled ssh.socket; then
        systemctl restart ssh.socket
    fi

    if service_exists ssh.service; then
        systemctl restart ssh.service
    fi

    if service_exists sshd.service; then
        systemctl restart sshd.service
    fi
}

new_port_is_listening() {
    [ -n "$(port_listener_lines "$SSH_PORT")" ]
}

preserved_ports_are_listening() {
    local port
    local missing="false"

    for port in $PRESERVED_SSH_PORTS; do
        if [ -z "$(port_listener_lines "$port")" ]; then
            warn "原有入口端口 ${port} 已不再监听。"
            missing="true"
        fi
    done

    [ "$missing" = "false" ]
}

ensure_new_port_listening_or_rollback() {
    if new_port_is_listening; then
        ok "本机已经监听新端口 ${SSH_PORT}"
        if preserved_ports_are_listening; then
            ok "原有 SSH 入口端口仍在监听"
            return
        fi
    fi

    warn "reload 后监听状态不完整，尝试 restart SSH 单元。"
    if force_restart_ssh_units && new_port_is_listening && preserved_ports_are_listening; then
        ok "restart 后新端口和原有入口端口都在监听"
        return
    fi

    rollback_config
    restart_known_ssh_units_best_effort
    die "没有检测到完整 SSH 监听状态，已回滚配置。防火墙新增规则如不需要请手动删除。"
}

reload_systemd_and_ssh_or_rollback() {
    local touched_service="false"

    info "重新加载 systemd 并更新 SSH 服务"

    if ! systemctl daemon-reload; then
        rollback_config
        die "systemctl daemon-reload 失败，已回滚配置。"
    fi

    if [ "$SSH_SOCKET_MANAGED" = "true" ]; then
        if ! systemctl restart ssh.socket; then
            rollback_config
            restart_known_ssh_units_best_effort
            die "ssh.socket 重启失败，已回滚配置。"
        fi
        ok "ssh.socket 已重启"
    fi

    if service_exists ssh.service; then
        if ! reload_or_restart_service ssh.service; then
            rollback_config
            restart_known_ssh_units_best_effort
            die "ssh.service 更新失败，已回滚配置。"
        fi
        touched_service="true"
    fi

    if service_exists sshd.service; then
        if ! reload_or_restart_service sshd.service; then
            rollback_config
            restart_known_ssh_units_best_effort
            die "sshd.service 更新失败，已回滚配置。"
        fi
        touched_service="true"
    fi

    if [ "$touched_service" != "true" ]; then
        rollback_config
        die "没有找到 ssh.service 或 sshd.service，已回滚配置。"
    fi

    ensure_new_port_listening_or_rollback
}

show_listening_ports() {
    info "检查 SSH 监听端口"
    ss -tlpn | grep -E '(:22|:'"$SSH_PORT"'|sshd|ssh)' || true
}

print_next_steps() {
    echo
    echo "============================================================"
    ok "root SSH 配置完成"
    echo "============================================================"
    echo "新端口: ${SSH_PORT}"
    echo "保留的原有 SSH 入口端口: ${PRESERVED_SSH_PORTS:-未识别}"
    echo "root 公钥文件: /root/.ssh/authorized_keys"
    echo "SSH 配置: ${MANAGED_CONF}"
    if [ -f "$MANAGED_SOCKET_CONF" ]; then
        echo "ssh.socket 配置: ${MANAGED_SOCKET_CONF}"
    fi
    echo "备份目录: ${BACKUP_DIR}"
    echo
    echo "请不要立刻关闭当前 SSH 窗口。先在新的终端里测试："
    echo "  ssh -p ${SSH_PORT} root@你的服务器IP"
    echo
    warn "云服务器还要确认安全组/云防火墙已经放行 ${SSH_PORT}/tcp。"
    warn "脚本不会关闭 22 或任何原有 SSH 入口端口；确认新端口长期可用后，再手动收紧旧端口。"
    if [ "$FIREWALL_RULE_ADDED" = "true" ]; then
        warn "如果后续要回滚脚本，防火墙新增的 ${SSH_PORT}/tcp 规则不会自动删除，需要手动清理。"
    fi
}

main() {
    need_preflight
    show_intro
    prompt_port
    prompt_public_key
    make_backup
    collect_preserved_ssh_ports
    install_root_key
    write_managed_sshd_config
    write_socket_override_if_needed
    open_firewall_first
    validate_sshd_config
    reload_systemd_and_ssh_or_rollback
    show_listening_ports
    print_next_steps
}

main "$@"
