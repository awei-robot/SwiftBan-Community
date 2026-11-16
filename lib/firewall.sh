#!/bin/bash
#==============================================================
# SwiftBan - 防火墙抽象层
# 支持: iptables / ip6tables（DOCKER-USER 链）
#==============================================================

# 判断是否 IPv6
is_ipv6() { [[ "$1" == *:* ]]; }

# 封禁 IP（失败返回非零并记录错误，不静默吞掉）
fw_ban() {
    local ip="$1" err
    if is_ipv6 "$ip"; then
        if ! command -v ip6tables >/dev/null 2>&1; then
            log_error "未安装 ip6tables，无法封禁 IPv6 地址 ${ip}"
            return 1
        fi
        if ! err=$(ip6tables -I "${FIREWALL_CHAIN}" 1 -s "$ip" -j DROP 2>&1); then
            log_error "ip6tables 封禁失败 ${ip}: ${err}"
            return 1
        fi
    else
        if ! err=$(iptables -I "${FIREWALL_CHAIN}" 1 -s "$ip" -j DROP 2>&1); then
            log_error "iptables 封禁失败 ${ip}: ${err}"
            return 1
        fi
    fi
    return 0
}

# 解封 IP（尽力而为：规则不存在不算失败，其他错误记录告警）
fw_unban() {
    local ip="$1" err
    if is_ipv6 "$ip"; then
        if ! command -v ip6tables >/dev/null 2>&1; then
            log_warn "未安装 ip6tables，跳过 IPv6 地址 ${ip} 的解封规则操作"
            return 0
        fi
        if ! err=$(ip6tables -D "${FIREWALL_CHAIN}" -s "$ip" -j DROP 2>&1); then
            log_warn "ip6tables 解封 ${ip} 返回: ${err}"
        fi
    else
        if ! err=$(iptables -D "${FIREWALL_CHAIN}" -s "$ip" -j DROP 2>&1); then
            log_warn "iptables 解封 ${ip} 返回: ${err}"
        fi
    fi
    return 0
}

# 是否已封禁
fw_is_banned() {
    local ip="$1"
    if is_ipv6 "$ip"; then
        command -v ip6tables >/dev/null 2>&1 || return 1
        ip6tables -C "${FIREWALL_CHAIN}" -s "$ip" -j DROP 2>/dev/null && return 0
    else
        iptables -C "${FIREWALL_CHAIN}" -s "$ip" -j DROP 2>/dev/null && return 0
    fi
    return 1
}

# 当前封禁数量（用 -S 精确统计规则，避免误计链内其他 DROP）
fw_count() {
    local c4 c6=0
    c4=$(iptables -S "${FIREWALL_CHAIN}" 2>/dev/null | grep -c -- '-j DROP' || true)
    if command -v ip6tables >/dev/null 2>&1; then
        c6=$(ip6tables -S "${FIREWALL_CHAIN}" 2>/dev/null | grep -c -- '-j DROP' || true)
    fi
    echo "${c4}:${c6}"
}

# 列出所有封禁规则
fw_list() {
    local ip
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        echo "$ip"
    done < <(iptables -S "${FIREWALL_CHAIN}" 2>/dev/null | grep -- '-j DROP' | awk '{for(i=1;i<=NF;i++) if($i=="-s") print $(i+1)}' | sort -u)
}
