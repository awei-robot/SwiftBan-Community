#!/bin/bash
#==============================================================
# SwiftBan - CLI 入口
# 用法: swiftban <command> [options]
#==============================================================
set -uo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 版本
SWIFTBAN_VERSION="1.0.1"

# 配置文件路径（可通过环境变量覆盖）
SWIFTBAN_CONF="${SWIFTBAN_CONF:-/etc/swiftban/swiftban.conf}"
SWIFTBAN_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib"

#---------------- 加载配置 ----------------
load_config() {
    if [[ -f "$SWIFTBAN_CONF" ]]; then
        # shellcheck disable=SC1090
        source "$SWIFTBAN_CONF"
    else
        echo "错误: 配置文件不存在: $SWIFTBAN_CONF" >&2
        echo "请复制 config/swiftban.conf 到该路径，或设置 SWIFTBAN_CONF 环境变量" >&2
        exit 1
    fi

    # 默认值
    LOG_DIR="${LOG_DIR:-/root/proxy-manager/data/logs}"
    STATE_DIR="${STATE_DIR:-/etc/swiftban/state}"
    BAN_TTL="${BAN_TTL:-259200}"
    WINDOW="${WINDOW:-7200}"
    FIREWALL_CHAIN="${FIREWALL_CHAIN:-DOCKER-USER}"
    WHITELIST="${WHITELIST:-127.0.0.1,::1}"
    WHITELIST_FILE="${WHITELIST_FILE:-${STATE_DIR}/whitelist.txt}"

    # 阈值默认值
    LIMIT_444="${LIMIT_444:-10}"
    LIMIT_SCAN="${LIMIT_SCAN:-100}"
    LIMIT_EVILPATH="${LIMIT_EVILPATH:-3}"
    LIMIT_PAYLOAD="${LIMIT_PAYLOAD:-2}"
    LIMIT_UA="${LIMIT_UA:-5}"
    LIMIT_AUTH="${LIMIT_AUTH:-20}"
    LIMIT_API="${LIMIT_API:-200}"
    LIMIT_API_RATE="${LIMIT_API_RATE:-30}"
    LIMIT_EMPTYUA="${LIMIT_EMPTYUA:-20}"
    LIMIT_HIGHFREQ="${LIMIT_HIGHFREQ:-500}"

    # 特征库默认值
    SAFE_PATH="${SAFE_PATH:-/TDT/}"
    GIT_SAFE="${GIT_SAFE:-git-upload-pack|git-receive-pack|info/refs}"
    EVIL_PATH="${EVIL_PATH:-wp-admin|wp-login|\.env|\.git|etc/passwd}"
    EVIL_PAYLOAD="${EVIL_PAYLOAD:-union.*select|sleep\(|<script>|alert\(|\.\./|cmd=}"
    EVIL_UA="${EVIL_UA:-sqlmap|nikto|nmap|masscan|zgrab|python-requests}"
    LOGIN_PATH="${LOGIN_PATH:-login|signin|auth|token}"

    # 运行时变量
    BANLIST="${STATE_DIR}/banlist.txt"
    BANLOG="${STATE_DIR}/ban.log"
    # shellcheck disable=SC2034  # NOW/NOW_EPOCH 由 detector.sh 模块内赋值使用
    NOW=0
    # shellcheck disable=SC2034
    NOW_EPOCH=0
}

#---------------- 加载模块 ----------------
load_libs() {
    local lib
    for lib in logger firewall whitelist detector; do
        # shellcheck disable=SC1090
        source "${SWIFTBAN_LIB_DIR}/${lib}.sh"
    done
}

#---------------- 命令 ----------------
cmd_run() {
    local dry="0"
    [[ "${1:-}" == "--dry-run" ]] && dry="1"
    det_run "$dry"
}

cmd_status() {
    local cnt
    cnt=$(fw_count)
    echo "=== SwiftBan v${SWIFTBAN_VERSION} 状态 ==="
    echo "配置:     ${SWIFTBAN_CONF}"
    echo "日志目录: ${LOG_DIR}"
    echo "状态目录: ${STATE_DIR}"
    echo "窗口:     ${WINDOW}s | 封禁时长: ${BAN_TTL}s"
    echo "封禁链:   ${FIREWALL_CHAIN}"
    echo "封禁数:   IPv4=${cnt%:*} IPv6=${cnt#*:}"
    echo
    echo "=== 最近操作 ==="
    tail -5 "${BANLOG}" 2>/dev/null || echo "(无)"
}

cmd_list() {
    echo "=== 封禁列表 (banlist.txt) ==="
    if [[ -f "${BANLIST}" ]]; then
        printf "%-18s %-10s %-8s %s\n" "IP" "时间" "TTL" "原因"
        while IFS='|' read -r ip ts ttl reason; do
            [[ -z "$ip" ]] && continue
            printf "%-18s %-10s %-8s %s\n" "$ip" "$(date -d "@$ts" '+%m-%d %H:%M' 2>/dev/null || echo "$ts")" "$ttl" "$reason"
        done < "${BANLIST}"
    else
        echo "(空)"
    fi
}

cmd_ban() {
    local ip="${1:-}"
    [[ -z "$ip" ]] && { echo "用法: swiftban ban <IP>"; exit 1; }
    # shellcheck disable=SC2034  # NOW 供 detector.sh 模块读取
    NOW=$(date +%s)
    det_ban "$ip" "手动封禁"
}

cmd_unban() {
    local ip="${1:-}"
    [[ -z "$ip" ]] && { echo "用法: swiftban unban <IP>"; exit 1; }
    fw_unban "$ip"
    if [[ -f "${BANLIST}" ]]; then
        # 按 IP 字段固定匹配删除，避免 sed 正则注入
        local tmp
        tmp=$(mktemp)
        awk -v ip="$ip" -F'|' '$1 != ip' "${BANLIST}" > "$tmp" && mv "$tmp" "${BANLIST}"
    fi
    log_action "UNBAN(manual) $ip"
    echo "已解封: $ip"
}

cmd_whitelist() {
    local action="${1:-list}"
    case "$action" in
        add)    wl_add "${2:-}" ;;
        remove) wl_remove "${2:-}" ;;
        list)   wl_list ;;
        *)      echo "用法: swiftban whitelist {add|remove|list} [IP/CIDR]"; exit 1 ;;
    esac
}

cmd_install_cron() {
    local cronline="* * * * * /usr/local/bin/swiftban run >> ${STATE_DIR}/cron.log 2>&1"
    if crontab -l 2>/dev/null | grep -q "swiftban run"; then
        echo "cron 已存在"
        return 0
    fi
    (crontab -l 2>/dev/null; echo "$cronline") | crontab -
    echo "已安装 cron: $cronline"
}

cmd_configtest() {
    echo "=== 配置检查 ==="
    echo "日志目录: ${LOG_DIR} $([[ -d "$LOG_DIR" ]] && echo '✓' || echo '✗ 不存在')"
    echo "状态目录: ${STATE_DIR} $([[ -d "$STATE_DIR" ]] && echo '✓' || echo '✗ 不存在')"
    echo "防火墙链: ${FIREWALL_CHAIN} $(iptables -L "$FIREWALL_CHAIN" -n >/dev/null 2>&1 && echo '✓' || echo '✗ 不可用')"
    echo "白名单文件: ${WHITELIST_FILE} $([[ -f "$WHITELIST_FILE" ]] && echo '✓' || echo '✗ 不存在')"
    echo
    echo "阈值: 444=${LIMIT_444} 扫描=${LIMIT_SCAN} 恶意路径=${LIMIT_EVILPATH} 载荷=${LIMIT_PAYLOAD} UA=${LIMIT_UA} 爆破=${LIMIT_AUTH} 接口=${LIMIT_API} 速率=${LIMIT_API_RATE} 空UA=${LIMIT_EMPTYUA}"
}

#---------------- 帮助 ----------------
usage() {
    cat << EOF
SwiftBan v${SWIFTBAN_VERSION} - Nginx 攻击检测与自动封禁

用法: swiftban <命令> [选项]

命令:
  run                  执行一次检测（cron 调用）
  run --dry-run        演练模式（只检测不封禁）
  status               查看运行状态
  list                 列出封禁 IP
  ban <IP>             手动封禁
  unban <IP>           手动解封
  whitelist add <IP>   添加白名单（支持 CIDR）
  whitelist remove <IP> 移除白名单
  whitelist list       列出白名单
  install-cron         安装定时任务（每分钟）
  configtest           配置检查
  version              版本信息

配置: ${SWIFTBAN_CONF}
EOF
}

#---------------- 主入口 ----------------
main() {
    local cmd="${1:-help}"
    shift || true

    # run 命令需要单实例锁：cron 与手动执行并发时避免重复封禁/状态竞态
    if [[ "$cmd" == "run" ]]; then
        load_config
        mkdir -p "${STATE_DIR}"
        local lockfd
        exec {lockfd}>"${STATE_DIR}/.lock" || true
        if ! flock -n "$lockfd"; then
            echo "已有 swiftban run 实例在执行，跳过本次" >&2
            exit 0
        fi
    fi

    case "$cmd" in
        run)            load_libs; cmd_run "$@" ;;
        status)         load_config; load_libs; cmd_status ;;
        list|ls)        load_config; load_libs; cmd_list ;;
        ban)            load_config; load_libs; cmd_ban "$@" ;;
        unban)          load_config; load_libs; cmd_unban "$@" ;;
        whitelist|wl)   load_config; load_libs; cmd_whitelist "$@" ;;
        install-cron)   load_config; cmd_install_cron ;;
        configtest)     load_config; cmd_configtest ;;
        version|-v|--version) echo "SwiftBan v${SWIFTBAN_VERSION}" ;;
        help|-h|--help|*) usage ;;
    esac
}

main "$@"
