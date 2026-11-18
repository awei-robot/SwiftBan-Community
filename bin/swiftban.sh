#!/bin/bash
#==============================================================
# SwiftBan - CLI 入口
# 用法: swiftban <command> [options]
#==============================================================
set -uo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 版本
SWIFTBAN_VERSION="1.0.3"

# 配置文件路径（可通过环境变量覆盖）
SWIFTBAN_CONF="${SWIFTBAN_CONF:-/etc/swiftban/swiftban.conf}"
SWIFTBAN_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib"
export SWIFTBAN_ENTRY
SWIFTBAN_ENTRY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

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
    LOG_FORMAT="${LOG_FORMAT:-auto}"
    WATCH_RETENTION_DAYS="${WATCH_RETENTION_DAYS:-7}"
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
    local lib path
    # 先核对全部模块，避免部分加载后继续调用不存在的函数。
    for lib in logger firewall whitelist runtime watch detector; do
        path="${SWIFTBAN_LIB_DIR}/${lib}.sh"
        if [[ ! -r "$path" ]]; then
            echo "错误: 无法读取模块 ${path}，请从同一版本源码重新运行安装脚本" >&2
            return 1
        fi
    done
    for lib in logger firewall whitelist runtime watch detector; do
        # shellcheck disable=SC1090
        if ! source "${SWIFTBAN_LIB_DIR}/${lib}.sh"; then
            echo "错误: 加载模块 ${SWIFTBAN_LIB_DIR}/${lib}.sh 失败" >&2
            return 1
        fi
    done
}

#---------------- 命令 ----------------
cmd_run() {
    local mode=formal
    if (( $# > 1 )); then echo "用法: swiftban run [--dry-run]" >&2; return 1; fi
    case "${1:-}" in
        "") ;;
        --dry-run) mode=dry-run ;;
        *) echo "用法: swiftban run [--dry-run]" >&2; return 1 ;;
    esac
    rt_execute "$mode" run
}

cmd_status() {
    echo "=== SwiftBan v${SWIFTBAN_VERSION} 状态 ==="
    echo "配置:     ${SWIFTBAN_CONF}"
    echo "日志目录: ${LOG_DIR}"
    echo "状态目录: ${STATE_DIR}"
    echo "窗口:     ${WINDOW}s | 封禁时长: ${BAN_TTL}s"
    echo "封禁链:   ${FIREWALL_CHAIN}"
    rt_show_status
    rt_show_schedule
    echo
    echo "=== 最近操作 ==="
    tail -5 "${BANLOG}" 2>/dev/null || echo "(无可读操作日志)"
}

cmd_list() {
    if [[ "${1:-}" == --dry-run && $# == 1 ]]; then rt_list_dry; return; fi
    if (( $# > 0 )); then echo "用法: swiftban list [--dry-run]" >&2; return 1; fi
    if [[ -e "$STATE_DIR/stopped.tsv" ]]; then
        echo "=== 保存的封禁记录（检测已停止；规则可能待恢复，实际状态见 status）==="
    else
        echo "=== 封禁列表 (banlist.txt) ==="
    fi
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
    [[ -n "$ip" ]] || { echo "用法: swiftban ban <IP>" >&2; return 1; }
    ip=$(wl_normalize_ip "$ip") || { echo "错误: ban 只接受合法的单个 IP" >&2; return 1; }
    # shellcheck disable=SC2034
    NOW=$(date +%s)
    det_ban "$ip" "手动封禁"
}

cmd_unban() {
    local ip="${1:-}"
    [[ -n "$ip" ]] || { echo "用法: swiftban unban <IP>" >&2; return 1; }
    ip=$(wl_normalize_ip "$ip") || { echo "错误: unban 只接受合法的单个 IP" >&2; return 1; }
    fw_unban "$ip" || return 1
    if [[ -f "${BANLIST}" ]]; then
        local tmp
        tmp=$(mktemp "$STATE_DIR/.unban.XXXXXX") || return 1
        if SWIFTBAN_IP="$ip" awk -F'|' "$(ip_awk)"'
            ip_canon($1)!=ENVIRON["SWIFTBAN_IP"] {print}
        ' "$BANLIST" > "$tmp" && mv "$tmp" "$BANLIST"; then :
        else rm -f "$tmp"; return 1; fi
    fi
    log_action "UNBAN(manual) $ip"
    echo "已解封: $ip"
}

cmd_whitelist_reconcile() (
    local ip ts ttl reason tmp failed=0
    [[ -f "$BANLIST" ]] || return 0
    tmp=$(mktemp "$STATE_DIR/.whitelist-unban.XXXXXX") || return 1
    trap 'rm -f "$tmp"' EXIT
    while IFS='|' read -r ip ts ttl reason || [[ -n "$ip" ]]; do
        [[ -n "$ip" ]] || continue
        if wl_is_whitelisted "$ip"; then
            if fw_unban "$ip"; then
                log_action "UNBAN(whitelist) $ip"
                continue
            fi
            log_error "白名单已保存，但解封失败，保留封禁记录；请重试 whitelist add: $ip"
            failed=1
        fi
        printf '%s|%s|%s|%s\n' "$ip" "$ts" "$ttl" "$reason" >> "$tmp" || return 1
    done < "$BANLIST"
    mv -f "$tmp" "$BANLIST" || return 1
    (( failed == 0 ))
)

cmd_whitelist() {
    local action="${1:-list}"
    case "$action" in
        add)    wl_add "${2:-}" && cmd_whitelist_reconcile ;;
        remove) wl_remove "${2:-}" ;;
        list)   wl_list ;;
        *)      echo "用法: swiftban whitelist {add|remove|list} [IP/CIDR]"; exit 1 ;;
    esac
}

cmd_install_cron() {
    rt_require_root || return 1
    rt_install_cron "$SWIFTBAN_ENTRY" "$SWIFTBAN_CONF" "$STATE_DIR"
}

cmd_configtest() {
    local failed=0
    load_libs || return 1
    det_check_config || return 1
    wl_check_config || return 1
    echo "=== 配置检查 ==="
    echo "日志格式: ${LOG_FORMAT}"
    if [[ -d "$LOG_DIR" && -r "$LOG_DIR" && -x "$LOG_DIR" ]]; then echo "日志目录: $LOG_DIR ✓"
    else echo "日志目录: $LOG_DIR ✗ 不存在或不可读取"; failed=1; fi
    if [[ -d "$STATE_DIR" && -r "$STATE_DIR" && -w "$STATE_DIR" && -x "$STATE_DIR" ]]; then echo "状态目录: $STATE_DIR ✓"
    else echo "状态目录: $STATE_DIR ✗ 不存在或不可读写"; failed=1; fi
    if command -v iptables >/dev/null 2>&1 && iptables -L "$FIREWALL_CHAIN" -n >/dev/null 2>&1; then echo "防火墙链: $FIREWALL_CHAIN ✓"
    else echo "防火墙链: $FIREWALL_CHAIN ✗ iptables 缺失、链不可用或权限不足"; failed=1; fi
    if command -v ip6tables >/dev/null 2>&1; then
        echo "IPv6 工具: ip6tables 已安装"
        if fw_ipv6_chain_available; then
            echo "IPv6 防火墙链: $FIREWALL_CHAIN ✓"
        else
            echo "IPv6 防火墙链: $FIREWALL_CHAIN ⚠ 不可用或权限不足，将忽略 IPv6；IPv4 不受影响"
        fi
    else echo "IPv6 工具: 未安装 ip6tables（可选，IPv4 功能不受影响）"; fi
    if [[ -r "$WHITELIST_FILE" && -f "$WHITELIST_FILE" ]]; then echo "白名单文件: $WHITELIST_FILE ✓"
    else echo "白名单文件: $WHITELIST_FILE ✗ 不存在或不可读取"; failed=1; fi
    echo
    echo "阈值: 444=${LIMIT_444} 扫描=${LIMIT_SCAN} 恶意路径=${LIMIT_EVILPATH} 载荷=${LIMIT_PAYLOAD} UA=${LIMIT_UA} 爆破=${LIMIT_AUTH} 接口=${LIMIT_API} 速率=${LIMIT_API_RATE} 空UA=${LIMIT_EMPTYUA}"
    return "$failed"
}

#---------------- 帮助 ----------------
watch_usage() {
    cat <<'EOF'
用法: swiftban watch [选项]

WATCH 观察列表：单接口高频、单接口速率和总请求高频仅告警，不单独封禁。
默认查看正式扫描近24小时记录，按最后发现时间倒序，最多50项。

选项:
  --ip <IP>            筛选单个 IPv4/IPv6 地址
  --rule <规则>        api=单接口高频，apirate=单接口速率，freq=总请求高频
  --since <时长>       查询最近时段，如 24h、7d（小时 h 或天 d）
  --limit <数量>       最多显示条数，默认50
  --dry-run            查看演练观察，默认查看正式扫描
  --json               输出 JSON，便于导出和脚本处理
  -h, --help           显示本帮助

示例:
  swiftban watch
  swiftban watch --ip 123.114.230.31
  swiftban watch --rule api --since 7d --limit 100
  swiftban watch --dry-run --json

字段包含最近计数/当时阈值、峰值、命中轮次、首次/最后发现和接口。
次数不跨扫描累加；同轮多个超限分钟取最大计数，只计一个命中轮次。
时间为 UTC；统计限于查询范围。正式与演练独立保存，默认保留7天，
可通过 WATCH_RETENTION_DAYS 修改。升级前的控制台 WATCH 输出不补录。
完成新扫描后开始积累记录；列表为空时可检查扫描模式和查询时间范围。
EOF
}

usage() {
    cat << EOF
SwiftBan v${SWIFTBAN_VERSION} - Nginx 攻击检测与自动封禁

用法: swiftban <命令> [选项]

命令:
  run                  执行一次检测（cron 调用）
  run --dry-run        演练模式（独立保存候选，不封禁）
  start                恢复未过期封禁并立即执行正式检测
  stop                 停止当前扫描并撤销规则，保留记录和 TTL
  status               查看当前执行、最近模式与定时任务
  watch                查看观察记录（支持 --ip、--rule、--since、--limit、--dry-run、--json）
  list                 列出保存的封禁记录
  list --dry-run       查看最近一次完整演练候选
  ban <IP>             手动封禁
  unban <IP>           手动解封
  whitelist add <IP>   添加白名单（支持 CIDR）
  whitelist remove <IP> 移除白名单
  whitelist list       列出白名单
  install-cron         安装定时任务（每分钟）
  configtest           配置检查
  doctor               运维诊断并提示修复方法
  version              版本信息

WATCH 示例:
  swiftban watch --rule api --since 7d
  swiftban watch --dry-run
  swiftban watch --help       查看全部参数与字段说明

配置: ${SWIFTBAN_CONF}
EOF
}

#---------------- 主入口 ----------------
main() {
    local cmd="${1:-help}"
    shift || true
    case "$cmd" in
        version|-v|--version) echo "SwiftBan v${SWIFTBAN_VERSION}"; return ;;
        help|-h|--help) usage; return ;;
        watch)
            if [[ $# == 1 && ( "$1" == --help || "$1" == -h ) ]]; then watch_usage; return; fi
            ;;
        run|start|stop|status|list|ls|ban|unban|whitelist|wl|install-cron|configtest|doctor|__worker) ;;
        *) usage; return 1 ;;
    esac
    load_config
    load_libs || return 1
    case "$cmd" in
        run) cmd_run "$@" ;;
        start) (( $# == 0 )) || return 1; rt_execute formal start ;;
        stop) (( $# == 0 )) || return 1; rt_stop ;;
        status) cmd_status ;;
        watch) cmd_watch "$@" ;;
        list|ls) cmd_list "$@" ;;
        ban) rt_mutate ban cmd_ban "$@" ;;
        unban) rt_mutate unban cmd_unban "$@" ;;
        whitelist|wl)
            case "${1:-list}" in
                list) cmd_whitelist "$@" ;;
                *) rt_mutate whitelist cmd_whitelist "$@" ;;
            esac ;;
        install-cron) cmd_install_cron ;;
        configtest) cmd_configtest ;;
        doctor) (( $# == 0 )) || return 1; rt_doctor ;;
        __worker) (( $# == 3 )) || return 1; rt_worker "$@" ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
