#!/bin/bash
#==============================================================
# SwiftBan 安装脚本
#==============================================================
set -euo pipefail

SWIFTBAN_HOME="/etc/swiftban"
SWIFTBAN_BIN="/usr/local/bin/swiftban"
SWIFTBAN_LIB="/usr/local/lib/swiftban"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

#---------------- 前置检查 ----------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 权限运行: sudo $0"
        exit 1
    fi
}

check_platform() {
    [[ "$(uname -s)" == Linux && -r /proc/self/stat ]] || { error "安装需要 Linux /proc"; exit 1; }
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1) )); then
        error "安装需要 Bash 4.1 或更新版本"
        exit 1
    fi
}

check_deps() {
    check_platform || return 1
    local deps=(iptables awk grep find stat sort flock setsid)
    local missing=()
    for d in "${deps[@]}"; do
        command -v "$d" >/dev/null 2>&1 || missing+=("$d")
    done
    if (( ${#missing[@]} > 0 )); then
        error "缺少依赖: ${missing[*]}"
        exit 1
    fi
    if ! command -v ip6tables >/dev/null 2>&1; then
        warn "未安装 ip6tables，IPv6 封禁不可用，IPv4 功能不受影响"
    fi

    # 与检测器一致：优先 gawk，并检查结构化解析使用的区间正则。
    local awk_bin=awk
    if command -v gawk >/dev/null 2>&1; then awk_bin=gawk; fi
    if ! "$awk_bin" 'BEGIN{if(mktime("2026 11 12 00 00 00")<0 || "123" !~ /^[0-9]{3}$/) exit 1}' >/dev/null 2>&1; then
        error "awk 需支持 mktime 和区间正则，请安装 gawk 或较新版本 mawk"
        error "  Debian/Ubuntu: apt install gawk"
        error "  CentOS/RHEL:   yum install gawk"
        exit 1
    fi
    local optional
    for optional in curl jq; do
        command -v "$optional" >/dev/null 2>&1 || warn "可选来源地功能需要 $optional；不影响日志检测"
    done
    info "依赖检查通过（awk 支持 mktime 和区间正则）"
}

#---------------- 安装 ----------------
install_files() {
    info "安装到 ${SWIFTBAN_HOME} ..."

    mkdir -p "${SWIFTBAN_HOME}/state" "${SWIFTBAN_LIB}" || return 1

    # 主程序
    install -m 755 "${SCRIPT_DIR}/bin/swiftban.sh" "${SWIFTBAN_BIN}" || return 1
    # 模块
    for lib in logger firewall whitelist runtime geo watch detector; do
        install -m 644 "${SCRIPT_DIR}/lib/${lib}.sh" "${SWIFTBAN_LIB}/${lib}.sh" || return 1
    done
    # 配置
    if [[ ! -f "${SWIFTBAN_HOME}/swiftban.conf" ]]; then
        install -m 644 "${SCRIPT_DIR}/config/swiftban.conf" "${SWIFTBAN_HOME}/swiftban.conf" || return 1
    else
        warn "配置已存在，保留: ${SWIFTBAN_HOME}/swiftban.conf"
    fi
    # 白名单模板
    if [[ ! -f "${SWIFTBAN_HOME}/state/whitelist.txt" ]]; then
        if ! cat > "${SWIFTBAN_HOME}/state/whitelist.txt" << 'EOF'
# SwiftBan 白名单 - 每行 IP 或 CIDR（# 注释）
EOF
        then
            error "创建白名单模板失败，安装未完成"
            return 1
        fi
    fi

    # 修正 lib 目录引用（安装后路径）
    if ! sed -i.bak "s|SWIFTBAN_LIB_DIR=.*|SWIFTBAN_LIB_DIR=\"${SWIFTBAN_LIB}\"|" "${SWIFTBAN_BIN}"; then
        error "写入模块加载目录失败，安装未完成"
        return 1
    fi

    info "文件安装完成"
}

# 安装前确认最容易因部署环境不同而需要调整的两项配置。
configure_runtime_settings() {
    local conf="$SWIFTBAN_HOME/swiftban.conf" current_log current_chain
    local answer new_log new_chain quoted_log quoted_chain tmp changed=0
    # shellcheck disable=SC1090
    source "$conf" || return 1
    current_log="${LOG_DIR:-/root/proxy-manager/data/logs}"
    current_chain="${FIREWALL_CHAIN:-DOCKER-USER}"

    echo
    echo "请确认 SwiftBan 的运行环境配置；直接回车保留当前值。"
    if read -r -p "Nginx/NPM 日志目录 [${current_log}]: " answer; then :; else answer=""; fi
    new_log="${answer:-$current_log}"
    while :; do
        if read -r -p "IPv4/IPv6 防火墙链 [${current_chain}]（Docker 通常 DOCKER-USER，裸机通常 INPUT）: " answer; then :; else answer=""; fi
        new_chain="${answer:-$current_chain}"
        if [[ "$new_chain" =~ ^[[:alnum:]_.:-]{1,29}$ ]]; then break; fi
        warn "链名只允许 1–29 位字母、数字、下划线、点、冒号或连字符。"
    done

    [[ "$new_log" == "$current_log" ]] || changed=1
    [[ "$new_chain" == "$current_chain" ]] || changed=1
    if (( ! changed )); then
        info "保留日志目录和防火墙链配置"
        return 0
    fi

    tmp=$(mktemp "${conf}.XXXXXX") || return 1
    if ! cat "$conf" > "$tmp"; then rm -f "$tmp"; return 1; fi
    {
        printf '\n# 安装时确认的运行环境配置\n'
        if [[ "$new_log" != "$current_log" ]]; then
            printf -v quoted_log '%q' "$new_log"
            printf 'LOG_DIR=%s\n' "$quoted_log"
        fi
        if [[ "$new_chain" != "$current_chain" ]]; then
            printf -v quoted_chain '%q' "$new_chain"
            printf 'FIREWALL_CHAIN=%s\n' "$quoted_chain"
        fi
    } >> "$tmp" || { rm -f "$tmp"; return 1; }
    if ! chmod --reference="$conf" "$tmp" || ! mv -f "$tmp" "$conf"; then
        rm -f "$tmp"
        error "保存日志目录和防火墙链配置失败"
        return 1
    fi
    info "已保存日志目录和防火墙链配置"
}

install_cron() {
    local ans conf
    read -r -p "是否安装正式检测 cron（每分钟执行，单次 --dry-run 不改变它）? [Y/n] " ans
    case "${ans:-Y}" in
        [Yy]*)
            # shellcheck disable=SC1090,SC1091
            source "$SCRIPT_DIR/lib/runtime.sh" || return 1
            conf="${SWIFTBAN_CONF:-$SWIFTBAN_HOME/swiftban.conf}"
            (
                # shellcheck disable=SC1090
                source "$conf" || exit 1
                rt_install_cron "$SWIFTBAN_BIN" "$conf" "${STATE_DIR:-$SWIFTBAN_HOME/state}"
            )
            ;;
        *) info "跳过 cron 安装" ;;
    esac
}

#---------------- 验证 ----------------
verify() {
    info "验证安装..."
    if "${SWIFTBAN_BIN}" version >/dev/null 2>&1; then
        info "版本: $("${SWIFTBAN_BIN}" version)"
    else
        error "安装验证失败"
        exit 1
    fi
    if ! "${SWIFTBAN_BIN}" configtest; then
        error "安装验证失败：模块加载或配置检查未通过，不安装定时任务"
        return 1
    fi
}

#---------------- 主流程 ----------------
main() {
    echo "=============================="
    echo "  SwiftBan 安装程序"
    echo "=============================="
    check_root
    check_deps
    install_files || return 1
    configure_runtime_settings || return 1
    verify || return 1
    install_cron
    echo
    info "安装完成！"
    echo
    echo "  手动执行:  swiftban run"
    echo "  查看状态:  swiftban status"
    echo "  来源地:    sudo swiftban geo refresh（仅手动刷新，查看 geo --help）"
    echo "  观察列表:  swiftban watch（仅告警，使用 swiftban watch --help 查看说明）"
    echo "  配置编辑:  ${SWIFTBAN_HOME}/swiftban.conf"
    echo "  文档:      ${SCRIPT_DIR}/docs/"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
