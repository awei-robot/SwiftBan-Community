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

check_deps() {
    local deps=(iptables awk grep find stat sort)
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
    info "依赖检查通过（awk 支持 mktime 和区间正则）"
}

#---------------- 安装 ----------------
install_files() {
    info "安装到 ${SWIFTBAN_HOME} ..."

    mkdir -p "${SWIFTBAN_HOME}"/{bin,lib,config,state} "${SWIFTBAN_LIB}"

    # 主程序
    install -m 755 "${SCRIPT_DIR}/bin/swiftban.sh" "${SWIFTBAN_BIN}"
    # 模块
    for lib in logger firewall whitelist detector; do
        install -m 644 "${SCRIPT_DIR}/lib/${lib}.sh" "${SWIFTBAN_LIB}/${lib}.sh"
    done
    # 配置
    if [[ ! -f "${SWIFTBAN_HOME}/swiftban.conf" ]]; then
        install -m 644 "${SCRIPT_DIR}/config/swiftban.conf" "${SWIFTBAN_HOME}/swiftban.conf"
    else
        warn "配置已存在，保留: ${SWIFTBAN_HOME}/swiftban.conf"
    fi
    # 白名单模板
    if [[ ! -f "${SWIFTBAN_HOME}/state/whitelist.txt" ]]; then
        cat > "${SWIFTBAN_HOME}/state/whitelist.txt" << 'EOF'
# SwiftBan 白名单 - 每行 IP 或 CIDR（# 注释）
EOF
    fi

    # 修正 lib 目录引用（安装后路径）
    sed -i.bak "s|SWIFTBAN_LIB_DIR=.*|SWIFTBAN_LIB_DIR=\"${SWIFTBAN_LIB}\"|" "${SWIFTBAN_BIN}" 2>/dev/null || true

    info "文件安装完成"
}

install_cron() {
    read -r -p "是否安装 cron 定时任务（每分钟执行）? [Y/n] " ans
    case "${ans:-Y}" in
        [Yy]*)
            (crontab -l 2>/dev/null | grep -v "swiftban run"; echo "* * * * * ${SWIFTBAN_BIN} run >> ${SWIFTBAN_HOME}/state/cron.log 2>&1") | crontab -
            info "cron 已安装"
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
    "${SWIFTBAN_BIN}" configtest || true
}

#---------------- 主流程 ----------------
main() {
    echo "=============================="
    echo "  SwiftBan 安装程序"
    echo "=============================="
    check_root
    check_deps
    install_files
    install_cron
    verify
    echo
    info "安装完成！"
    echo
    echo "  手动执行:  swiftban run"
    echo "  查看状态:  swiftban status"
    echo "  配置编辑:  ${SWIFTBAN_HOME}/swiftban.conf"
    echo "  文档:      ${SCRIPT_DIR}/docs/"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
