#!/bin/bash
#==============================================================
# SwiftBan 单元测试
# 运行: bash tests/test_detector.sh
#==============================================================
set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"
LIBS="${PROJECT_DIR}/lib"

PASS=0; FAIL=0
ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

# 加载模块（mock 全局变量）
export WHITELIST="127.0.0.1,::1,192.168.224.1"
export WHITELIST_FILE="/tmp/swiftban_test_wl_$$"
export FIREWALL_CHAIN="DOCKER-USER"
export BAN_TTL=259200
export NOW=0
touch "${WHITELIST_FILE}"
# shellcheck disable=SC1090,SC1091  # 测试按相对路径动态 source
source "${LIBS}/logger.sh"
# shellcheck disable=SC1090,SC1091
source "${LIBS}/whitelist.sh"

echo "=== 白名单测试 ==="

# 精确 IP
if wl_is_whitelisted "127.0.0.1"; then ok "精确IP 127.0.0.1"; else fail "精确IP 127.0.0.1"; fi
if wl_is_whitelisted "8.8.8.8"; then fail "非白名单IP误判"; else ok "非白名单IP 8.8.8.8"; fi

# CIDR
if wl_ip_in_cidr "8.8.8.8" "8.8.8.0/24"; then ok "CIDR 8.8.8.8 in 8.8.8.0/24"; else fail "CIDR 8.8.8.8 in 8.8.8.0/24"; fi
if wl_ip_in_cidr "8.8.9.8" "8.8.8.0/24"; then fail "CIDR 越界误判"; else ok "CIDR 8.8.9.8 not in 8.8.8.0/24"; fi
if wl_ip_in_cidr "10.1.2.3" "10.0.0.0/8"; then ok "CIDR 10.1.2.3 in 10.0.0.0/8"; else fail "CIDR 10.1.2.3 in 10.0.0.0/8"; fi
if wl_ip_in_cidr "172.18.5.5" "172.18.0.0/16"; then ok "CIDR 172.18.5.5 in 172.18.0.0/16"; else fail "CIDR 172.18.5.5"; fi
if wl_ip_in_cidr "1.2.3.4" "192.168.0.0/16"; then fail "CIDR 未命中误判"; else ok "CIDR 1.2.3.4 not in 192.168.0.0/16"; fi

# 白名单文件
{
    echo "8.8.8.8"
    echo "10.0.0.0/8"
    echo "# 注释"
} >> "${WHITELIST_FILE}"
if wl_is_whitelisted "8.8.8.8"; then ok "文件精确IP"; else fail "文件精确IP"; fi
if wl_is_whitelisted "10.5.5.5"; then ok "文件CIDR"; else fail "文件CIDR"; fi
if wl_is_whitelisted "1.1.1.1"; then fail "文件外IP误判"; else ok "文件外IP 1.1.1.1"; fi

rm -f "${WHITELIST_FILE}"

echo ""
echo "=== 时间过滤测试 ==="

# 检查 awk 是否支持 mktime（gawk/mawk 支持，BSD awk 不支持）
if ! awk 'BEGIN{mktime("2026 11 12 00 00 00")}' 2>/dev/null; then
    echo "  ⊘ 跳过: 当前 awk 不支持 mktime（需 gawk/mawk；生产环境已验证支持）"
    echo ""
    echo "=== 结果: ${PASS} 通过, ${FAIL} 失败 ==="
    exit 0
fi

# shellcheck disable=SC1090,SC1091  # 测试按相对路径动态 source
source "${LIBS}/detector.sh"

export WINDOW=7200
NOW_EPOCH=$(date -u +%s)
TMP=$(mktemp)

# 生成 UTC 时间字符串（兼容 GNU/BSD date）
utc_str() {
    if date -u -d "@$1" '+%d/%b/%Y:%H:%M:%S' >/dev/null 2>&1; then
        date -u -d "@$1" '+%d/%b/%Y:%H:%M:%S'
    else
        date -u -r "$1" '+%d/%b/%Y:%H:%M:%S'
    fi
}

cat > "$TMP" << EOF
[$(utc_str $((NOW_EPOCH-60))) +0000] 444 - GET https a.com "/" [Client 1.2.3.4] [Length 0] [Gzip -] "-" "-"
[$(utc_str $((NOW_EPOCH-7200-100))) +0000] 444 - GET https a.com "/" [Client 5.6.7.8] [Length 0] [Gzip -] "-" "-"
EOF
det_time_filter "$TMP" "${TMP}.out"
C=$(wc -l < "${TMP}.out" | tr -d ' ')
if [[ "$C" == "1" ]]; then ok "时间过滤保留60s内，排除7300s前"; else fail "时间过滤行数错误: $C"; fi
rm -f "$TMP" "${TMP}.out"

echo ""
echo "=== 结果: ${PASS} 通过, ${FAIL} 失败 ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
