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
echo "=== 日志格式、统计和决策回归测试 ==="
# shellcheck disable=SC1090,SC1091
source "$PROJECT_DIR/config/swiftban.conf"
export LOG_FORMAT WINDOW EVIL_PAYLOAD LIMIT_HIGHFREQ
# shellcheck disable=SC1090,SC1091
source "$LIBS/detector.sh"
if ! det_awk 'BEGIN {if(mktime("2026 11 16 12 00 00")<0 || "123" !~ /^[0-9]{3}$/) exit 1}' >/dev/null 2>&1; then
    echo "错误: 完整测试需要支持 mktime 和区间正则的 awk（macOS 请安装 gawk）"
    exit 1
fi
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
WD="$T/work"
mkdir -p "$WD"
NOW_EPOCH=$(TZ=UTC det_awk 'BEGIN {print mktime("2026 11 16 12 00 00")}')
WINDOW=7200
WHITELIST="127.0.0.1,::1"
WHITELIST_FILE="$T/whitelist"
touch "$WHITELIST_FILE"
eq() {
    if [[ "$1" == "$2" ]]; then ok "$3"; else fail "$3（实际=$1，期望=$2）"; fi
}
rows() { wc -l < "$1" | tr -d ' '; }
total() { det_awk '{n+=$1} END {print n+0}' "$WD/ip_$1.txt"; }
reset_logs() {
    : > "$WD/input.tsv"
    : > "$WD/stats.tsv"
    LOG_FORMAT=auto
}
record() {
    printf '%s\t%s\t%s\n' "${2:-/logs/site_access.log}" "${3:-/logs/site_access.log}" "$1" >> "$WD/input.tsv"
}
npm() {
    printf '[%s] %s - GET https %s "%s" [Client %s] [Length 0] [Gzip -] "%s" "%s"' \
        "${5:-16/Nov/2026:11:59:00 +0000}" "${3:-200}" "${6:-example.com}" "$1" \
        "${4:-198.51.100.1}" "${2-Mozilla/5.0}" "${7:--}"
}
proxy() {
    printf '[16/Nov/2026:11:59:00 +0000] %s %s %s - GET https example.com "%s" [Client 198.51.100.1] [Length 0] [Gzip -] [Sent-to backend] "Mozilla/5.0" "-"' "$1" "$2" "$3" "${4:-/}"
}
combined() {
    printf '%s - - [16/Nov/2026:11:59:00 +0000] "GET %s HTTP/1.1" %s 0 "-" "%s"' \
        "${4:-198.51.100.1}" "$1" "${3:-200}" "${2-Mozilla/5.0}"
}
process() {
    if ! det_parse "$WD/input.tsv" "$WD/recent.log" "$WD/stats.tsv" || ! det_detect_all "$WD"; then
        fail "解析或统计程序执行失败"
        exit 1
    fi
}
fw_is_banned() { return 1; }
fw_count() { echo "0:0"; }
decisions() { det_decide "$WD" dry > "$T/decisions"; }

reset_logs
record "$(npm /a Mozilla/5.0 404)"
record "$(proxy - 404 200 /b)"
record "$(proxy HIT - 404 /c)"
record "$(proxy - '502, 200' 200 /d)"
record "$(proxy - '502 : 404' 401 /login)"
record "$(proxy - - 444 /e)"
record "$(combined /f Mozilla/5.0 404)"
process
eq "$(rows "$WD/recent.log")" 7 "三种格式、缓存、无上游和多次上游状态均可解析"
eq "$(total scan)" 3 "扫描使用最终状态，忽略上游404和缓存字段"
eq "$(total auth)" 1 "重试后的最终401参与登录检测"
eq "$(total 444)" 1 "无上游444检测"
eq "$(det_awk -F '\t' '$6=="/d" {print $3}' "$WD/recent.log")" 200 "上游重试不会推移URI"
eq "$(det_awk -F '\t' '$6=="/f" {print $5}' "$WD/recent.log")" "@file:/logs/site_access.log" "combined使用文件家族隔离站点"
for format in npm_standard npm_proxy combined; do
    LOG_FORMAT="$format"
    process
    case "$format" in npm_standard|combined) expected=1 ;; npm_proxy) expected=5 ;; esac
    eq "$(rows "$WD/recent.log")" "$expected" "显式格式 $format 不接受其他格式"
done
LOG_FORMAT=wrong
if det_check_config >/dev/null; then fail "拒绝未知格式配置"; else ok "拒绝未知格式配置"; fi
LOG_FORMAT=auto
WINDOW=0
if det_check_config >/dev/null; then fail "拒绝无效窗口"; else ok "拒绝无效窗口"; fi
WINDOW=7200

reset_logs
for ip in 198.51.100.1 2001:db8::1 ::1 ::ffff:192.0.2.1 2001:db8:0:0:0:0:0:1; do
    record "$(npm / Mozilla/5.0 200 "$ip")"
done
for ip in 999.1.2.3 01.2.3.4 1.2.3 1.2.3.4:80 1.2.3.4/24 example.com 2001:::1 1:2:3:4:5:6:7::8 'fe80::1%eth0'; do
    record "$(npm / Mozilla/5.0 200 "$ip")"
done
record 'unknown'
record '{"ip":"198.51.100.1"}'
record "$(npm /)"$'\tbad'
process
eq "$(rows "$WD/recent.log")" 5 "合法IP通过，非法IP、未知格式和控制字符被拒绝"
eq "$(det_awk -F '\t' '{n+=$3} END {print n}' "$WD/stats.tsv")" 12 "坏记录有明确计数"

reset_logs
for i in $(seq 1 5); do
    record "$(npm '/?x=[Client%20203.0.113.8]' 'sqlmap [Client 203.0.113.9]' 200 198.51.100.1 '' example.com 'http://x/[Client 203.0.113.7]')"
done
process
decisions
if grep -q '203.0.113.' "$T/decisions"; then fail "伪造IP不得进入决策"; else ok "URI、UA和Referer中的伪造IP不进入决策"; fi
eq "$(total ua)" 5 "真实客户端的可疑UA照常检测"
eq "$(total freq)" 5 "伪造标记不增加请求总量"
WHITELIST="198.51.100.1"
decisions
eq "$(rows "$T/decisions")" 0 "演练候选也排除白名单"
WHITELIST="127.0.0.1,::1"

reset_logs
record "$(npm '/escaped%20uri' 'Mozilla\x22 [Client 203.0.113.9]')"
record "$(npm /ipv6-host Mozilla/5.0 200 2001:db8::1 '' '[2001:db8::2]')"
record "$(npm /)"' "unterminated'
process
eq "$(rows "$WD/recent.log")" 2 "保留转义UA、支持IPv6域名，拒绝未闭合引号"
eq "$(det_awk -F '\t' '$6=="/escaped%20uri" {print $7}' "$WD/recent.log")" 'Mozilla\x22 [Client 203.0.113.9]' "日志转义不解码"
eq "$(det_awk -F '\t' '$6=="/ipv6-host" {print $5}' "$WD/recent.log")" '[2001:db8::2]' "IPv6域名括号保留"
if det_parse "$WD/input.tsv" "$WD/recent.log" "$T/missing/stats" 2>/dev/null; then fail "统计摘要写入失败返回非零"; else ok "统计摘要写入失败返回非零"; fi

reset_logs
for stamp in \
    '16/Nov/2026:11:59:00 +0000' '16/Nov/2026:19:59:00 +0800' \
    '16/Nov/2026:06:59:00 -0500' '16/Nov/2026:10:00:00 +0000' \
    '16/Nov/2026:12:00:00 +0000' '16/Nov/2026:09:59:59 +0000' \
    '16/Nov/2026:12:00:01 +0000' '17/Nov/2026:12:00:00 +0000' \
    '16/Nov/2026:13:00:00 +0800' '31/Nov/2026:11:59:00 +0000' \
    '16/Bad/2026:11:59:00 +0000' '16/Nov/2026:24:00:00 +0000' \
    '16/Nov/2026:11:59:00 +2460'; do
    record "$(npm / Mozilla/5.0 200 198.51.100.1 "$stamp")"
done
process
eq "$(rows "$WD/recent.log")" 5 "时区换算、窗口两端和未来时间过滤"
eq "$(det_awk -F '\t' 'NR<=3 {a[$1]=1} END {for(i in a)n++; print n}' "$WD/recent.log")" 1 "正负时区表示同一时刻"
eq "$(det_awk -F '\t' '{print $3,$4,$5}' "$WD/stats.tsv")" "4 2 2" "非法日期、过期和未来记录分别计数"
old_now="$NOW_EPOCH"
NOW_EPOCH=$(TZ=UTC det_awk 'BEGIN {print mktime("2026 11 17 00 00 00")}')
reset_logs
record "$(npm / Mozilla/5.0 200 198.51.100.1 '17/Nov/2026:07:59:00 +0800')"
record "$(npm / Mozilla/5.0 200 198.51.100.1 '16/Nov/2026:23:59:00 +0000')"
process
eq "$(rows "$WD/ip_apirate.txt")" 1 "跨日期时区换算后归入同一个UTC分钟"
NOW_EPOCH="$old_now"

reset_logs
for i in $(seq 1 30); do record "$(npm "/page/$i")"; done
process
decisions
eq "$(rows "$T/decisions")" 0 "standard访问30个不同接口不误封"
reset_logs
for i in $(seq 1 30); do record "$(npm /same)"; done
process
decisions
if grep -q 'WATCH 单IP单接口速率 198.51.100.1 | 30次/分钟' "$T/decisions" &&
    ! grep -q '\[DRY-RUN\] 将封禁 198.51.100.1.*单接口速率' "$T/decisions"; then
    ok "相同接口达到速率阈值只告警且不生成封禁候选"
else fail "相同接口达到速率阈值只告警且不生成封禁候选"; fi
# 总量阈值达到时，正式和演练均只观察。
old_api="$LIMIT_API"
LIMIT_API=30
: > "$T/fw.calls"
det_decide "$WD" > "$T/api-watch"
if grep -q 'WATCH 单接口高频 198.51.100.1 | 30次/' "$T/api-watch"; then
    ok "单接口总量达到阈值只记录WATCH"
else fail "单接口总量达到阈值只记录WATCH"; fi
eq "$(rows "$T/fw.calls")" 0 "单接口总量超限不执行封禁"
decisions
if grep -q '\[DRY-RUN\] 将封禁' "$T/decisions"; then
    fail "单接口总量超限不生成演练封禁候选"
else ok "单接口总量超限不生成演练封禁候选"; fi
LIMIT_API="$old_api"
reset_logs
for host in a.example.com b.example.com; do
    for i in $(seq 1 29); do record "$(npm /same Mozilla/5.0 200 198.51.100.1 '' "$host")"; done
done
process
decisions
eq "$(rows "$T/decisions")" 0 "不同域名的相同接口不合并"
reset_logs
for i in $(seq 1 30); do record "$(npm "/same?q=$i")"; done
process
decisions
eq "$(rows "$T/decisions")" 0 "查询参数保持独立分组"
reset_logs
for family in /logs/a_access.log /logs/b_access.log; do
    for i in $(seq 1 29); do record "$(combined /same)" "$family" "$family"; done
done
process
decisions
eq "$(rows "$T/decisions")" 0 "combined不同文件家族不合并"

reset_logs
record "$(npm /docs/sqlmap)"
record "$(npm '/missing?x=/TDT/' 'Mozilla /TDT/' 404)"
record "$(npm '/.env?x=git-upload-pack' 'Mozilla git-upload-pack' 200 198.51.100.1 '' example.com 'git-upload-pack')"
record "$(npm '/?x=login' Mozilla/5.0 401)"
record "$(npm /login Mozilla/5.0 403)"
record "$(npm /TDT/missing Mozilla/5.0 404)"
record "$(npm /info/refs sqlmap 404)"
record "$(npm / '-')"
record "$(npm / '') extra"
process
eq "$(total ua)" 1 "可疑UA只匹配UA字段"
eq "$(total scan)" 2 "查询参数和UA中的SAFE_PATH不绕过扫描"
eq "$(total evilpath)" 1 "查询参数、UA和Referer中的Git词不绕过恶意路径"
eq "$(total auth)" 1 "登录爆破只匹配路径"
eq "$(total emptyua)" 2 "空字符串、短横线UA及追加字段均可识别"

reset_logs
record "$(npm '/?cmd=id')"
# shellcheck disable=SC2016 # 保留恶意载荷原文，不做 shell 展开。
record "$(npm / 'hello ${jndi:ldap://x}')"
record "$(npm / Mozilla/5.0 200 198.51.100.1 '' example.com 'http://x/?cmd=id')"
# shellcheck disable=SC2016
record "$(npm /info/refs 'hello ${jndi:ldap://x}')"
# shellcheck disable=SC2016
record "$(npm / 'hello ${jndi:ldap://x}' 200 198.51.100.1 '' git.43tc.cn)"
# shellcheck disable=SC2016
record "$(npm / 'hello ${jndi:ldap://x}' 200 198.51.100.1 '' git.43tc.cn.evil)"
process
eq "$(total payload)" 4 "载荷覆盖URI、UA、Referer，Git域名必须精确匹配"
reset_logs
EVIL_PAYLOAD='union.*select'
record "$(npm '/?union' select)"
process
eq "$(total payload)" 0 "载荷匹配不跨字段拼接"
# shellcheck disable=SC1090,SC1091
source "$PROJECT_DIR/config/swiftban.conf"
NOW_EPOCH="$old_now"

reset_logs
LOG_DIR="$T/log files"
mkdir -p "$LOG_DIR"
line="$(npm /)"
printf '%s\n%s\n' "$line" "$line" > "$LOG_DIR/site_access.log"
printf '%s\n%s\n%s\n' "$line" "$line" "$line" > "$LOG_DIR/site_access.log.1"
printf '%s\n' "$(npm /older)" > "$LOG_DIR/site_access.log-20261116"
printf '%s\n' "$(npm /ignored)" > "$LOG_DIR/site_access.log.gz"
printf '%s\n' "$(npm /ignored)" > "$LOG_DIR/site_access.log.bak"
ln "$LOG_DIR/site_access.log" "$LOG_DIR/site_access.log.9"
mkdir "$LOG_DIR/sub"
printf '%s\n' "$(npm /ignored)" > "$LOG_DIR/sub/other_access.log"
# 修改时间预筛选独立于日志条目的时间窗口。
printf '%s\n' "$(npm /cold)" > "$LOG_DIR/cold_access.log"
printf '%s\n' "$(npm /warm)" > "$LOG_DIR/warm_access.log"
cold_stamp=$(TZ=UTC det_awk -v epoch="$(($(date -u +%s)-240))" 'BEGIN {print strftime("%Y%m%d%H%M.%S",epoch)}')
warm_stamp=$(TZ=UTC det_awk -v epoch="$(($(date -u +%s)-60))" 'BEGIN {print strftime("%Y%m%d%H%M.%S",epoch)}')
TZ=UTC touch -t "$cold_stamp" "$LOG_DIR/cold_access.log" "$LOG_DIR/site_access.log-20261116"
TZ=UTC touch -t "$warm_stamp" "$LOG_DIR/warm_access.log"
det_collect "$WD" || { fail "收集日志失败"; exit 1; }
process
eq "$(rows "$WD/input.tsv")" 6 "收集空格路径及轮转，忽略压缩、备份、子目录及同inode"
eq "$(rows "$WD/recent.log")" 4 "轮转重叠采用最大重数，保留单文件重复请求"
if grep -Fq "$LOG_DIR/cold_access.log" "$WD/input.tsv" || grep -Fq "$LOG_DIR/site_access.log-20261116" "$WD/input.tsv"; then
    fail "超过3分钟未修改的活动及轮转文件不读取"
else
    ok "超过3分钟未修改的活动及轮转文件不读取"
fi
if grep -Fq "$LOG_DIR/warm_access.log" "$WD/input.tsv"; then ok "1分钟前修改的日志正常读取"; else fail "1分钟前修改的日志正常读取"; fi
WINDOW=10800
printf '%s\n' "$(npm /old Mozilla/5.0 200 198.51.100.1 '16/Nov/2026:09:30:00 +0000')" > "$LOG_DIR/site_access.log.2"
det_collect "$WD" || exit 1
process
eq "$(rows "$WD/recent.log")" 5 "最近修改文件内的旧条目按更大的WINDOW统计"
WINDOW=7200
process
eq "$(rows "$WD/recent.log")" 4 "入选文件仍排除WINDOW之外的旧日志条目"
if (LOG_DIR="$T/missing"; det_collect "$WD" 2>/dev/null); then fail "目录读取失败返回非零"; else ok "目录读取失败返回非零"; fi
# shellcheck disable=SC2329 # 模块间接调用的 mock。
if (det_awk() { return 1; }; det_collect "$WD"); then fail "文件读取程序失败返回非零"; else ok "文件读取程序失败返回非零"; fi

STATE_DIR="$T/state"
BANLOG="$STATE_DIR/ban.log"
WHITELIST="127.0.0.1,::1"
WHITELIST_FILE="$T/whitelist"
mkdir -p "$STATE_DIR"
touch "$T/fw.calls" "$BANLOG" "$STATE_DIR/banlist.txt"
fw_ban() { printf 'BAN %s\n' "$1" >> "$T/fw.calls"; }
fw_unban() { printf 'UNBAN %s\n' "$1" >> "$T/fw.calls"; }
NOW=$(date -u +%s)
det_ban 127.0.0.1 "测试"
eq "$(rows "$T/fw.calls")" 0 "白名单仍然阻止真实封禁"
# shellcheck disable=SC2329
if (fw_ban() { return 1; }; det_ban 198.51.100.3 "测试"); then fail "防火墙失败返回非零"; else ok "防火墙失败返回非零"; fi
eq "$(rows "$STATE_DIR/banlist.txt")" 0 "防火墙失败不写状态"
printf '198.51.100.2|%s|3600|测试恢复\n198.51.100.3|%s|1|测试过期\n' "$NOW" "$((NOW-100))" > "$STATE_DIR/banlist.txt"
# shellcheck disable=SC2329
if (det_collect() { return 1; }; det_run 0 > "$T/run.output"); then fail "收集失败中止运行"; else ok "收集失败中止运行"; fi
eq "$(cat "$T/fw.calls")" $'BAN 198.51.100.2\nUNBAN 198.51.100.3' "收集失败仍先恢复和解封，且不新增封禁"
eq "$(rows "$STATE_DIR/banlist.txt")" 1 "过期状态正常移除"
: > "$T/fw.calls"
before=$(cksum "$STATE_DIR/banlist.txt")
# shellcheck disable=SC2329
if (det_parse() { return 1; }; det_run 1 > "$T/run.output"); then fail "解析程序失败中止运行"; else ok "解析程序失败中止运行"; fi
eq "$(rows "$T/fw.calls")" 0 "解析程序失败不执行新增封禁"
det_run 1 > "$T/run.output" || { fail "演练运行失败"; exit 1; }
eq "$(cksum "$STATE_DIR/banlist.txt")" "$before" "演练不修改封禁状态"
eq "$(rows "$T/fw.calls")" 0 "演练不修改防火墙"
reset_logs
record 'garbage'
process
eq "$(total freq)" 0 "全坏记录不生成统计候选"
reset_logs
for i in $(seq 1 3); do record "$(npm "/watch/$i")"; done
process
LIMIT_HIGHFREQ=3
det_decide "$WD" > "$T/watch"
if grep -q 'WATCH 高频' "$T/watch"; then ok "高频观察仍仅记录WATCH"; else fail "高频观察仍仅记录WATCH"; fi
eq "$(rows "$T/fw.calls")" 0 "WATCH不封禁"

# 使用实际当前时间覆盖完整 run，所有防火墙动作仍然是 mock。
LIMIT_HIGHFREQ=500
LOG_DIR="$T/live"
mkdir "$LOG_DIR"
stamp=$(LC_ALL=C date -u '+%d/%b/%Y:%H:%M:%S +0000')
for i in $(seq 1 5); do
    npm / 'sqlmap [Client 203.0.113.9]' 200 198.51.100.1 "$stamp"
    echo
done > "$LOG_DIR/site_access.log"
: > "$STATE_DIR/banlist.txt"
: > "$T/fw.calls"
det_run 0 > "$T/run.output" || { fail "完整运行失败"; exit 1; }
eq "$(cat "$T/fw.calls")" "BAN 198.51.100.1" "完整run只封真实客户端，不封伪造IP"
eq "$(rows "$STATE_DIR/banlist.txt")" 1 "完整run成功后写入一条封禁状态"
: > "$STATE_DIR/banlist.txt"
: > "$T/fw.calls"
printf 'unknown\n' > "$LOG_DIR/site_access.log"
det_run 0 > "$T/run.output" || { fail "全坏日志运行失败"; exit 1; }
eq "$(rows "$T/fw.calls")" 0 "完整run全坏日志不新增封禁"
if grep -q '格式错误=1' "$T/run.output"; then ok "完整run报告格式错误数量"; else fail "完整run报告格式错误数量"; fi
# shellcheck disable=SC2329
if (det_detect_all() { return 1; }; det_run 0 > "$T/run.output"); then fail "统计失败中止运行"; else ok "统计失败中止运行"; fi
eq "$(rows "$T/fw.calls")" 0 "统计程序失败不新增封禁"

# 仅在临时目录执行安装文件步骤，不请求 root，不安装 cron。
# shellcheck disable=SC2329 # 子进程配置检查使用导出的防火墙替身。
if (
    # shellcheck disable=SC1090,SC1091
    source "$PROJECT_DIR/install/install.sh"
    SWIFTBAN_HOME="$T/installed/etc"
    SWIFTBAN_LIB="$T/installed/lib/swiftban"
    SWIFTBAN_BIN="$T/installed/swiftban"
    mkdir -p "$T/installed" || exit 1
    install_files || exit 1
    mkdir -p "$T/live" "$T/state"
    printf '\nLOG_DIR="%s"\nSTATE_DIR="%s"\nWHITELIST_FILE="%s"\n' "$T/live" "$T/state" "$T/whitelist" >> "$SWIFTBAN_HOME/swiftban.conf"
    iptables() { return 0; }
    ip6tables() { return 0; }
    export -f iptables ip6tables
    for module in logger firewall whitelist runtime detector; do
        test -r "$SWIFTBAN_LIB/$module.sh" || exit 1
    done
    SWIFTBAN_CONF="$SWIFTBAN_HOME/swiftban.conf" "$SWIFTBAN_BIN" configtest > "$T/installed/output" || exit 1
    grep -q '日志格式: auto' "$T/installed/output" || exit 1
    printf 'LOG_DIR="%s"\nSTATE_DIR="%s"\nWHITELIST_FILE="%s"\n' "$T/live" "$T/state" "$T/whitelist" > "$T/installed/legacy.conf"
    SWIFTBAN_CONF="$T/installed/legacy.conf" "$SWIFTBAN_BIN" configtest > "$T/installed/output" || exit 1
    grep -q '日志格式: auto' "$T/installed/output" || exit 1
    printf 'LOG_FORMAT=bad\n' >> "$T/installed/legacy.conf"
    if SWIFTBAN_CONF="$T/installed/legacy.conf" "$SWIFTBAN_BIN" configtest > "$T/installed/output"; then exit 1; fi
    grep -q '不支持的 LOG_FORMAT: bad' "$T/installed/output" || exit 1
) > "$T/install.output" 2>&1; then
    ok "临时安装后模块可加载、旧配置默认auto、无效格式返回非零"
else
    cat "$T/install.output"
    fail "临时目录安装及配置兼容性"
fi

# 模拟已安装目录中缺少模块，CLI 不应继续调用缺失的检测函数。
mv "$T/installed/lib/swiftban/logger.sh" "$T/installed/lib/swiftban/logger.sh.saved"
if SWIFTBAN_CONF="$T/installed/etc/swiftban.conf" "$T/installed/swiftban" configtest > "$T/missing-module.output" 2>&1; then
    fail "缺少模块时configtest必须失败"
else
    if grep -q '无法读取模块.*logger.sh' "$T/missing-module.output" && ! grep -q 'det_check_config:' "$T/missing-module.output"; then
        ok "缺少模块时明确报错，不继续调用缺失函数"
    else
        fail "缺少模块时明确报错，不继续调用缺失函数"
    fi
fi
if SWIFTBAN_CONF="$T/installed/etc/swiftban.conf" "$T/installed/swiftban" status > "$T/missing-module.output" 2>&1; then
    fail "缺少模块时status必须失败"
else
    if grep -q '无法读取模块' "$T/missing-module.output" && ! grep -q 'fw_count:' "$T/missing-module.output"; then
        ok "命令分发在模块加载失败后停止"
    else
        fail "命令分发在模块加载失败后停止"
    fi
fi
if (
    # shellcheck disable=SC1090,SC1091
    source "$PROJECT_DIR/install/install.sh"
    SWIFTBAN_BIN="$T/installed/swiftban"
    SWIFTBAN_CONF="$T/installed/etc/swiftban.conf" verify
) > "$T/verify.output" 2>&1; then
    fail "模块缺失不得报告安装验证成功"
else
    if grep -q '安装验证失败' "$T/verify.output"; then ok "安装验证拒绝缺少模块的程序"; else fail "安装验证拒绝缺少模块的程序"; fi
fi
mv "$T/installed/lib/swiftban/logger.sh.saved" "$T/installed/lib/swiftban/logger.sh"
# shellcheck disable=SC2329 # 校验失败时不应进入 cron；通过 mock 验证顺序。
if (
    # shellcheck disable=SC1090,SC1091
    source "$PROJECT_DIR/install/install.sh"
    check_root() { return 0; }
    check_deps() { return 0; }
    install_files() { return 0; }
    configure_runtime_settings() { echo configure >> "$T/install-order"; }
    verify() { echo verify >> "$T/install-order"; return 1; }
    install_cron() { echo cron >> "$T/install-order"; }
    main
) > "$T/install-order.output" 2>&1; then
    fail "安装验证失败必须停止安装流程"
else
    eq "$(cat "$T/install-order")" $'configure\nverify' "安装配置确认后验证失败不创建cron，也不报告完成"
fi
# shellcheck disable=SC2329 # 强制 sed 失败，检查路径改写错误能否向外传递。
if (
    # shellcheck disable=SC1090,SC1091
    source "$PROJECT_DIR/install/install.sh"
    SWIFTBAN_HOME="$T/relocate-failure/etc"
    SWIFTBAN_LIB="$T/relocate-failure/lib"
    SWIFTBAN_BIN="$T/relocate-failure/swiftban"
    mkdir -p "$T/relocate-failure"
    sed() { return 1; }
    install_files
) > "$T/relocate.output" 2>&1; then
    fail "模块路径改写失败必须停止安装"
else
    if grep -q '写入模块加载目录失败' "$T/relocate.output"; then ok "模块路径改写失败必须停止安装"; else fail "模块路径改写失败必须停止安装"; fi
fi

# 必需/可选依赖检查不访问真实防火墙。
# shellcheck disable=SC2329 # 被安装器和防火墙模块间接调用的 mock。
if (
    # shellcheck disable=SC1090,SC1091
    source "$PROJECT_DIR/install/install.sh"
    check_platform() { return 0; }
    flock() { return 0; }
    setsid() { return 0; }
    command() {
        if [[ "$1" == -v && "$2" == iptables ]]; then return 1; fi
        builtin command "$@"
    }
    check_deps
) > "$T/deps.output" 2>&1; then
    fail "缺少iptables必须阻止安装"
else
    if grep -q '缺少依赖:.*iptables' "$T/deps.output"; then ok "缺少iptables必须阻止安装"; else fail "缺少iptables必须阻止安装"; fi
fi
# shellcheck disable=SC2329
if (
    # shellcheck disable=SC1090,SC1091
    source "$PROJECT_DIR/install/install.sh"
    # shellcheck disable=SC2329 # command -v 检测的命令替身。
    iptables() { return 0; }
    check_platform() { return 0; }
    flock() { return 0; }
    setsid() { return 0; }
    command() {
        if [[ "$1" == -v && "$2" == ip6tables ]]; then return 1; fi
        builtin command "$@"
    }
    check_deps
) > "$T/deps.output" 2>&1; then
    if grep -q '未安装 ip6tables' "$T/deps.output"; then ok "缺少ip6tables仅提示，不阻止安装"; else fail "缺少ip6tables应提示"; fi
else
    cat "$T/deps.output"
    fail "缺少ip6tables不应阻止安装"
fi

# shellcheck disable=SC2329
if (
    # shellcheck disable=SC1090,SC1091
    source "$LIBS/firewall.sh"
    STATE_DIR="$T/ipv4-only-state"
    BANLOG="$STATE_DIR/ban.log"
    mkdir -p "$STATE_DIR"
    : > "$STATE_DIR/banlist.txt"
    : > "$T/ipv4.calls"
    : > "$T/ipv6.calls"
    iptables() {
        printf '%s\n' "$*" >> "$T/ipv4.calls"
        if [[ "$1" == -S ]]; then printf '%s\n' '-A DOCKER-USER -s 198.51.100.1 -j DROP'; fi
        return 0
    }
    # shellcheck disable=SC2329 # 缺失工具的防误调用哨兵。
    ip6tables() { echo called >> "$T/ipv6.calls"; return 127; }
    command() {
        if [[ "$1" == -v && "$2" == ip6tables ]]; then return 1; fi
        builtin command "$@"
    }
    fw_ban 198.51.100.1 || exit 1
    fw_is_banned 198.51.100.1 || exit 1
    fw_unban 198.51.100.1 || exit 1
    if det_ban 2001:db8::123 "测试"; then exit 1; fi
    test ! -s "$STATE_DIR/banlist.txt" || exit 1
    if fw_is_banned 2001:db8::123; then exit 1; fi
    fw_unban 2001:db8::123 || exit 1
    [[ "$(fw_count)" == 1:0 ]] || exit 1
    test ! -s "$T/ipv6.calls" || exit 1
) > "$T/firewall.output" 2>&1; then
    ok "无ip6tables时IPv4操作正常、IPv6不误调用且封禁失败不写状态"
else
    cat "$T/firewall.output"
    fail "IPv4单栈防火墙兼容性"
fi
# shellcheck disable=SC2329
if (
    # shellcheck disable=SC1090,SC1091
    source "$LIBS/firewall.sh"
    iptables() { if [[ "$1" == -S ]]; then printf '%s\n' '-A DOCKER-USER -s 198.51.100.1 -j DROP'; fi; return 0; }
    ip6tables() {
        if [[ "$1" == -S ]]; then printf '%s\n' '-A DOCKER-USER -s 2001:db8::1 -j DROP'; fi
        return 0
    }
    fw_ban 2001:db8::1 || exit 1
    fw_is_banned 2001:db8::1 || exit 1
    fw_unban 2001:db8::1 || exit 1
    [[ "$(fw_count)" == 1:1 ]] || exit 1
) > "$T/firewall.output" 2>&1; then
    ok "有ip6tables时IPv6封禁、解封和统计保持正常"
else
    cat "$T/firewall.output"
    fail "IPv6防火墙回归"
fi

echo ""
echo "=== 高优先级故障回归 ==="
(
    WHITELIST=""
    WHITELIST_FILE="$T/invalid-cidr"
    : > "$WHITELIST_FILE"
    for cidr in 10.0.0.0/33 10.0.0.0/-1 10.0.0.0/abc 10.0.0.0/08 10.0.0.0/24/1 999.0.0.0/8 010.0.0.0/8 '10.0.0.0/x+1' 2001:db8::/32; do
        printf '%s\n' "$cidr" > "$WHITELIST_FILE"
        if wl_is_whitelisted 198.51.100.8; then exit 1; fi
        : > "$WHITELIST_FILE"
        if wl_add "$cidr"; then exit 1; fi
        [[ ! -s "$WHITELIST_FILE" ]] || exit 1
    done
) > "$T/cidr.output" 2>&1
eq "$?" 0 "非法CIDR既不能添加，也不能使公网IP进入白名单"
if wl_ip_in_cidr 198.51.100.8 0.0.0.0/0 &&
    wl_ip_in_cidr 198.51.100.8 198.51.100.8/32 &&
    ! wl_ip_in_cidr 198.51.100.9 198.51.100.8/32 &&
    ! wl_ip_in_cidr 2001:db8::1 10.0.0.0/8; then
    ok "CIDR的/0、/32边界正确，IPv6不进入IPv4算术"
else fail "合法CIDR边界"; fi

# 独立 Bash 保留安装器真实的 errexit/pipefail，绝不调用系统 crontab。
cat > "$T/cron-test.sh" <<'EOF'
#!/bin/bash
source "$PROJECT_DIR/install/install.sh"
SWIFTBAN_HOME="$CASE_DIR"
export SWIFTBAN_CONF="$CASE_DIR/swiftban.conf"
mkdir -p "$CASE_DIR/state"
printf 'STATE_DIR="%s/state"\n' "$CASE_DIR" > "$SWIFTBAN_CONF"
crontab() {
    if [[ "$1" == -l ]]; then
        case "$CRON_CASE" in
            none) printf 'no crontab for root\n' >&2; return 1 ;;
            read-error) printf 'permission denied\n' >&2; return 1 ;;
            *) cat "$CASE_DIR/current" ;;
        esac
    else
        if [[ "$CRON_CASE" == write-error ]]; then return 2; fi
        cat "$1" > "$CASE_DIR/installed"
    fi
}
install_cron <<< Y
EOF
for cron_case in none empty only mixed read-error write-error; do
    case_dir="$T/cron-$cron_case"
    mkdir "$case_dir"
    : > "$case_dir/current"
    case "$cron_case" in
        only) printf '* * * * * /usr/local/bin/swiftban run\n' > "$case_dir/current" ;;
        mixed)
            printf '# swiftban run comment\n0 * * * * /usr/local/bin/backup\n* * * * * /usr/local/bin/swiftban run\n' > "$case_dir/current" ;;
    esac
    if PROJECT_DIR="$PROJECT_DIR" CRON_CASE="$cron_case" CASE_DIR="$case_dir" bash "$T/cron-test.sh" > "$case_dir/output" 2>&1; then
        if [[ "$cron_case" == *-error ]]; then
            fail "cron错误必须返回失败: $cron_case"
        elif [[ "$(grep -c '^\* \* \* \* \* SWIFTBAN_CONF=' "$case_dir/installed")" != 1 ]]; then
            fail "cron必须完整安装且不重复: $cron_case"
        elif [[ "$cron_case" == mixed ]] &&
            ! diff -u <(head -n 2 "$case_dir/current") <(head -n 2 "$case_dir/installed"); then
            fail "cron保留其他任务和注释"
        else ok "cron安全安装: $cron_case"; fi
    else
        if [[ "$cron_case" == *-error && ! -e "$case_dir/installed" ]] &&
            ! grep -q 'cron 已安装' "$case_dir/output"; then
            ok "cron失败不写任务、不报告成功: $cron_case"
        else cat "$case_dir/output"; fail "cron安全安装: $cron_case"; fi
    fi
done

# shellcheck disable=SC2329 # 从决策链间接调用的防火墙替身。
if (
    # shellcheck disable=SC1090,SC1091
    source "$PROJECT_DIR/config/swiftban.conf"
    # shellcheck disable=SC1090,SC1091
    source "$LIBS/firewall.sh"
    STATE_DIR="$T/mixed-family-state"
    mkdir "$STATE_DIR"
    BANLOG="$STATE_DIR/ban.log"
    wd="$T/mixed-family-work"
    mkdir "$wd"
    for category in 444 scan evilpath payload ua auth api apirate emptyua freq; do
        : > "$wd/ip_$category.txt"
    done
    printf '10 2001:db8::1\n10 198.51.100.10\n' > "$wd/ip_444.txt"
    printf '100 198.51.100.11\n' > "$wd/ip_scan.txt"
    wl_is_whitelisted() { return 1; }
    fw_is_banned() { return 1; }
    iptables() { [[ "$1" == -I ]]; }
    ip6tables() { printf 'unexpected\n' >> "$STATE_DIR/ipv6.calls"; return 2; }
    command() {
        if [[ "$1" == -v && "$2" == ip6tables ]]; then return 1; fi
        builtin command "$@"
    }
    NOW=100
    det_decide "$wd" || exit 1
    [[ "$(rows "$STATE_DIR/banlist.txt")" == 2 ]] || exit 1
    grep -q '^198.51.100.10|' "$STATE_DIR/banlist.txt" || exit 1
    grep -q '^198.51.100.11|' "$STATE_DIR/banlist.txt" || exit 1
    [[ ! -e "$STATE_DIR/ipv6.calls" ]] || exit 1
    # 工具存在但执行失败时，仍中断，而非静默吞掉真实故障。
    ip6tables() { if [[ "$1" == -L ]]; then return 0; else echo unexpected >> "$STATE_DIR/ipv6.calls"; return 2; fi; }
    command() { builtin command "$@"; }
    if det_decide "$wd"; then exit 1; fi
    [[ -s "$STATE_DIR/ipv6.calls" ]] || exit 1
    [[ "$(rows "$STATE_DIR/banlist.txt")" == 2 ]] || exit 1
    # ip6tables 命令存在但配置链不存在时，视作可选 IPv6 不可用并继续 IPv4。
    : > "$STATE_DIR/ipv6.calls"
    : > "$STATE_DIR/banlist.txt"
    fw_is_banned() { return 1; }
    ip6tables() { if [[ "$1" == -L ]]; then return 1; else echo called >> "$STATE_DIR/ipv6.calls"; return 2; fi; }
    command() { builtin command "$@"; }
    det_decide "$wd" || exit 1
    [[ "$(rows "$STATE_DIR/banlist.txt")" == 2 ]] || exit 1
    [[ ! -s "$STATE_DIR/ipv6.calls" ]] || exit 1
) > "$T/mixed-family.output" 2>&1; then
    ok "缺少ip6tables或IPv6链不阻断IPv4封禁，真实IPv6执行错误仍返回失败"
else
    cat "$T/mixed-family.output"
    fail "IPv4/IPv6混合决策降级"
fi

echo ""
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[[ $FAIL -eq 0 ]]
