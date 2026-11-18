#!/bin/bash
# shellcheck disable=SC1090,SC1091,SC2329 # 模块按项目路径加载，curl等替身间接调用
set -euo pipefail
PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_PATH="$PATH"
source "$PROJECT_DIR/bin/swiftban.sh"
export PATH="$TEST_PATH"
SWIFTBAN_CONF="$PROJECT_DIR/config/swiftban.conf"
load_config
load_libs
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
STATE_DIR="$T/state"; LOG_DIR="$T/logs"; BANLIST="$STATE_DIR/banlist.txt"; WHITELIST_FILE="$STATE_DIR/whitelist.txt"
mkdir -p "$STATE_DIR" "$LOG_DIR"
: > "$BANLIST"; : > "$WHITELIST_FILE"
rt_require_root() { :; }
flock() { :; }
sleep() { :; }
MOCK_MODE=success
curl() {
    local body='' headers='' url ip
    printf 'request\n' >> "$T/calls"
    while (( $# )); do
        case "$1" in
            --output) body="$2"; shift 2 ;;
            --dump-header) headers="$2"; shift 2 ;;
            http://*) url="$1"; shift ;;
            *) shift ;;
        esac
    done
    ip="${url#http://ip-api.com/json/}"; ip="${ip%%\?*}"
    case "$MOCK_MODE" in
        timeout) return 28 ;;
        invalid) echo '{bad' > "$body"; printf 200; return ;;
        limited) printf 'X-Rl: 0\r\nX-Ttl: 120\r\n' > "$headers"; printf 429; return ;;
        fail) echo '{"status":"fail","message":"reserved range"}' > "$body"; printf 200; return ;;
        mismatch) ip=8.8.4.4 ;;
    esac
    printf 'X-Rl: 40\r\nX-Ttl: 60\r\n' > "$headers"
    jq -n --arg ip "$ip" '{status:"success",country:"中国",regionName:"北京市",city:"北京市",isp:"示例\n运营商",org:"Test Org",as:"AS123 Example",query:$ip}' > "$body"
    printf 200
}
count() { if [[ -f "$T/calls" ]]; then wc -l < "$T/calls" | tr -d ' '; else echo 0; fi; }
cache_edit() {
    jq "$2" "$STATE_DIR/geo/$1.json" > "$T/edited"
    chmod 600 "$T/edited"
    mv "$T/edited" "$STATE_DIR/geo/$1.json"
}
geo_refresh --ip 8.8.8.8 > "$T/summary"
[[ $(count) == 1 ]]
geo_read 8.8.8.8 | jq -e '.state=="fresh" and .location=="中国/北京市" and .isp=="示例 运营商"' >/dev/null
geo_refresh --ip 8.8.8.8 >/dev/null
[[ $(count) == 1 ]]
geo_refresh --ip 8.8.8.8 --force >/dev/null
[[ $(count) == 2 ]]
echo '通过 成功缓存、去重地名、控制字符清理、命中缓存及强制更新'
for ip in 127.0.0.1 10.0.0.1 169.254.1.1 224.0.0.1 ::1 fe80::1 fc00::1 ff02::1 ::ffff:192.168.1.1; do
    geo_refresh --ip "$ip" >/dev/null
    canonical=$(wl_normalize_ip "$ip")
    geo_read "$canonical" | jq -e '.state=="local"' >/dev/null
done
[[ $(count) == 2 ]]
geo_refresh --ip 2001:db8::1 >/dev/null
geo_refresh --ip 2001:0db8:0:0:0:0:0:1 >/dev/null
[[ $(count) == 3 ]]
echo '通过 本地地址不请求接口及IPv6等价缓存'
cache_edit 8.8.8.8 '.updated_at=1'
geo_read 8.8.8.8 | jq -e '.state=="stale" and (.location|contains("已过期"))' >/dev/null
MOCK_MODE=timeout
if geo_refresh --ip 8.8.8.8 >/dev/null 2>&1; then exit 1; fi
geo_read 8.8.8.8 | jq -e '.state=="stale" and .geo.country=="中国" and .last_error!="" and .retry_after>0' >/dev/null
before=$(count)
geo_refresh --ip 8.8.8.8 >/dev/null
[[ $(count) == "$before" ]]
for mode in invalid mismatch fail; do
    MOCK_MODE="$mode"
    if geo_refresh --ip 9.9.9.9 --force >/dev/null 2>&1; then exit 1; fi
    geo_read 9.9.9.9 | jq -e '.state=="failed" and .geo==null' >/dev/null
done
echo '通过 过期、失败保留成功数据、失败退避、非法JSON及返回IP不匹配'
MOCK_MODE=limited
if geo_refresh --ip 9.9.9.9 --force > "$T/quota" 2>/dev/null; then exit 1; fi
before=$(count)
MOCK_MODE=success
if geo_refresh --ip 1.1.1.1 --force >/dev/null 2>&1; then exit 1; fi
[[ $(count) == "$before" ]]
[[ $(cat "$STATE_DIR/geo/rate-limit") -gt $(date +%s) ]]
if geo_refresh --ip 1.1.1.1 --force > "$T/quota" 2>/dev/null; then exit 1; fi
grep -q '限流暂停' "$T/quota"
echo '通过 429持久化限流且force不能绕过'
# 对展示与诊断使用禁止网络调用的替身。
curl() { echo 'unexpected network' >> "$T/unexpected"; return 1; }
printf '8.8.8.8|1|0|test\n' > "$BANLIST"
cmd_list > "$T/list"
grep -q '中国/北京市' "$T/list"
cmd_list_ip 8.8.8.8 > "$T/raw"
grep -q '来源地:' "$T/raw"
mkdir -p "$STATE_DIR/watch/formal/2026-11-18"
printf '%s\t8.8.8.8\tapi\t203\t200\t7200\texample.com/api\n' "$(date +%s)" > "$STATE_DIR/watch/formal/2026-11-18/.pending.test.tsv"
cmd_watch --json > "$T/watch.json"
jq -e '.[0].geo.country=="中国" and .[0].count==203' "$T/watch.json" >/dev/null
cmd_geo show 8.8.8.8 > "$T/show"
grep -q 'AS123' "$T/show"
geo_doctor >/dev/null
[[ ! -e "$T/unexpected" && ! -e "$STATE_DIR/.lock" ]]
echo '通过 列表、明细、WATCH JSON和详情只读缓存，不联网不申请扫描锁'
# 模拟原子替换失败，已发布缓存必须保持原样。
before_cache=$(cksum "$STATE_DIR/geo/8.8.8.8.json")
(
    mv() { return 1; }
    if geo_save 8.8.8.8 < "$STATE_DIR/geo/8.8.8.8.json"; then exit 1; fi
)
[[ $(cksum "$STATE_DIR/geo/8.8.8.8.json") == "$before_cache" ]]
# 支持真实 flock 的 Linux CI 验证独立刷新锁冲突。
if [[ "$(uname -s)" == Linux ]]; then
    (
        flock() { builtin command flock "$@"; }
        exec 6> "$STATE_DIR/geo/.refresh.lock"
        builtin command flock -n 6
        if geo_refresh --ip 1.1.1.1 --force > "$T/locked" 2>&1; then exit 1; fi
        grep -q '归属地刷新正在执行' "$T/locked"
    )
    echo '通过 Linux 真实刷新锁冲突'
else
    echo '跳过 Linux 真实刷新锁冲突（需 Linux CI）'
fi
echo '通过 原子替换失败保留缓存'
echo broken > "$STATE_DIR/geo/8.8.8.8.json"
geo_read 8.8.8.8 | jq -e '.state=="missing"' >/dev/null
if geo_doctor >/dev/null; then exit 1; fi
# 批量去重、优先级及30项上限（独立目录，无已有缓存）。
(
    STATE_DIR="$T/batch"; BANLIST="$STATE_DIR/banlist.txt"
    mkdir -p "$STATE_DIR/watch/dry-run/day"; : > "$T/batch-calls"
    for n in $(seq 1 32); do printf '198.51.100.%s|1|0|test\n' "$n"; done > "$BANLIST"
    printf '%s\t198.51.100.1\tapi\t203\t200\t7200\ta\n%s\t203.0.113.1\tfreq\t600\t500\t7200\t-\n' "$(date +%s)" "$(date +%s)" > "$STATE_DIR/watch/dry-run/day/.pending.test.tsv"
    curl() {
        local body='' headers='' url ip
        while (( $# )); do
            case "$1" in --output) body="$2"; shift 2;; --dump-header) headers="$2"; shift 2;; http://*) url="$1"; shift;; *) shift;; esac
        done
        ip="${url#http://ip-api.com/json/}"; ip="${ip%%\?*}"
        echo "$ip" >> "$T/batch-calls"
        echo 'X-Rl: 40' > "$headers"
        jq -n --arg ip "$ip" '{status:"success",country:"X",regionName:"",city:"",isp:"ISP",org:"",as:"",query:$ip}' > "$body"
        printf 200
    }
    if geo_refresh > "$T/batch-summary"; then exit 1; fi
    [[ $(wc -l < "$T/batch-calls" | tr -d ' ') == 30 ]]
    [[ $(head -1 "$T/batch-calls") == 198.51.100.1 ]]
    grep -q '剩余=3' "$T/batch-summary"
    geo_refresh > "$T/batch-summary"
    [[ $(wc -l < "$T/batch-calls" | tr -d ' ') == 33 ]]
    grep -q '203.0.113.1' "$T/batch-calls"
)
echo '通过 批量规范化去重、封禁优先、演练WATCH候选及30项续刷'
# 可选依赖缺失不影响查看缓存降级。
(
    command() { if [[ "${2:-}" == jq ]]; then return 1; fi; builtin command "$@"; }
    geo_read 8.8.8.8 > "$T/unavailable"
    grep -q '功能不可用' "$T/unavailable"
    cmd_list >/dev/null
)
echo '通过 缺失可选依赖和损坏缓存降级'

# 正式和演练的完整扫描路径均不得调用网络。
test_scan_offline() (
    local STATE_DIR="$T/scan" BANLIST BANLOG
    BANLIST="$STATE_DIR/banlist.txt"; BANLOG="$STATE_DIR/ban.log"
    mkdir -p "$STATE_DIR"
    fw_count() { echo '0:0'; }
    det_run 0 >/dev/null
    det_run 1 >/dev/null
    [[ ! -e "$T/unexpected" && ! -e "$STATE_DIR/geo" ]]
)
test_scan_offline
echo '通过 正式及演练扫描不联网'
