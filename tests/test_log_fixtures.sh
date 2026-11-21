#!/bin/bash
# Offline golden-fixture acceptance for every configured access-log format.
set -euo pipefail

TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "$TEST_DIR/.." && pwd)
FIXTURES="$TEST_DIR/fixtures/log-formats"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
PASS=0
FAIL=0
FORMATS=(npm_standard npm_proxy combined apache_common apache_combined apache_vhost_combined)

ok() { PASS=$((PASS+1)); printf '  ✓ %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  ✗ %s\n' "$1"; }

# shellcheck disable=SC1091
source "$PROJECT_DIR/config/swiftban.conf"
# shellcheck disable=SC1091
source "$PROJECT_DIR/lib/logger.sh"
# shellcheck disable=SC1091
source "$PROJECT_DIR/lib/whitelist.sh"
# shellcheck disable=SC1091
source "$PROJECT_DIR/lib/detector.sh"

if ! det_awk 'BEGIN {if(mktime("2026 11 21 12 00 00")<0 || "123" !~ /^[0-9]{3}$/) exit 1}' >/dev/null 2>&1; then
    echo "错误: 格式夹具测试需要支持 mktime 和区间正则的 awk（macOS 请安装 gawk）"
    exit 1
fi

NOW_EPOCH=1795262400 # 2026-11-21 12:00:00 UTC
WINDOW=7200
WHITELIST="127.0.0.1,::1"
WHITELIST_FILE="$T/whitelist"
touch "$WHITELIST_FILE"
export WHITELIST WHITELIST_FILE NOW_EPOCH WINDOW

make_input() {
    local format="$1" input="$2" source raw
    source="/fixtures/$format.log"
    : > "$input"
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        printf '%s\t%s\t%s\n' "$source" "$source" "$raw" >> "$input"
    done < "$FIXTURES/$format.log"
}

normalized() {
    local input="$1" output="$2" stats="$3"
    det_parse "$input" "$output" "$stats"
    awk -F '\t' 'BEGIN {OFS="|"} NF>=9 {print $1,$2,$3,$4,$5,$6,$7,$8}' "$output"
}

compare_golden() {
    local label="$1" actual="$2" expected="$3"
    if diff -u <(LC_ALL=C sort "$expected") <(LC_ALL=C sort "$actual") >/dev/null; then
        ok "$label"
    else
        bad "$label"
        diff -u <(LC_ALL=C sort "$expected") <(LC_ALL=C sort "$actual") || true
    fi
}

compare_contract() {
    local label="$1" actual="$2" expected="$3"
    if [[ ! -s "$expected" ]]; then
        bad "$label 契约文件存在且非空"
        return
    fi
    if diff -u <(LC_ALL=C sort "$expected") <(LC_ALL=C sort "$actual") >/dev/null; then
        ok "$label 符合检测契约"
    else
        bad "$label 符合检测契约"
        diff -u <(LC_ALL=C sort "$expected") <(LC_ALL=C sort "$actual") || true
    fi
}

printf '=== 自编日志格式夹具验收 ===\n'
: > "$T/all.input"
: > "$T/all.expected"
: > "$T/all.expected-stats"
for format in "${FORMATS[@]}"; do
    input="$T/$format.input"
    make_input "$format" "$input"
    source="/fixtures/$format.log"
    expected="$FIXTURES/$format.expected"

    # Each explicit format must accept its own records and reject malformed rows.
    LOG_FORMAT="$format"
    actual="$T/$format.actual"
    stats="$T/$format.stats"
    if normalized "$input" "$T/$format.parsed" "$stats" > "$actual"; then
        compare_golden "$format 显式模式字段符合黄金结果" "$actual" "$expected"
    else
        bad "$format 显式模式解析成功"
    fi
    valid=$(wc -l < "$expected" | tr -d ' ')
    total=$(wc -l < "$FIXTURES/$format.log" | tr -d ' ')
    invalid=$((total-valid))
    printf '%s\t%s\t%s\t0\t0\t0\n' "$source" "$valid" "$invalid" > "$T/$format.expected-stats"
    if diff -u "$T/$format.expected-stats" "$stats" >/dev/null; then
        ok "$format 有效/格式错误计数正确"
    else
        bad "$format 有效/格式错误计数正确"
        diff -u "$T/$format.expected-stats" "$stats" || true
    fi

    cat "$input" >> "$T/all.input"
    cat "$expected" >> "$T/all.expected"
    cat "$T/$format.expected-stats" >> "$T/all.expected-stats"
done

# Auto mode must parse the mixed-format fixture set in one pass.
export LOG_FORMAT=auto
if normalized "$T/all.input" "$T/recent.log" "$T/all.stats" > "$T/all.actual"; then
    compare_golden "auto 模式识别混合格式并逐字段匹配" "$T/all.actual" "$T/all.expected"
    if diff -u <(LC_ALL=C sort "$T/all.expected-stats") <(LC_ALL=C sort "$T/all.stats") >/dev/null; then
        ok "auto 模式混合格式计数正确"
    else
        bad "auto 模式混合格式计数正确"
        diff -u <(LC_ALL=C sort "$T/all.expected-stats") <(LC_ALL=C sort "$T/all.stats") || true
    fi
else
    bad "auto 模式混合格式解析成功"
fi

# Exercise decision behavior from the same normalized fixture rows.
LIMIT_444=99
LIMIT_SCAN=99
LIMIT_EVILPATH=2
LIMIT_PAYLOAD=99
LIMIT_UA=99
LIMIT_AUTH=99
LIMIT_API=3
LIMIT_API_RATE=99
LIMIT_EMPTYUA=99
LIMIT_HIGHFREQ=100
SAFE_PATH='^/safe$'
GIT_SAFE='^$'
EVIL_PATH='\.env|wp-config'
EVIL_PAYLOAD='union.*select'
EVIL_UA='known-bad-agent'
LOGIN_PATH='login'
export LIMIT_444 LIMIT_SCAN LIMIT_EVILPATH LIMIT_PAYLOAD LIMIT_UA LIMIT_AUTH \
    LIMIT_API LIMIT_API_RATE LIMIT_EMPTYUA LIMIT_HIGHFREQ SAFE_PATH GIT_SAFE \
    EVIL_PATH EVIL_PAYLOAD EVIL_UA LOGIN_PATH
fw_is_banned() { return 1; }
WATCH_ROWS="$T/watch.rows"
: > "$WATCH_ROWS"
watch_record() { printf '%s\t' "$1" >> "$WATCH_ROWS"; shift; printf '%s\t' "$@" >> "$WATCH_ROWS"; printf '\n' >> "$WATCH_ROWS"; }
det_detect_all "$T" # The normalized rows were produced above.
: > "$T/candidates.tsv"
det_decide "$T" dry "$T/candidates.tsv" >/dev/null
awk -F '\t' 'NF>=5 {print $1 "\t" $2 "\t" $3 "\t" $4}' "$T/candidates.tsv" > "$T/candidates.actual"
awk -F '\t' 'NF>=6 {print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6}' "$WATCH_ROWS" > "$T/watch.actual"
compare_contract "dry-run 封禁候选" "$T/candidates.actual" "$FIXTURES/detection-candidates.expected"
compare_contract "WATCH 观察记录" "$T/watch.actual" "$FIXTURES/detection-watch.expected"

printf '=== 格式夹具结果: %s 通过, %s 失败 ===\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
