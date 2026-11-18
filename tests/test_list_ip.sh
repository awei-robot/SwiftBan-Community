#!/bin/bash
# shellcheck disable=SC1090,SC1091
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
LOG_DIR="$T/logs"; STATE_DIR="$T/state"
mkdir -p "$LOG_DIR" "$STATE_DIR"
printf 'unchanged\n' > "$STATE_DIR/banlist.txt"
now=$(date +%s)
stamp() {
    LC_ALL=C date -u -d "@$1" '+%d/%b/%Y:%H:%M:%S +0000' 2>/dev/null ||
        LC_ALL=C date -u -r "$1" '+%d/%b/%Y:%H:%M:%S +0000'
}
new=$(stamp "$((now-10))"); old=$(stamp "$((now-120))"); expired=$(stamp "$((now-9000))"); future=$(stamp "$((now+3600))")
printf '%s\n' \
 'bad record' \
 "198.51.100.1 - - [$old] \"GET /old HTTP/1.1\" 404 0 \"-\" \"Mozilla\"" \
 "198.51.100.2 - - [$new] \"GET /198.51.100.1 HTTP/1.1\" 200 0 \"-\" \"198.51.100.1\"" \
 "198.51.100.1 - - [$expired] \"GET /expired HTTP/1.1\" 200 0 \"-\" \"Mozilla\"" \
 "198.51.100.1 - - [$future] \"GET /future HTTP/1.1\" 200 0 \"-\" \"Mozilla\"" > "$LOG_DIR/site_access.log"
printf '[%s] 200 - POST https example.com "/new?a=1" [Client 198.51.100.1] [Length 0] [Gzip -] "Mozilla\\x22" "-"\n' "$new" > "$LOG_DIR/npm_access.log"
printf '2001:db8::1 - - [%s] "GET /v6 HTTP/1.1" 200 0 "-" "Mozilla"\n' "$new" > "$LOG_DIR/v6_access.log"
printf 'unchanged\n' > "$STATE_DIR/banlist.txt"
cmd_list --ip 198.51.100.1 > "$T/result"
grep -q '命中: 3 条' "$T/result"
grep -q 'site_access.log:2' "$T/result"
grep -q 'npm_access.log:1' "$T/result"
grep -qF "$(cat "$LOG_DIR/npm_access.log")" "$T/result"
python3 - "$T/result" <<'PY'
import sys
s=open(sys.argv[1]).read()
assert s.index('/expired HTTP') < s.index('/old HTTP') < s.index('/new?a=1')
for value in ['/future HTTP','/198.51.100.1 HTTP']:
    assert value not in s
PY
cmd_list --ip 198.51.100.1 --limit 1 --since 1m > "$T/limited"
grep -q '命中: 1 条' "$T/limited"
if grep -q '/old HTTP' "$T/limited"; then exit 1; fi
cmd_list --ip 2001:0db8:0:0:0:0:0:1 > "$T/v6"
grep -q '/v6 HTTP' "$T/v6"
cmd_list --ip 198.51.100.99 > "$T/empty"
grep -q '无匹配记录' "$T/empty"
[[ $(cat "$STATE_DIR/banlist.txt") == unchanged ]]
if cmd_list --ip invalid >/dev/null 2>&1; then exit 1; fi
if cmd_list --ip 198.51.100.1 --limit 0 >/dev/null 2>&1; then exit 1; fi
if cmd_list --ip 198.51.100.1 --since bad >/dev/null 2>&1; then exit 1; fi
# 原始查询保留轮转文件的重复行，可通过来源区分。
cp "$LOG_DIR/npm_access.log" "$LOG_DIR/npm_access.log.1"
cmd_list --ip 198.51.100.1 > "$T/rotation"
grep -q '命中: 4 条' "$T/rotation"
grep -q 'npm_access.log.1:1' "$T/rotation"
rm "$LOG_DIR/npm_access.log.1"
# 历史查询包括较旧文件，自动扫描仍按3分钟筛选。
touch -t 202001010000 "$LOG_DIR/site_access.log"
cmd_list --ip 198.51.100.1 > "$T/mtime"
grep -q '命中: 3 条' "$T/mtime"
mkdir "$T/recent"
det_collect "$T/recent"
if grep -q '/old HTTP' "$T/recent/input.tsv"; then exit 1; fi
cmd_list --ip 198.51.100.1 --limit 1 > "$T/first"
grep -q '/expired HTTP' "$T/first"
if grep -q '/old HTTP' "$T/first"; then exit 1; fi
(
    # shellcheck disable=SC2329 # 间接调用的故障替身
    det_collect() { return 1; }
    if cmd_list --ip 198.51.100.1 > "$T/failed" 2>/dev/null; then exit 1; fi
    [[ ! -s "$T/failed" ]]
)
echo '通过 原始日志与行号、时间正序、客户端精确匹配、IPv6、时间和数量筛选、包含旧文件且默认不限日志时间、自动扫描仍排除旧文件、无命中与失败处理、不修改状态'
