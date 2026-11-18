#!/bin/bash
# shellcheck disable=SC1090,SC1091,SC2034
set -euo pipefail
PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$PROJECT_DIR/lib/logger.sh"
source "$PROJECT_DIR/lib/whitelist.sh"
source "$PROJECT_DIR/lib/watch.sh"
source "$PROJECT_DIR/lib/geo.sh"
source "$PROJECT_DIR/lib/detector.sh"
STATE_DIR=$(mktemp -d)
trap 'rm -rf "$STATE_DIR"' EXIT
WATCH_RETENTION_DAYS=7
NOW=$(date +%s)
WATCH_PENDING="$STATE_DIR/pending"
: > "$WATCH_PENDING"
watch_record 198.51.100.1 api 203 200 7200 'example.com/a?x="test"\x22'
watch_record 198.51.100.1 apirate 40 30 60 example.com/a
watch_record 198.51.100.1 apirate 35 30 60 example.com/a
watch_record 198.51.100.2 freq 600 500 7200 -
watch_publish formal "$WATCH_PENDING"
: > "$WATCH_PENDING"
NOW=$((NOW+1))
watch_record 198.51.100.1 api 210 200 7200 'example.com/a?x="test"\x22'
watch_publish formal "$WATCH_PENDING"
cmd_watch --json > "$STATE_DIR/result.json"
python3 - "$STATE_DIR/result.json" <<'PY'
import json,sys
rows=json.load(open(sys.argv[1]))
assert len(rows)==3
rate=next(x for x in rows if x['rule']=='apirate')
assert rate['count']==40 and rate['scans']==1
row=next(x for x in rows if x['rule']=='api')
assert row['count']==210 and row['peak']==210 and row['scans']==2
assert row['endpoint']=='example.com/a?x="test"\\x22'
assert row['first_seen']<row['last_seen']
PY
echo '通过 聚合、峰值、轮次、时间与JSON转义'
cmd_watch --ip 198.51.100.2 --rule freq --json | python3 -c 'import json,sys; r=json.load(sys.stdin); assert len(r)==1 and r[0]["count"]==600'
cmd_watch --limit 1 --json | python3 -c 'import json,sys; assert len(json.load(sys.stdin))==1'
watch_publish dry-run "$WATCH_PENDING"
cmd_watch --dry-run --json | python3 -c 'import json,sys; r=json.load(sys.stdin); assert len(r)==1 and r[0]["scans"]==1'
echo '通过 筛选、条数限制、正式与演练隔离'
: > "$WATCH_PENDING"
watch_publish formal "$WATCH_PENDING"
cmd_watch --json | python3 -c 'import json,sys; assert len(json.load(sys.stdin))==3'
watch_summary > "$STATE_DIR/summary"
grep -q '近24小时命中IP=2' "$STATE_DIR/summary"
watch_doctor
# 未发布的中间文件不会进入查询。
watch_record 198.51.100.99 api 999 200 7200 incomplete
cmd_watch --json | python3 -c 'import json,sys; assert all(x["ip"]!="198.51.100.99" for x in json.load(sys.stdin))'
echo '通过 零命中不清除历史、状态摘要、诊断与未完成结果隔离'
if cmd_watch --since bad >/dev/null 2>&1; then exit 1; fi
if cmd_watch --rule bad >/dev/null 2>&1; then exit 1; fi
NOW=$(( NOW + 8*86400 ))
: > "$WATCH_PENDING"
watch_publish formal "$WATCH_PENDING"
cmd_watch --since 30d --json | python3 -c 'import json,sys; assert json.load(sys.stdin)==[]'
printf 'bad\n' > "$STATE_DIR/watch/formal/broken.pending"
# 用产品发布文件名校验损坏格式。
mv "$STATE_DIR/watch/formal/broken.pending" "$STATE_DIR/watch/formal/.pending.broken.tsv"
if watch_doctor >/dev/null 2>&1; then exit 1; fi
echo '通过 非法参数、跨模式过期清理与损坏文件诊断'
(
    STATE_DIR="$STATE_DIR/alignment"
    mkdir -p "$STATE_DIR"
    NOW=$(date +%s)
    WATCH_PENDING="$STATE_DIR/pending"
    : > "$WATCH_PENDING"
    watch_record 114.252.120.44 freq 517 500 7200 -
    watch_record 2001:0db8:0000:0000:0000:0000:0000:0001 apirate 2147483647 2147483647 60 example.com/api
    watch_record 198.51.100.1 api 203 200 7200 example.com/a
    watch_publish formal "$WATCH_PENDING"
    LC_ALL=C cmd_watch > "$STATE_DIR/table"
    cat "$STATE_DIR/table"
    python3 - "$STATE_DIR/table" <<'PY'
import re, sys, unicodedata
lines = open(sys.argv[1]).read().splitlines()[1:]
def starts(line):
    positions = [m.start() for m in re.finditer(r'\S.*?(?= {2,}|$)', line)]
    return [sum(2 if unicodedata.east_asian_width(c) in ('W','F') else 1
                for c in line[:p]) for p in positions]
expected = starts(lines[0])
assert len(expected) == 11, expected
for line in lines[1:]:
    assert '\t' not in line
    assert starts(line) == expected, (line, starts(line), expected)
PY
)
echo '通过 中文表头与三种规则、IPv4/IPv6和长计数的终端显示列对齐'
