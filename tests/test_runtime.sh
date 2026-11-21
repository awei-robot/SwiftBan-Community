#!/bin/bash
# shellcheck disable=SC2016 # bash -c 的位置参数由内层 shell 展开。
# Linux 真实进程会话/锁集成测试；全部防火墙和调度查询均替换为测试程序。
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
    echo "运行控制集成测试需 Linux；CI 中必须执行"
    exit 0
fi
for dep in python3 setsid flock; do command -v "$dep" >/dev/null || exit 1; done
PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T=$(mktemp -d)
PASS=0
FAIL=0
CLI="$T/repo/bin/swiftban.sh"
cleanup() {
    local code=$?
    if (( code != 0 )); then cat "$T/latest.out" 2>/dev/null || true; fi
    if [[ -n "${SWIFTBAN_CONF:-}" ]]; then "$CLI" stop >/dev/null 2>&1 || true; fi
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$T/repo/bin" "$T/repo/lib" "$T/fake-bin"
cp "$PROJECT_DIR/bin/swiftban.sh" "$CLI"
cp "$PROJECT_DIR"/lib/*.sh "$T/repo/lib/"
# 仅测试副本允许非root执行，且只访问以下替身。
printf '\nrt_require_root() { return 0; }\n' >> "$T/repo/lib/runtime.sh"
cp "$PROJECT_DIR/tests/fake_firewall.py" "$T/fake-bin/iptables"
chmod +x "$T/fake-bin/iptables"
ln -s iptables "$T/fake-bin/ip6tables"
sed -i "s|^export PATH=.*|export PATH=$T/fake-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|" "$CLI"
cp "$T/repo/lib/detector.sh" "$T/detector.original"
cp "$T/repo/lib/scanstate.sh" "$T/scanstate.original"
cat > "$T/fake-bin/crontab" <<'EOF'
#!/bin/bash
cat "$FAKE_FW_DIR/cron"
EOF
cat > "$T/fake-bin/systemctl" <<'EOF'
#!/bin/bash
if [[ "$*" == *swiftban.timer* ]]; then
    printf 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'
else
    echo 'ExecStart={ path=/usr/local/bin/swiftban ; argv[]=/usr/local/bin/swiftban run ; }'
fi
EOF
chmod +x "$T/fake-bin/crontab" "$T/fake-bin/systemctl"
# 工具始终被替身覆盖；只模拟 command -v 判断可选 IPv6 缺失。
command() {
    if [[ "${1:-}" == -v && "${2:-}" == ip6tables && -e "$FAKE_FW_DIR/disable-ipv6" ]]; then return 1; fi
    builtin command "$@"
}
export -f command
ok() { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad() { FAIL=$((FAIL+1)); echo "  ✗ $1"; cat "$T/latest.out" 2>/dev/null || true; }
check() { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
cli() { bash "$CLI" "$@" > "$T/latest.out" 2>&1; }
run_metric() {
    local run_id
    run_id=$(awk -F '\t' '{print $1}' "$STATE/last-run.tsv") || return 1
    find "$STATE/scan/metrics" -type f -name "$run_id.tsv" -print -quit
}
new_case() {
    local name="$1"
    export FAKE_FW_DIR="$T/$name/firewall"
    export SWIFTBAN_CONF="$T/$name/config"
    STATE="$T/$name/state"
    LOGS="$T/$name/logs"
    mkdir -p "$FAKE_FW_DIR" "$STATE" "$LOGS"
    cp "$PROJECT_DIR/config/swiftban.conf" "$SWIFTBAN_CONF"
    printf '\nLOG_DIR="%s"\nSTATE_DIR="%s"\nWHITELIST="127.0.0.1,::1"\n' "$LOGS" "$STATE" >> "$SWIFTBAN_CONF"
    printf '* * * * * /usr/local/bin/swiftban run --dry-run >> /tmp/mock-log 2>&1\n' > "$FAKE_FW_DIR/cron"
    : > "$LOGS/site_access.log"
    : > "$STATE/banlist.txt"
    cp "$T/detector.original" "$T/repo/lib/detector.sh"
    cp "$T/scanstate.original" "$T/repo/lib/scanstate.sh"
}
sample() {
    python3 - "$LOGS/site_access.log" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import sys
stamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
line = f'[{stamp}] 200 - GET https test.example "/" [Client 198.51.100.10] [Length 0] [Gzip -] "sqlmap" "-"\n'
Path(sys.argv[1]).write_text(line * 5)
PY
}
rules() {
    python3 - "$FAKE_FW_DIR" <<'PY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1])
for family in ("v4","v6"):
    file=root/f"{family}.json"
    for rule in json.loads(file.read_text()) if file.exists() else []:
        print(family,rule["ip"],rule["comment"])
PY
}
await_ready() {
    local i
    for ((i=0;i<100;i++)); do
        [[ -f "$STATE/test-ready" && -f "$STATE/child-pid" ]] && return 0
        sleep 0.1
    done
    return 1
}
not_live() {
    [[ ! -r "/proc/$1/stat" ]] || [[ "$(awk '{print $3}' "/proc/$1/stat")" == Z ]]
}

echo "=== Linux 运行管理集成测试 ==="
new_case dry
cli status
check "无历史记录明确显示无可读记录" grep -q '最近执行: 无可读记录' "$T/latest.out"
if cli ban 198.51.100.0/24; then bad "不接受无法按单IP恢复的CIDR"; else ok "手动ban拒绝CIDR和非单IP状态"; fi
sample
cli run --dry-run
check "演练保存独立候选" grep -q $'198.51.100.10\t可疑UA\t5\t5' "$STATE/dry-run.tsv"
check "演练不写真实banlist" test ! -s "$STATE/banlist.txt"
metric=$(run_metric)
check "成功扫描原子保存0600指标文件" bash -c '[[ -f "$1" && "$(stat -c %a "$1")" == 600 ]]' _ "$metric"
check "指标包含各阶段及逐文件耗时" bash -c 'awk -F "\t" '\''$1=="P"&&$2=="collecting"{c=1}$1=="P"&&$2=="parsing"{p=1}$1=="P"&&$2=="publishing"{u=1}$1=="F"{f=1}END{exit !(c&&p&&u&&f)}'\'' "$1"' _ "$metric"
check "指标记录读取行数和窗口事件" bash -c 'awk -F "\t" '\''$1=="C"&&$2=="lines_read"&&$3==5{l=1}$1=="C"&&$2=="window_events"&&$3==5{e=1}END{exit !(l&&e)}'\'' "$1"' _ "$metric"
check "演练无防火墙写操作" bash -c '! grep -Eq "\"-I\"|\"-D\"" "$1"' _ "$FAKE_FW_DIR/calls.jsonl"
cli status
check "status显示最近演练和空闲" grep -q '最近执行: dry-run' "$T/latest.out"
check "status显示最近扫描耗时和处理量" grep -q '最近扫描耗时: .*文件=.*读取=' "$T/latest.out"
check "status显示独立定时配置" grep -q 'cron 推断模式: 演练' "$T/latest.out"
check "status显示systemd配置" grep -q 'ActiveState=active' "$T/latest.out"
printf '* * * * * echo swiftban run --dry-run; touch %s\n' "$T/must-not-execute" > "$FAKE_FW_DIR/cron"
cli status
check "复杂cron命令不误判模式" grep -q 'cron 推断模式: 无法可靠确认' "$T/latest.out"
check "调度查询不执行任务文本" test ! -e "$T/must-not-execute"
cli list --dry-run
check "演练列表明确未实际封禁" grep -q '未实际封禁' "$T/latest.out"
before=$(cksum "$STATE/dry-run.tsv")
printf '\nLOG_DIR="%s"\n' "$T/missing" >> "$SWIFTBAN_CONF"
if cli run --dry-run; then bad "失败演练应返回非零"; else ok "失败演练返回非零"; fi
check "失败保留上次完整结果" test "$(cksum "$STATE/dry-run.tsv")" = "$before"
metric=$(run_metric)
check "失败扫描保存失败阶段部分耗时" bash -c 'awk -F "\t" '\''$1=="M"&&$5=="failed"{f=1}$1=="P"&&$2=="collecting"{p=1}END{exit !(f&&p)}'\'' "$1"' _ "$metric"
printf '\nLOG_DIR="%s"\n' "$LOGS" >> "$SWIFTBAN_CONF"
# A truncated source file does not expire already-collected events. Clear the
# rolling event snapshot here so this assertion covers a genuinely empty window.
awk -F '\t' '$1=="C" {print}' "$STATE/scan/state.tsv" > "$T/cursors-only.tsv"
mv "$T/cursors-only.tsv" "$STATE/scan/state.tsv"
: > "$LOGS/site_access.log"
cli run --dry-run
check "零候选覆盖旧演练结果并保留复核元数据" bash -c 'grep -q "^# run_id[[:space:]]" "$1" && grep -q "^# thresholds[[:space:]]" "$1" && ! grep -q "^[0-9]" "$1"' _ "$STATE/dry-run.tsv"
metric=$(run_metric)
metric_before=$(cksum "$metric" "$STATE/scan/state.tsv")
cli doctor
check "doctor展示历史趋势、阶段详情和状态快照" bash -c 'grep -q "30天扫描记录:" "$1" && grep -q "总耗时分位数: P50=.*P95=" "$1" && grep -q "最近扫描阶段耗时" "$1" && grep -q "扫描快照: 游标=" "$1"' _ "$T/latest.out"
check "doctor不修改指标和扫描快照" test "$(cksum "$metric" "$STATE/scan/state.tsv")" = "$metric_before"
old_day=$(date -u -d '31 days ago' '+%F')
mkdir -p "$STATE/scan/metrics/$old_day"
chmod 700 "$STATE/scan/metrics/$old_day"
old_id=$(cat /proc/sys/kernel/random/uuid)
printf '# swiftban-scan-metrics-v1\nM\t1\t%s\tdry-run\tcompleted\t1\t2\t10000\tv-test\n' "$old_id" > "$STATE/scan/metrics/$old_day/$old_id.tsv"
chmod 600 "$STATE/scan/metrics/$old_day/$old_id.tsv"
cli doctor
check "doctor统计排除保留期外的旧指标" grep -q '30天扫描记录: 3 |' "$T/latest.out"
check "doctor只提示旧指标待清理" grep -q '超出30天的指标目录待清理' "$T/latest.out"
cp "$STATE/scan/state.tsv" "$T/state.backup"
printf 'invalid state row\n' >> "$STATE/scan/state.tsv"
damaged_snapshot=$(cksum "$STATE/scan/state.tsv")
if cli doctor; then bad "doctor应报告损坏的扫描快照"; else ok "doctor报告损坏的扫描快照"; fi
check "doctor诊断损坏快照但不修改它" bash -c 'grep -q "扫描快照结构损坏" "$1" && [[ "$(cksum "$2/scan/state.tsv")" == "$3" ]]' _ "$T/latest.out" "$STATE" "$damaged_snapshot"
mv "$T/state.backup" "$STATE/scan/state.tsv"

new_case stop
now=$(date -u +%s)
printf '198.51.100.1|%s|3600|历史\n2001:db8::1|%s|0|永久\n' "$now" "$now" > "$STATE/banlist.txt"
cli run --dry-run
owner="swiftban:$(cat "$STATE/.instance-id")"
"$T/fake-bin/iptables" -I DOCKER-USER 1 -s 198.51.100.1 -j DROP
"$T/fake-bin/ip6tables" -I DOCKER-USER 1 -s 2001:db8::1 -j DROP
"$T/fake-bin/iptables" -I INPUT 1 -s 198.51.100.99 -m comment --comment "$owner" -j DROP
"$T/fake-bin/iptables" -I DOCKER-USER 1 -s 198.51.100.200 -m comment --comment other-service -j DROP
before=$(cksum "$STATE/banlist.txt")
cli stop
check "停止保留banlist字节和TTL" test "$(cksum "$STATE/banlist.txt")" = "$before"
check "撤销历史IPv4、IPv6及未持久化标记规则" test "$(rules | wc -l)" -eq 1
check "保留其它系统规则" bash -c '[[ "$1" == *other-service* ]]' _ "$(rules)"
cli stop
ok "重复stop幂等"
cli run
check "正式定时运行因停止状态跳过" grep -q '正式检测已停止' "$T/latest.out"
if cli ban 198.51.100.2; then bad "停止状态拒绝手动ban"; else ok "停止状态拒绝手动ban"; fi
cli run --dry-run
check "停止时仍可显式演练" grep -q '^stopped' "$STATE/stopped.tsv"
cli unban 198.51.100.1
check "停止时可取消待恢复记录" bash -c '! grep -q "^198.51.100.1|" "$1"' _ "$STATE/banlist.txt"

new_case start
now=$(date -u +%s)
printf '198.51.100.1|%s|3600|有效\n198.51.100.2|%s|1|过期\n198.51.100.3|0|0|永久\n127.0.0.1|0|0|白名单\n2001:db8::1|%s|3600|IPv6\n' "$now" "$((now-100))" "$now" > "$STATE/banlist.txt"
cli stop
cli start
check "start恢复有效、永久和IPv6记录" test "$(rules | wc -l)" -eq 3
check "start清理已过期记录" bash -c '! grep -q "^198.51.100.2|" "$1"' _ "$STATE/banlist.txt"
check "start跳过白名单" bash -c '[[ "$1" != *127.0.0.1* ]]' _ "$(rules)"
check "start解除停止状态" test ! -e "$STATE/stopped.tsv"
check "start立即正式扫描并记录结果" grep -q $'\tformal\t.*\tcompleted\t0' "$STATE/last-run.tsv"

new_case restore_failure
now=$(date -u +%s)
printf '198.51.100.1|%s|3600|有效\n198.51.100.2|%s|3600|失败\n' "$now" "$now" > "$STATE/banlist.txt"
cli stop
echo 198.51.100.2 > "$FAKE_FW_DIR/fail-insert"
if cli start; then bad "恢复失败应返回非零"; else ok "恢复失败返回非零"; fi
check "恢复失败撤销已恢复部分" test "$(rules | wc -l)" -eq 0
check "恢复失败保持停止状态" grep -q '^stopped' "$STATE/stopped.tsv"
rm "$FAKE_FW_DIR/fail-insert"
cli start
ok "恢复失败后可重试start"
touch "$FAKE_FW_DIR/fail-delete"
if cli stop; then bad "撤销失败不能误报成功"; else ok "撤销失败返回非零"; fi
check "撤销失败保留停止标记" grep -q '^cleanup_failed' "$STATE/stopped.tsv"
if cli start; then bad "停止未完成不得start"; else ok "停止未完成拒绝start"; fi
rm "$FAKE_FW_DIR/fail-delete"
cli stop
ok "重复stop继续清理残留"

new_case cancel
cat >> "$T/repo/lib/scanstate.sh" <<'EOF'
det_scan_collect() {
    rt_phase collecting
    touch "$STATE_DIR/test-ready"
    sleep 60 &
    echo "$!" > "$STATE_DIR/child-pid"
    wait
}
EOF
bash "$CLI" run > "$T/cancel.out" 2>&1 &
supervisor=$!
await_ready
child=$(cat "$STATE/child-pid")
cli status
check "status识别正在执行的正式扫描" grep -q '当前执行: formal' "$T/latest.out"
cli stop
wait "$supervisor"
check "stop终止当前扫描的子进程" not_live "$child"
check "stop记录被停止且释放扫描锁" grep -q $'\tstopped\t0' "$STATE/last-run.tsv"
check "stop移除当前执行元数据" test ! -e "$STATE/active.tsv"

for stage in parsing extracting; do
    new_case "cancel-$stage"
    if [[ "$stage" == parsing ]]; then fn=det_parse; else fn=det_detect_all; fi
    printf '\n%s() {\n' "$fn" >> "$T/repo/lib/detector.sh"
    cat >> "$T/repo/lib/detector.sh" <<'EOF'
    touch "$STATE_DIR/test-ready"
    sleep 60 &
    echo "$!" > "$STATE_DIR/child-pid"
    wait
}
EOF
    bash "$CLI" run > "$T/$stage.out" 2>&1 &
    supervisor=$!
    await_ready
    child=$(cat "$STATE/child-pid")
    cli status
    check "$stage 阶段状态准确" grep -q "阶段=$stage" "$T/latest.out"
    check "$stage 阶段显示动态耗时" grep -Eq "阶段=$stage（已运行 [0-9]+\\.[0-9]{2}s）" "$T/latest.out"
    cli stop
    wait "$supervisor"
    check "$stage 阶段停止后子进程退出" not_live "$child"
    check "$stage 阶段停止不改变banlist" test ! -s "$STATE/banlist.txt"
    if [[ "$stage" == parsing ]]; then
        metric=$(run_metric)
        check "stop中断保留部分阶段耗时并标记停止" bash -c 'awk -F "\t" '\''$1=="M"&&$5=="stopped"{s=1}$1=="P"&&$2=="parsing"{p=1}END{exit !(s&&p)}'\'' "$1"' _ "$metric"
    fi
done

new_case dry_cancel
sample
cli run --dry-run
before=$(cksum "$STATE/dry-run.tsv")
cat >> "$T/repo/lib/scanstate.sh" <<'EOF'
det_scan_collect() {
    touch "$STATE_DIR/test-ready"
    sleep 60 &
    echo "$!" > "$STATE_DIR/child-pid"
    wait
}
EOF
bash "$CLI" run --dry-run > "$T/dry-cancel.out" 2>&1 &
supervisor=$!
await_ready
cli stop
wait "$supervisor"
check "中断演练保留上次完整结果" test "$(cksum "$STATE/dry-run.tsv")" = "$before"
check "中断演练记录正确模式和结果" grep -q $'\tdry-run\t.*\tstopped\t0' "$STATE/last-run.tsv"
cp "$T/detector.original" "$T/repo/lib/detector.sh"
cli run --dry-run
check "中断后仍可在停止状态重新演练" grep -q '^stopped' "$STATE/stopped.tsv"

new_case atomic_cancel
sample
touch "$FAKE_FW_DIR/hold-banlist"
cat > "$T/fake-bin/mv" <<'EOF'
#!/bin/bash
if [[ "$1" == */.banlist-* && -f "$FAKE_FW_DIR/hold-banlist" ]]; then
    state="${FAKE_FW_DIR%/firewall}/state"
    touch "$state/test-ready"
    sleep 60 &
    echo "$!" > "$state/child-pid"
    wait
fi
exec /usr/bin/mv "$@"
EOF
chmod +x "$T/fake-bin/mv"
before=$(cksum "$STATE/banlist.txt")
bash "$CLI" run > "$T/atomic-cancel.out" 2>&1 &
supervisor=$!
await_ready
cli stop
wait "$supervisor"
check "封禁持久化中断不留下半行状态" test "$(cksum "$STATE/banlist.txt")" = "$before"
check "清理已写入但未持久化的本实例规则" test "$(rules | wc -l)" -eq 0
if compgen -G "$STATE/.banlist-*" >/dev/null; then bad "停止后应清理本轮状态临时文件"; else ok "停止后清理本轮状态临时文件"; fi

new_case escalation
cat >> "$T/repo/lib/scanstate.sh" <<'EOF'
det_scan_collect() {
    touch "$STATE_DIR/test-ready"
    bash -c 'trap "" TERM; exec sleep 60' &
    echo "$!" > "$STATE_DIR/child-pid"
    wait
}
EOF
bash "$CLI" run > "$T/escalation.out" 2>&1 &
supervisor=$!
await_ready
child=$(cat "$STATE/child-pid")
cli stop
wait "$supervisor"
check "TERM无效后KILL清理会话成员" not_live "$child"

new_case orphan
cat >> "$T/repo/lib/scanstate.sh" <<'EOF'
det_scan_collect() {
    touch "$STATE_DIR/test-ready"
    bash -c 'exec 8>&-; trap "" TERM; exec sleep 60' &
    echo "$!" > "$STATE_DIR/child-pid"
    wait
}
EOF
bash "$CLI" run > "$T/orphan.out" 2>&1 &
supervisor=$!
await_ready
worker=$(cut -f2 "$STATE/active.tsv")
child=$(cat "$STATE/child-pid")
kill -KILL "$worker"
if wait "$supervisor"; then bad "异常工作进程退出应报告失败"; else ok "异常工作进程退出报告失败"; fi
check "协调进程清理已关闭扫描锁的孤儿子进程" not_live "$child"
check "异常退出记录为中断" grep -q $'\tinterrupted\t137' "$STATE/last-run.tsv"

new_case start_stop_race
now=$(date -u +%s)
printf '198.51.100.1|%s|3600|有效\n' "$now" > "$STATE/banlist.txt"
cat >> "$T/repo/lib/scanstate.sh" <<'EOF'
det_scan_collect() {
    touch "$STATE_DIR/test-ready"
    bash -c 'trap "" TERM; exec sleep 60' &
    echo "$!" > "$STATE_DIR/child-pid"
    wait
}
EOF
bash "$CLI" run > "$T/race-worker.out" 2>&1 &
supervisor=$!
if ! await_ready; then
    printf '启停竞态未进入检测阶段，状态目录内容：\n' >&2
    find "$STATE" -maxdepth 3 -type f -print >&2
    for state_file in "$STATE/active.tsv" "$STATE/stopped.tsv" "$STATE"/.run-*/phase "$STATE"/.run-*/ready "$STATE"/.run-*/go; do
        [[ -r "$state_file" ]] && { printf '%s: ' "$state_file" >&2; cat "$state_file" >&2; }
    done
    pgrep -af 'swiftban\.sh|sleep 60' >&2 || true
    cat "$T/race-worker.out" "$T/race-stop.out" 2>/dev/null || true
    exit 1
fi
child=$(cat "$STATE/child-pid")
bash "$CLI" stop > "$T/race-stop.out" 2>&1 &
stopper=$!
for ((i=0;i<50;i++)); do
    if [[ -r "$STATE/stopped.tsv" ]] && grep -q '^stopping' "$STATE/stopped.tsv"; then break; fi
    sleep 0.1
done
# 旧进程已加载阻塞扫描，新启动进程使用正常引擎。
cp "$T/detector.original" "$T/repo/lib/detector.sh"
bash "$CLI" start > "$T/race-start.out" 2>&1 &
starter=$!
wait "$stopper"
wait "$supervisor"
wait "$starter"
check "并发start等待stop完成再恢复" test ! -e "$STATE/stopped.tsv"
check "旧扫描退出不覆盖新扫描结果" grep -q $'\tformal\t.*\tcompleted\t0' "$STATE/last-run.tsv"
check "并发启停没有遗留旧子进程" not_live "$child"
check "并发启停最终封禁与保留记录一致" test "$(rules | wc -l)" -eq 1

new_case unknown_lock
flock -F "$STATE/.lock" bash -c 'touch "$1"; exec sleep 60' _ "$STATE/test-ready" &
holder=$!
for ((i=0;i<50;i++)); do [[ -f "$STATE/test-ready" ]] && break; sleep 0.1; done
if cli stop; then bad "未知持锁者不得假装停止成功"; else ok "未知持锁者返回未完成"; fi
check "不误杀未登记进程" kill -0 "$holder"
kill "$holder"; wait "$holder" || true
cli stop
ok "未知锁释放后可重试stop"

new_case stale_identity
flock -F "$STATE/.lock" bash -c 'touch "$1"; exec sleep 60' _ "$STATE/test-ready" &
holder=$!
setsid sleep 60 &
unrelated=$!
for ((i=0;i<50;i++)); do [[ -f "$STATE/test-ready" ]] && break; sleep 0.1; done
id=$(cat /proc/sys/kernel/random/uuid)
boot=$(cat /proc/sys/kernel/random/boot_id)
printf '%s\t%s\t%s\t%s\t1\t%s\tformal\t%s\trun\tDOCKER-USER\n' "$id" "$unrelated" "$unrelated" "$unrelated" "$boot" "$(date -u +%s)" > "$STATE/active.tsv"
if cli stop; then bad "失效进程身份应停止失败"; else ok "失效进程身份拒绝发送信号"; fi
check "不误杀被复用PID指向的其它会话" kill -0 "$unrelated"
kill "$holder" "$unrelated"
wait "$holder" || true
wait "$unrelated" || true
cli stop
cli status
check "失效运行记录不显示正在执行" grep -q '当前执行: 空闲' "$T/latest.out"

new_case pid_one_guard
id=$(cat /proc/sys/kernel/random/uuid)
boot=$(cat /proc/sys/kernel/random/boot_id)
printf '%s\t1\t1\t1\t0\t%s\tformal\t0\trun\tDOCKER-USER\n' "$id" "$boot" > "$STATE/active.tsv"
# 只测试解析拒绝，不调用 stop 或发送任何信号。
check "拒绝可能导致kill(-1)的危险元数据" bash -c 'source "$1"; STATE_DIR=$2; ! rt_read_active' _ "$T/repo/lib/runtime.sh" "$STATE"
rm -f "$STATE/active.tsv"

new_case ipv4_only
now=$(date -u +%s)
printf '198.51.100.1|%s|3600|IPv4\n2001:db8::1|%s|3600|IPv6\n' "$now" "$now" > "$STATE/banlist.txt"
printf 'stopped\t-\n' > "$STATE/stopped.tsv"
touch "$FAKE_FW_DIR/disable-ipv6"
cli start
check "缺少可选IPv6时仍恢复IPv4" test "$(rules | wc -l)" -eq 1
check "缺少IPv6工具仍保留IPv6状态" grep -q '^2001:db8::1|' "$STATE/banlist.txt"
if cli stop; then bad "无法验证历史IPv6撤销时不应声称完整成功"; else ok "IPv6撤销未知明确报告停止未完成"; fi

echo "=== 运行管理结果: $PASS 通过, $FAIL 失败 ==="
(( FAIL == 0 ))
