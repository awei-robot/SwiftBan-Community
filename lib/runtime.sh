#!/bin/bash
# 运行控制：控制锁只保护短事务，扫描锁随独立工作会话存活。

rt_record() {
    local target="$1" tmp field sep=""
    shift
    tmp=$(mktemp "$STATE_DIR/.state-${RT_RUN_ID:-control}.XXXXXX") || return 1
    if {
        for field in "$@"; do
            printf '%s%s' "$sep" "$field"
            sep=$'\t'
        done
        printf '\n'
    } > "$tmp" && mv -f "$tmp" "$target"
    then return 0
    else rm -f "$tmp"; return 1; fi
}

rt_require_root() {
    if (( EUID != 0 )); then
        log_error "此命令需要 root 权限"
        return 1
    fi
}

rt_init() {
    local dep uuid
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1) )); then
        log_error "运行控制需要 Bash 4.1 或更新版本"
        return 1
    fi
    [[ "$(uname -s)" == Linux && -r /proc/self/stat ]] || {
        log_error "运行控制需要 Linux /proc"; return 1;
    }
    for dep in flock setsid; do
        command -v "$dep" >/dev/null 2>&1 || { log_error "缺少运行依赖: $dep"; return 1; }
    done
    umask 077
    mkdir -p "$STATE_DIR" || return 1
    STATE_DIR=$(cd "$STATE_DIR" && pwd -P) || return 1
    BANLIST="$STATE_DIR/banlist.txt"
    BANLOG="$STATE_DIR/ban.log"
}

rt_control_lock() {
    exec 9> "$STATE_DIR/.control.lock" || return 1
    flock -w 10 9 || { log_error "运行控制繁忙，请稍后重试"; return 1; }
    if [[ ! -e "$STATE_DIR/.instance-id" ]]; then
        IFS= read -r uuid < /proc/sys/kernel/random/uuid || return 1
        rt_record "$STATE_DIR/.instance-id" "$uuid" || return 1
    fi
    IFS= read -r uuid < "$STATE_DIR/.instance-id" || return 1
    [[ "$uuid" =~ ^[0-9a-f-]{36}$ ]] || { log_error "实例标识损坏"; return 1; }
    export RT_OWNER="swiftban:$uuid"
}

rt_read_active() {
    [[ -r "$STATE_DIR/active.tsv" ]] || return 1
    IFS=$'\t' read -r RT_ID RT_PID RT_PGID RT_SID RT_TICKS RT_BOOT RT_MODE RT_STARTED RT_ACTION RT_CHAIN \
        < "$STATE_DIR/active.tsv" || return 1
    [[ "$RT_ID" =~ ^[0-9a-f-]{36}$ && "$RT_PID" =~ ^[1-9][0-9]*$ &&
       "$RT_TICKS" =~ ^[0-9]+$ && "$RT_PID" == "$RT_PGID" && "$RT_PID" == "$RT_SID" ]] || return 1
    (( RT_PID > 1 )) || return 1
    [[ "$RT_MODE" == formal || "$RT_MODE" == dry-run ]] || return 1
}

rt_proc() {
    local raw
    IFS= read -r raw 2>/dev/null < "/proc/$1/stat" || return 1
    read -r -a RT_PROC <<< "${raw##*) }"
    (( ${#RT_PROC[@]} >= 20 ))
}

# /proc/uptime is monotonic and available on every supported Linux host.
# Store centiseconds to avoid sub-second scans appearing to take zero time.
rt_clock_cs() {
    local uptime seconds fraction
    IFS=' ' read -r uptime _ < /proc/uptime || return 1
    [[ "$uptime" =~ ^([0-9]+)\.([0-9]+)$ ]] || return 1
    seconds="${BASH_REMATCH[1]}"
    fraction="${BASH_REMATCH[2]}00"
    fraction="${fraction:0:2}"
    REPLY=$((10#$seconds * 100 + 10#$fraction))
}

rt_metrics_init() {
    local dir="$STATE_DIR/.run-$RT_RUN_ID" tick wall
    rt_clock_cs || return 1
    tick="$REPLY"
    wall=$(date -u +%s) || return 1
    : > "$dir/phases.tsv" && : > "$dir/files.tsv" && : > "$dir/facts.tsv" || return 1
    printf 'M\t1\t%s\t%s\t%s\t%s\tpending\t0\t0\n' \
        "$RT_RUN_ID" "$RT_MODE" "$wall" "$tick" > "$dir/metrics.tsv" || return 1
}

rt_metrics_fact() {
    [[ "${RT_METRICS_ENABLED:-0}" == 1 && -n "${RT_RUN_DIR:-}" && -n "${RT_RUN_ID:-}" ]] || return 0
    [[ "$1" =~ ^[a-z_]+$ && "$2" != *$'\t'* && "$2" != *$'\n'* ]] || return 0
    printf 'C\t%s\t%s\n' "$1" "$2" >> "$RT_RUN_DIR/facts.tsv" ||
        log_warn "扫描指标更新失败: $1"
    return 0
}

rt_metrics_inc() {
    local key="$1" value=0
    [[ "${RT_METRICS_ENABLED:-0}" == 1 && -n "${RT_RUN_DIR:-}" && -n "${RT_RUN_ID:-}" ]] || return 0
    value=$(awk -F '\t' -v key="$key" '$1=="C" && $2==key {v=$3} END {print v+0}' \
        "$RT_RUN_DIR/facts.tsv" 2>/dev/null) || return 1
    rt_metrics_fact "$key" "$((value + ${2:-1}))"
}

rt_metrics_file() {
    [[ "${RT_METRICS_ENABLED:-0}" == 1 && -n "${RT_RUN_DIR:-}" && -n "${RT_RUN_ID:-}" ]] || return 0
    local path="$1" elapsed="$2" bytes="$3" lines="$4"
    [[ "$path" != *$'\t'* && "$path" != *$'\n'* && "$elapsed" =~ ^[0-9]+$ &&
       "$bytes" =~ ^[0-9]+$ && "$lines" =~ ^[0-9]+$ ]] || return 1
    printf 'F\t%s\t%s\t%s\t%s\n' "$path" "$elapsed" "$bytes" "$lines" \
        >> "$RT_RUN_DIR/files.tsv" || log_warn "单文件扫描耗时记录失败: $path"
    return 0
}

rt_metrics_close_phase() {
    local run_dir="$1" now phase started wall elapsed
    [[ -r "$run_dir/phase-clock" ]] || return 0
    IFS=$'\t' read -r phase started wall < "$run_dir/phase-clock" || return 1
    [[ "$phase" =~ ^[a-z-]+$ && "$started" =~ ^[0-9]+$ ]] || return 1
    rt_clock_cs || return 1
    now="$REPLY"
    elapsed=$((now-started))
    (( elapsed >= 0 )) || elapsed=0
    printf 'P\t%s\t%s\n' "$phase" "$elapsed" >> "$run_dir/phases.tsv"
}

rt_metrics_path() {
    local run_id="$1" file
    [[ "$run_id" =~ ^[0-9a-f-]{36}$ ]] || return 1
    for file in "$STATE_DIR"/scan/metrics/????-??-??/"$run_id".tsv; do
        [[ -f "$file" ]] && { printf '%s\n' "$file"; return 0; }
    done
    return 1
}

# Publish a compact, versioned run record plus the ten slowest files. The
# record is diagnostic only: its failure never changes the scan result.
rt_metrics_publish() (
    local run_id="$1" mode="$2" result="$3" started_epoch="$4"
    local run_dir="$STATE_DIR/.run-$run_id" finish_epoch finish_cs start_cs duration day root tmp
    [[ -r "$run_dir/metrics.tsv" ]] || return 0
    if rt_metrics_path "$run_id" >/dev/null 2>&1; then return 0; fi
    IFS=$'\t' read -r _ _ _ _ _ start_cs _ _ _ < "$run_dir/metrics.tsv" || return 1
    [[ "$start_cs" =~ ^[0-9]+$ ]] || return 1
    rt_metrics_close_phase "$run_dir" || return 1
    if [[ -r "$run_dir/result" ]] && IFS=$'\t' read -r _ finish_epoch finish_cs < "$run_dir/result" &&
        [[ "$finish_epoch" =~ ^[0-9]+$ && "$finish_cs" =~ ^[0-9]+$ ]]; then :
    else
        rt_clock_cs || return 1
        finish_cs="$REPLY"
        finish_epoch=$(date -u +%s) || return 1
    fi
    duration=$((finish_cs-start_cs)); (( duration >= 0 )) || duration=0
    day=$(date -u -d "@$finish_epoch" '+%F') || return 1
    root="$STATE_DIR/scan/metrics/$day"
    umask 077
    mkdir -p "$root" || return 1
    chmod 700 "$STATE_DIR/scan" "$STATE_DIR/scan/metrics" "$root" || return 1
    tmp=$(mktemp "$root/.${run_id}.XXXXXX") || return 1
    {
        printf '# swiftban-scan-metrics-v1\n'
        printf 'M\t1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$run_id" "$mode" "$result" "$started_epoch" "$finish_epoch" "$duration" \
            "${SWIFTBAN_VERSION:-unknown}"
        [[ ! -s "$run_dir/phases.tsv" ]] || cat "$run_dir/phases.tsv"
        if [[ -s "$run_dir/facts.tsv" ]]; then
            awk -F '\t' -v OFS='\t' '{facts[$2]=$3} END {for(k in facts) print "C",k,facts[k]}' \
                "$run_dir/facts.tsv" | LC_ALL=C sort -t $'\t' -k2,2
        fi
        if [[ -s "$run_dir/files.tsv" ]]; then
            LC_ALL=C sort -t $'\t' -k3,3nr -k2,2 "$run_dir/files.tsv" |
                sed -n '1,10p'
        fi
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    if chmod 600 "$tmp" && mv "$tmp" "$root/$run_id.tsv"; then :
    else rm -f "$tmp"; return 1; fi
    # Keep the most recent 30 UTC days; date directory names sort lexically.
    local cutoff old
    cutoff=$(date -u -d "@$((finish_epoch-30*86400))" '+%F') || return 1
    for old in "$STATE_DIR"/scan/metrics/????-??-??; do
        [[ -d "$old" ]] || continue
        [[ "${old##*/}" < "$cutoff" ]] && rm -rf "$old"
    done
)

# 返回 0=同一会话仍有存活成员，1=已退出，2=身份不可信。忽略僵尸进程。
rt_group_state() {
    local boot path
    IFS= read -r boot < /proc/sys/kernel/random/boot_id || return 2
    # 不同启动周期的会话已经不存在，不能将复用PID当作旧扫描。
    [[ "$boot" == "$RT_BOOT" ]] || return 1
    if [[ -e "/proc/$RT_PID" ]]; then
        rt_proc "$RT_PID" || return 2
        [[ "${RT_PROC[19]}" == "$RT_TICKS" && "${RT_PROC[2]}" == "$RT_PGID" &&
           "${RT_PROC[3]}" == "$RT_SID" ]] || return 2
    fi
    for path in /proc/[0-9]*/stat; do
        path="${path%/stat}"
        rt_proc "${path##*/}" || continue
        if [[ "${RT_PROC[0]}" != Z && "${RT_PROC[2]}" == "$RT_PGID" &&
              "${RT_PROC[3]}" == "$RT_SID" ]]; then return 0; fi
    done
    return 1
}

rt_terminate_group() {
    local i code
    if rt_group_state; then :; else code=$?; [[ "$code" == 1 ]]; return; fi
    kill -TERM -- "-$RT_PGID" 2>/dev/null || true
    for ((i=0;i<50;i++)); do
        if rt_group_state; then sleep 0.1
        else code=$?; [[ "$code" == 1 ]]; return; fi
    done
    # 升级信号前再次校验，防止向复用的进程组发送KILL。
    if rt_group_state; then :; else code=$?; [[ "$code" == 1 ]]; return; fi
    kill -KILL -- "-$RT_PGID" 2>/dev/null || true
    for ((i=0;i<50;i++)); do
        if rt_group_state; then sleep 0.1
        else code=$?; [[ "$code" == 1 ]]; return; fi
    done
    return 1
}

rt_scan_busy() (
    [[ -e "$STATE_DIR/.lock" ]] || return 1
    exec 8< "$STATE_DIR/.lock" || return 2
    if flock -n 8; then return 1; else return 0; fi
)

rt_phase() {
    [[ -n "${RT_RUN_DIR:-}" ]] || return 0
    if [[ -r "$RT_RUN_DIR/phase-clock" ]]; then
        rt_metrics_close_phase "$RT_RUN_DIR" || log_warn "阶段耗时记录失败: $1"
    fi
    rt_record "$RT_RUN_DIR/phase" "$1" || return 1
    if [[ "${RT_METRICS_ENABLED:-0}" == 1 ]]; then
        local tick wall
        if rt_clock_cs; then
            tick="$REPLY"
            if wall=$(date -u +%s); then
                rt_record "$RT_RUN_DIR/phase-clock" "$1" "$tick" "$wall" ||
                    log_warn "阶段计时起点保存失败: $1"
            else log_warn "无法读取UTC时间，跳过阶段计时起点"; fi
        else log_warn "无法读取单调时钟，跳过阶段计时起点"; fi
    fi
    return 0
}

rt_cleanup_run() {
    local id="$1"
    [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || return 1
    rm -f "$STATE_DIR/.state-$id".* "$STATE_DIR/.banlist-$id".* \
        "$STATE_DIR/.expired-$id".* "$STATE_DIR/.dry-run-$id".*
    rm -rf "$STATE_DIR/.run-$id/work"
}

rt_may_enforce() {
    local state id
    [[ -e "$STATE_DIR/stopped.tsv" ]] || return 0
    IFS=$'\t' read -r state id < "$STATE_DIR/stopped.tsv" || return 1
    [[ "${RT_ACTION:-}" == start && "$state" == starting && "$id" == "${RT_RUN_ID:-}" ]]
}

rt_last() {
    rt_record "$STATE_DIR/last-run.tsv" "$RT_ID" "$RT_MODE" "$RT_STARTED" \
        "$(date -u +%s)" "$1" "$2"
}

rt_finish() (
    local id="$1" code="$2" result=completed
    rt_control_lock || return 1
    if rt_read_active && [[ "$RT_ID" == "$id" ]]; then
        if (( code >= 128 )); then result=interrupted
        elif (( code != 0 )); then result=failed; fi
        if ! rt_metrics_publish "$id" "$RT_MODE" "$result" "$RT_STARTED"; then
            log_warn "扫描耗时指标保存失败，不影响扫描结果"
        fi
        rt_last "$result" "$code" || return 1
        rm -f "$STATE_DIR/active.tsv"
    fi
)

rt_start_restore() {
    export NOW
    NOW=$(date -u +%s)
    mkdir -p "$STATE_DIR" || return 1
    touch "$BANLIST" "$BANLOG" || return 1
    rt_phase restoring || return 1
    if ! det_unban_expired || ! det_restore; then
        log_error "恢复失败，保留停止状态并撤销本次恢复规则"
        if fw_remove_managed; then rt_record "$STATE_DIR/stopped.tsv" stopped "$RT_RUN_ID"
        else rt_record "$STATE_DIR/stopped.tsv" cleanup_failed "$RT_RUN_ID"; fi
        return 1
    fi
    # 恢复阶段不长期持有控制锁，stop 可以在恢复中终止工作会话。
    if (
        rt_control_lock || exit 1
        local state id
        IFS=$'\t' read -r state id < "$STATE_DIR/stopped.tsv" || exit 1
        [[ "$state" == starting && "$id" == "$RT_RUN_ID" ]] || exit 1
        rm -f "$STATE_DIR/stopped.tsv"
    ); then return 0
    else
        if fw_remove_managed; then rt_record "$STATE_DIR/stopped.tsv" stopped "$RT_RUN_ID"
        else rt_record "$STATE_DIR/stopped.tsv" cleanup_failed "$RT_RUN_ID"; fi
        return 1
    fi
}

# 只由持有扫描锁的协调进程启动；未收到 go 前不能访问防火墙或扫描日志。
rt_worker() {
    RT_RUN_ID="$1"
    RT_MODE="$2"
    RT_ACTION="$3"
    [[ "$RT_RUN_ID" =~ ^[0-9a-f-]{36}$ ]] || return 1
    [[ "$RT_MODE" == formal || "$RT_MODE" == dry-run ]] || return 1
    [[ "$RT_ACTION" == run || "$RT_ACTION" == start ]] || return 1
    [[ "$RT_MODE" == dry-run ]] || rt_require_root || return 1
    rt_init || return 1
    RT_RUN_DIR="$STATE_DIR/.run-$RT_RUN_ID"
    [[ -d "$RT_RUN_DIR" && "$(readlink "/proc/$BASHPID/fd/8")" == "$STATE_DIR/.lock" ]] || return 1
    if rt_metrics_init; then RT_METRICS_ENABLED=1
    else RT_METRICS_ENABLED=0; log_warn "扫描耗时指标初始化失败，继续扫描"; fi
    rt_phase starting || return 1
    local uuid
    IFS= read -r uuid < "$STATE_DIR/.instance-id" || return 1
    export RT_OWNER="swiftban:$uuid"
    rt_proc "$BASHPID" || return 1
    [[ "${RT_PROC[2]}" == "$BASHPID" && "${RT_PROC[3]}" == "$BASHPID" ]] || return 1
    local boot ticks="${RT_PROC[19]}" i code
    IFS= read -r boot < /proc/sys/kernel/random/boot_id || return 1
    rt_record "$RT_RUN_DIR/ready" "$RT_RUN_ID" "$BASHPID" "$BASHPID" "$BASHPID" \
        "$ticks" "$boot" "$RT_MODE" "$(date -u +%s)" "$RT_ACTION" "$FIREWALL_CHAIN" || return 1
    for ((i=0;i<100;i++)); do
        [[ -f "$RT_RUN_DIR/go" ]] && break
        sleep 0.1
    done
    [[ -f "$RT_RUN_DIR/go" ]] || return 1
    if [[ "$RT_ACTION" == start ]] && ! rt_start_restore; then return 1; fi
    if [[ "$RT_MODE" == formal ]]; then
        rt_may_enforce || return 1
        if det_run 0; then code=0; else code=$?; fi
    else
        if det_run 1; then code=0; else code=$?; fi
    fi
    local finished_epoch finished_cs
    finished_epoch=$(date -u +%s) || return 1
    if rt_clock_cs; then finished_cs="$REPLY"; else finished_cs=0; fi
    rt_record "$RT_RUN_DIR/result" "$code" "$finished_epoch" "$finished_cs" || return 1
    return "$code"
}

rt_execute() (
    local mode="$1" action="$2" id child dir code i state
    set +m
    [[ "$mode" == dry-run ]] || rt_require_root || return 1
    rt_init || return 1
    rt_control_lock || return 1
    if [[ "$action" == run && "$mode" == formal && -e "$STATE_DIR/stopped.tsv" ]]; then
        log_info "正式检测已停止，跳过本次；使用 swiftban start 恢复"
        return 0
    fi
    exec 8> "$STATE_DIR/.lock" || return 1
    if ! flock -n 8; then
        log_info "已有扫描或状态操作在执行，跳过本次"
        [[ "$action" == run ]]
        return
    fi
    if rt_read_active; then
        if rt_group_state; then
            log_error "上次扫描仍有存活会话成员，请先执行 stop"
            return 1
        fi
        # 上一协调进程异常退出，但锁已释放；将其标为失败，而非沿用运行中状态。
        if ! rt_metrics_publish "$RT_ID" "$RT_MODE" interrupted "$RT_STARTED"; then
            log_warn "上次扫描的部分耗时指标无法保存"
        fi
        rt_last interrupted 1 || return 1
        rt_cleanup_run "$RT_ID" || return 1
        rm -rf "$STATE_DIR/.run-$RT_ID"
        rm -f "$STATE_DIR/active.tsv"
    fi
    IFS= read -r id < /proc/sys/kernel/random/uuid || return 1
    if [[ "$action" == start ]]; then
        if [[ -e "$STATE_DIR/stopped.tsv" ]]; then
            IFS=$'\t' read -r state _ < "$STATE_DIR/stopped.tsv" || return 1
            [[ "$state" == stopped ]] || { log_error "停止尚未完成，请先重试 stop"; return 1; }
        fi
        rt_record "$STATE_DIR/stopped.tsv" starting "$id" || return 1
    fi
    dir="$STATE_DIR/.run-$id"
    mkdir "$dir" || return 1
    (
        exec 9>&-
        exec setsid bash "$SWIFTBAN_ENTRY" __worker "$id" "$mode" "$action"
    ) &
    child=$!
    # 此后只有工作会话及其子进程持有扫描锁，stop 无需等待父进程的收尾锁。
    exec 8>&-
    for ((i=0;i<50;i++)); do
        [[ -f "$dir/ready" ]] && break
        kill -0 "$child" 2>/dev/null || break
        sleep 0.1
    done
    if [[ ! -f "$dir/ready" ]]; then
        kill -TERM "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
        log_error "工作进程登记失败，未开始扫描"
        [[ "$action" != start ]] || rt_record "$STATE_DIR/stopped.tsv" stopped "$id"
        rm -rf "$dir"
        return 1
    fi
    cp "$dir/ready" "$STATE_DIR/.active-$id" &&
        mv "$STATE_DIR/.active-$id" "$STATE_DIR/active.tsv" || return 1
    if ! rt_read_active || [[ "$RT_ID" != "$id" || "$RT_PID" != "$child" ]] || ! rt_group_state; then
        kill -TERM "$child" 2>/dev/null || true
        exec 9>&-
        wait "$child" 2>/dev/null || true
        log_error "工作进程身份校验失败"
        return 1
    fi
    rt_record "$dir/go" go || return 1
    exec 9>&-
    trap 'if rt_group_state; then kill -TERM -- "-$RT_PGID" 2>/dev/null || true; fi' INT TERM
    if wait "$child"; then code=0; else code=$?; fi
    trap - INT TERM
    if rt_group_state && ! rt_terminate_group; then
        log_error "扫描退出后仍有子进程，保留运行记录等待 stop 清理"
        return 1
    fi
    rt_finish "$id" "$code" || code=1
    [[ ! -f "$dir/cancelled" ]] || code=0
    rt_cleanup_run "$id" || code=1
    rm -rf "$dir"
    return "$code"
)

rt_stop() (
    local group_code=1 failed=0 id="" exit_code result busy=0 mode="" started=""
    rt_require_root && rt_init && rt_control_lock || return 1
    rt_record "$STATE_DIR/stopped.tsv" stopping - || return 1
    if rt_scan_busy; then busy=1; fi
    if rt_read_active; then
        id="$RT_ID"
        mode="$RT_MODE"
        started="$RT_STARTED"
        if rt_group_state; then group_code=0; else group_code=$?; fi
        if (( group_code == 2 )); then
            log_error "进程身份不一致，拒绝发送信号"
            rt_record "$STATE_DIR/stopped.tsv" cleanup_failed "$id"
            return 1
        fi
        if ! rt_terminate_group; then failed=1; fi
    elif (( busy )); then
        log_error "扫描锁被占用但无法确认进程身份，拒绝误杀；已阻止后续正式检测"
        rt_record "$STATE_DIR/stopped.tsv" cleanup_failed -
        return 1
    fi
    exec 8> "$STATE_DIR/.lock" || return 1
    if (( failed )) || ! flock -w 5 8; then
        log_error "当前扫描尚未完全退出，停止未完成"
        rt_record "$STATE_DIR/stopped.tsv" cleanup_failed "$id"
        return 1
    fi
    if [[ -n "$id" ]]; then
        if [[ -r "$STATE_DIR/.run-$id/result" ]]; then
            IFS=$'\t' read -r exit_code _ < "$STATE_DIR/.run-$id/result" || return 1
            result=completed
            [[ "$exit_code" == 0 ]] || result=failed
        elif [[ -d "$STATE_DIR/.run-$id" ]]; then
            rt_record "$STATE_DIR/.run-$id/cancelled" cancelled || return 1
            result=stopped; exit_code=0
        else
            result=interrupted; exit_code=1
        fi
        if [[ -n "$mode" && -n "$started" ]] && ! rt_metrics_publish "$id" "$mode" "$result" "$started"; then
            log_warn "停止时的部分耗时指标保存失败"
        fi
        rt_last "$result" "$exit_code" || return 1
        rm -f "$STATE_DIR/active.tsv"
        rt_cleanup_run "$id" || return 1
        rm -rf "$STATE_DIR/.run-$id"
    fi
    if ! fw_remove_managed; then
        rt_record "$STATE_DIR/stopped.tsv" cleanup_failed "$id"
        log_error "检测已停止，但存在未撤销或无法确认的规则；请重试 stop"
        return 1
    fi
    rt_record "$STATE_DIR/stopped.tsv" stopped - || return 1
    log_action "STOP 已停止扫描并撤销管理的规则，保留 banlist 和原 TTL"
)

rt_mutate() (
    local action="$1"
    shift
    rt_require_root && rt_init && rt_control_lock || return 1
    if [[ "$action" == ban && -e "$STATE_DIR/stopped.tsv" ]]; then
        log_error "正式检测已停止，不允许手动封禁；使用 start 恢复"
        return 1
    fi
    exec 8> "$STATE_DIR/.lock" || return 1
    if ! flock -n 8; then
        log_info "扫描正在执行，等待完成后修改状态（最多 60 秒）"
        flock -w 60 8 || { log_error "等待扫描结束超时，请稍后重试状态修改"; return 1; }
    fi
    "$@"
)

# cron 使用 /bin/sh，路径采用 POSIX 单引号；拒绝 cron 会额外解释的百分号。
rt_cron_quote() {
    local value="$1" escaped="'\\''"
    [[ "$value" != *%* && ! "$value" =~ [[:cntrl:]] ]] || return 1
    printf "'"
    while [[ "$value" == *"'"* ]]; do
        printf '%s%s' "${value%%\'*}" "$escaped"
        value="${value#*\'}"
    done
    printf "%s'" "$value"
}

rt_cron_line() {
    local entry conf output config="$2" state="$3"
    if [[ -f "$config" ]]; then
        config="$(cd "$(dirname "$config")" && pwd -P)/$(basename "$config")" || return 1
    fi
    if [[ -d "$state" ]]; then state=$(cd "$state" && pwd -P) || return 1; fi
    entry=$(rt_cron_quote "$1") && conf=$(rt_cron_quote "$config") &&
        output=$(rt_cron_quote "$state/cron.log") || return 1
    printf '* * * * * SWIFTBAN_CONF=%s %s run >> %s 2>&1' "$conf" "$entry" "$output"
}

# 安装器与 CLI 共用：构造完整文件后才提交，任何读取/生成错误均保留原任务。
rt_install_cron() (
    local entry="$1" conf="$2" state="$3" work read_code line value
    for value in "$entry" "$conf" "$state"; do
        [[ "$value" != *%* && ! "$value" =~ [[:cntrl:]] ]] || {
            printf '错误: cron 路径不能包含百分号或控制字符\n' >&2; return 1;
        }
    done
    [[ "$entry" == /* && -f "$conf" && -d "$state" ]] || {
        printf '错误: cron 需要绝对入口路径、已存在的配置文件和状态目录\n' >&2; return 1;
    }
    conf="$(cd "$(dirname "$conf")" && pwd -P)/$(basename "$conf")" || return 1
    state=$(cd "$state" && pwd -P) || return 1
    line=$(rt_cron_line "$entry" "$conf" "$state") || {
        printf '错误: cron 路径不能包含百分号或控制字符\n' >&2; return 1;
    }
    work=$(mktemp -d) || return 1
    trap 'rm -rf "$work"' EXIT
    if LC_ALL=C crontab -l > "$work/current" 2> "$work/error"; then :
    else
        read_code=$?
        if [[ "$read_code" != 1 ]] || ! grep -q '^no crontab for ' "$work/error"; then
            printf '错误: 无法读取现有 cron，未修改定时任务\n' >&2
            cat "$work/error" >&2
            return 1
        fi
        : > "$work/current" || return 1
    fi
    if ! SWIFTBAN_CRONLINE="$line" SWIFTBAN_CRONCONF="$conf" SWIFTBAN_CRONENTRY="$entry" awk '
        /^[[:space:]]*#/ {print;next}
        $0==ENVIRON["SWIFTBAN_CRONLINE"] {next}
        ENVIRON["SWIFTBAN_CRONCONF"]=="/etc/swiftban/swiftban.conf" &&
            $6==ENVIRON["SWIFTBAN_CRONENTRY"] && $7=="run" {next}
        {print}
    ' "$work/current" > "$work/next" ||
        ! printf '%s\n' "$line" >> "$work/next"; then
        printf '错误: 生成 cron 失败，未修改定时任务\n' >&2
        return 1
    fi
    if ! crontab "$work/next"; then printf '错误: cron 安装失败\n' >&2; return 1; fi
    printf 'cron 已安装: %s\n' "$line"
)

rt_mode_text() {
    case "$1" in formal) printf 'formal（正式）' ;; dry-run) printf 'dry-run（演练）' ;; *) printf '未知模式' ;; esac
}

rt_time_text() {
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        date -u -d "@$1" '+%F %T UTC' 2>/dev/null || printf '%s' "$1"
    else printf '未知'; fi
}

rt_seconds_text() {
    local centiseconds="$1"
    [[ "$centiseconds" =~ ^[0-9]+$ ]] || { printf '?'; return; }
    printf '%d.%02d' "$((centiseconds/100))" "$((centiseconds%100))"
}

rt_metrics_status() {
    local run_id="$1" file summary
    if ! file=$(rt_metrics_path "$run_id" 2>/dev/null); then
        printf '最近扫描耗时: 无指标记录（旧版本运行或记录保存失败）\n'
        return 0
    fi
    summary=$(awk -F '\t' '
        $1=="M" {mode=$4; result=$5; duration=$8}
        $1=="C" {v[$2]=$3}
        END {
            printf "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d",mode,result,duration,
                v["files"],v["bytes_read"],v["lines_read"],v["valid"],v["invalid"],v["window_events"],v["candidates"],
                (v["files"]!="" ? 1 : 0)
        }
    ' "$file") || { printf '最近扫描耗时: 指标记录无法读取\n'; return 0; }
    local mode result duration files bytes lines valid invalid events candidates has_counts
    IFS=$'\t' read -r mode result duration files bytes lines valid invalid events candidates has_counts <<< "$summary"
    [[ "$duration" =~ ^[0-9]+$ ]] || { printf '最近扫描耗时: 指标记录格式无效\n'; return 0; }
    if [[ "$has_counts" != 1 ]]; then
        printf '最近扫描耗时: %ss | 结果=%s | 处理量未完整统计\n' "$(rt_seconds_text "$duration")" "$result"
        return 0
    fi
    printf '最近扫描耗时: %ss | 结果=%s | 文件=%s | 读取=%s字节/%s行 | 有效=%s 格式错误=%s | 窗口事件=%s 候选=%s\n' \
        "$(rt_seconds_text "$duration")" "$result" "${files:-0}" "${bytes:-0}" "${lines:-0}" \
        "${valid:-0}" "${invalid:-0}" "${events:-0}" "${candidates:-0}"
}

rt_show_status() {
    local state=- id mode started finished result code phase=unknown cnt records=0 stale=0 label
    local phase_name phase_tick now_cs phase_elapsed
    if [[ -d "$STATE_DIR" && ( ! -r "$STATE_DIR" || ! -x "$STATE_DIR" ) ]]; then
        echo "控制及执行状态: 无法读取状态目录（权限不足）"
        return 0
    fi
    if [[ -e "$STATE_DIR/stopped.tsv" ]]; then
        if IFS=$'\t' read -r state _ < "$STATE_DIR/stopped.tsv"; then
            case "$state" in
                stopped) label=已停止 ;;
                starting) label=正在恢复 ;;
                stopping) label=正在停止 ;;
                cleanup_failed) label=停止未完成 ;;
                *) label=状态无法识别 ;;
            esac
            echo "控制状态: $label（$state；正式定时检测跳过，显式演练仍允许）"
        else echo "控制状态: 无法读取（权限不足或状态损坏）"; fi
    else echo "控制状态: 启用"; fi
    if command -v flock >/dev/null 2>&1 && [[ -r "$STATE_DIR/.lock" ]]; then
        if rt_scan_busy; then
            if rt_read_active && rt_group_state; then
                [[ ! -r "$STATE_DIR/.run-$RT_ID/phase" ]] ||
                    IFS= read -r phase < "$STATE_DIR/.run-$RT_ID/phase"
                if IFS=$'\t' read -r phase_name phase_tick _ < "$STATE_DIR/.run-$RT_ID/phase-clock" 2>/dev/null &&
                    [[ "$phase_name" == "$phase" && "$phase_tick" =~ ^[0-9]+$ ]] && rt_clock_cs; then
                    now_cs="$REPLY"; phase_elapsed=$((now_cs-phase_tick)); (( phase_elapsed >= 0 )) || phase_elapsed=0
                    echo "当前执行: $(rt_mode_text "$RT_MODE") | PID=$RT_PID | 开始=$(rt_time_text "$RT_STARTED") | 阶段=$phase（已运行 $(rt_seconds_text "$phase_elapsed")s） | 链=$RT_CHAIN"
                else
                    echo "当前执行: $(rt_mode_text "$RT_MODE") | PID=$RT_PID | 开始=$(rt_time_text "$RT_STARTED") | 阶段=$phase | 链=$RT_CHAIN"
                fi
            else echo "当前执行: 锁被占用，进程信息无法确认"; fi
        else
            local lock_code=$?
            if (( lock_code == 1 )); then
                echo "当前执行: 空闲"
                if rt_read_active; then stale=1; fi
            else echo "当前执行: 无法查询运行锁"; fi
        fi
    else echo "当前执行: 无可读运行锁（未运行或权限不足）"; fi
    if (( stale )); then
        echo "最近执行: $(rt_mode_text "$RT_MODE") | 开始=$(rt_time_text "$RT_STARTED") | 结果=记录未收尾，完成情况未知"
    elif [[ -r "$STATE_DIR/last-run.tsv" ]] &&
        IFS=$'\t' read -r id mode started finished result code < "$STATE_DIR/last-run.tsv"; then
        echo "最近执行: $(rt_mode_text "$mode") | 开始=$(rt_time_text "$started") | 结束=$(rt_time_text "$finished") | 结果=$result | 退出码=$code"
        rt_metrics_status "$id"
    else echo "最近执行: 无可读记录"; fi
    if [[ -r "$BANLIST" ]]; then records=$(wc -l < "$BANLIST"); fi
    watch_summary
    echo "保存的封禁记录: $records（停止时待恢复；过期记录在 start 时清理）"
    if cnt=$(fw_managed_count); then echo "实际管理的规则: $cnt"; else echo "实际管理的规则: 无法确认"; fi
    if [[ -r "$STATE_DIR/dry-run.tsv" ]]; then
        echo "演练结果: $STATE_DIR/dry-run.tsv（最近一次完整结果，使用 list --dry-run 查看）"
        awk -F '\t' '
            /^# run_id\t/ {print "演练运行: " $2}
            /^# started_utc\t/ {print "演练开始: " $2}
            /^# finished_utc\t/ {print "演练结束: " $2}
            /^# file_mtime_filter\t/ {print "文件筛选: 最近3分钟修改"}
            /^# entry_window_seconds\t/ {print "日志时间窗口: " $2 " 秒"}
            /^# thresholds\t/ {print "阈值摘要: " $2}
            /^# file\t/ {files++}
            /^# parse\t/ {valid+=$3; invalid+=$4}
            /^IP\t/ {next}
            /^[^#]/ && NF>=4 {candidates++}
            END {printf "来源文件: %d | 有效日志: %d | 格式错误: %d | 候选: %d\n",files,valid,invalid,candidates}
        ' "$STATE_DIR/dry-run.tsv"
    else echo "演练结果: 无可读的完整结果"; fi
}

rt_cron_mode() {
    local line="$1" i=7 mode=正式 word expected
    if expected=$(rt_cron_line "$SWIFTBAN_ENTRY" "$SWIFTBAN_CONF" "$STATE_DIR") &&
        [[ "$line" == "$expected" ]]; then echo "正式"; return; fi
    local -a words
    read -r -a words <<< "$line"
    if (( ${#words[@]} < 7 )) ||
        [[ "${words[5]##*/}" != swiftban && "${words[5]##*/}" != swiftban.sh ]] ||
        [[ "${words[6]}" != run ]]; then echo "无法可靠确认复杂命令"; return; fi
    if [[ "${words[7]:-}" == --dry-run ]]; then mode=演练; i=8; fi
    while (( i < ${#words[@]} )); do
        word="${words[i]}"
        case "$word" in
            '>'|'>>')
                i=$((i+1))
                [[ "${words[i]:-}" =~ ^[/A-Za-z0-9_.-]+$ ]] || { echo "无法可靠确认复杂命令"; return; } ;;
            '2>&1') ;;
            *) echo "无法可靠确认复杂命令"; return ;;
        esac
        i=$((i+1))
    done
    echo "$mode"
}

rt_show_schedule() {
    local text line found=0 match
    echo "=== 定时任务配置（当前用户 cron / 标准 swiftban.timer）==="
    if command -v crontab >/dev/null 2>&1; then
        if text=$(crontab -l 2>&1); then
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                match="${line//\'/}"
                if [[ "$match" =~ (^|[[:space:]/])swiftban(\.sh)?[[:space:]]+run([[:space:]]|$) ]]; then
                    found=1
                    echo "cron: $line"
                    echo "cron 推断模式: $(rt_cron_mode "$line")（以原始命令为准）"
                fi
            done <<< "$text"
            (( found )) || echo "cron: 未发现可识别的 SwiftBan 任务"
        else echo "cron: 无法读取（可能未配置或权限不足）"; fi
    else echo "cron: 工具不存在，无法确认"; fi
    if command -v systemctl >/dev/null 2>&1; then
        if text=$(systemctl show swiftban.timer -p LoadState -p ActiveState -p UnitFileState 2>/dev/null); then
            printf 'systemd timer:\n%s\n' "$text"
            if text=$(systemctl show swiftban.service -p ExecStart 2>/dev/null); then
                printf '%s\n' "$text"
                case "$text" in
                    *"path=/usr/local/bin/swiftban ;"*"argv[]=/usr/local/bin/swiftban run --dry-run ;"*) echo "systemd 推断模式: 演练" ;;
                    *"path=/usr/local/bin/swiftban ;"*"argv[]=/usr/local/bin/swiftban run ;"*) echo "systemd 推断模式: 正式" ;;
                    *) echo "systemd 推断模式: 无法可靠确认自定义命令" ;;
                esac
            else echo "systemd 命令: 无法读取"; fi
        else echo "systemd: 无法查询标准单元"; fi
    else echo "systemd: 工具不存在，无法确认"; fi
}

rt_list_dry() {
    echo "=== 最近一次完整演练及复核信息（演练未实际封禁）==="
    if [[ -r "$STATE_DIR/dry-run.tsv" ]]; then
        cat "$STATE_DIR/dry-run.tsv"
    else
        echo "尚无可读的完整演练结果"
    fi
}

rt_metrics_doctor() (
    local root="$STATE_DIR/scan/metrics" tmp file mode result duration
    local id metric count cutoff daydir invalid=0 state_cursors state_events
    local -a files durations daydirs
    printf '\n=== 扫描耗时与增量状态诊断 ===\n'
    cutoff=$(date -u -d "@$(($(date -u +%s)-30*86400))" '+%F') || return 1
    if [[ -d "$STATE_DIR/scan" && "$(stat -c '%a' "$STATE_DIR/scan" 2>/dev/null)" != 700 ]]; then
        printf '失败 扫描状态目录权限不是 0700: %s\n' "$STATE_DIR/scan"; invalid=1
    fi
    if [[ ! -d "$root" ]]; then
        printf '提示 尚无扫描指标记录\n'
        if [[ -e "$STATE_DIR/scan/state.tsv" ]]; then
            tmp=$(mktemp) || return 1
            if det_scan_validate_state "$STATE_DIR/scan/state.tsv" "$tmp"; then
                IFS=$'\t' read -r _ state_cursors state_events < "$tmp"
                printf '扫描快照: 游标=%s 窗口事件=%s | 大小=%s字节\n' \
                    "$state_cursors" "$state_events" "$(wc -c < "$STATE_DIR/scan/state.tsv" | tr -d ' ')"
            else printf '失败 扫描快照结构损坏，保留现场: %s\n' "$STATE_DIR/scan/state.tsv"; invalid=1; fi
            [[ "$(stat -c '%a' "$STATE_DIR/scan/state.tsv" 2>/dev/null)" == 600 ]] || {
                printf '失败 扫描快照权限不是 0600: %s\n' "$STATE_DIR/scan/state.tsv"; invalid=1;
            }
            rm -f "$tmp"
        else printf '提示 尚无增量扫描快照\n'; fi
        (( invalid == 0 ))
        return $?
    fi
    [[ -r "$root" && -x "$root" ]] || { printf '失败 扫描指标目录不可读取: %s\n' "$root"; return 1; }
    [[ "$(stat -c '%a' "$root" 2>/dev/null)" == 700 ]] || {
        printf '失败 扫描指标目录权限不是 0700: %s\n' "$root"; invalid=1;
    }
    shopt -s nullglob
    for daydir in "$root"/????-??-??; do daydirs+=("$daydir"); done
    shopt -u nullglob
    for daydir in "${daydirs[@]}"; do
        if [[ "${daydir##*/}" < "$cutoff" ]]; then
            printf '警告 超出30天的指标目录待清理: %s（下次扫描发布时清理）\n' "$daydir"
            continue
        fi
        shopt -s nullglob
        files+=("$daydir"/*.tsv)
        shopt -u nullglob
    done
    if (( ${#files[@]} == 0 )); then printf '提示 尚无扫描指标记录\n'; fi
    tmp=$(mktemp -d) || { printf '失败 无法创建诊断临时目录\n'; return 1; }
    trap 'rm -rf "$tmp"' EXIT
    : > "$tmp/all.tsv" || return 1
    for file in "${files[@]}"; do
        if [[ "$(stat -c '%a' "$file" 2>/dev/null)" != 600 ]]; then
            printf '失败 指标文件权限不是 0600: %s\n' "$file"; invalid=1
        fi
        [[ "$(stat -c '%a' "${file%/*}" 2>/dev/null)" == 700 ]] || {
            printf '失败 指标日期目录权限不是 0700: %s\n' "${file%/*}"; invalid=1;
        }
        printf '#FILE\n' >> "$tmp/all.tsv" || return 1
        cat "$file" >> "$tmp/all.tsv" || { printf '失败 无法读取指标文件: %s\n' "$file"; invalid=1; }
    done
    if (( ${#files[@]} > 0 )); then
        if ! awk -F '\t' '
            $0=="#FILE" {if(infile && m!=1) bad=1; infile=1; header=0; m=0; next}
            !header {if($0!="# swiftban-scan-metrics-v1") bad=1; header=1; next}
            $1=="M" {
                if(NF!=9 || $2!="1" || $3!~/^[0-9a-f-]{36}$/ ||
                   ($4!="formal" && $4!="dry-run") ||
                   ($5!="completed" && $5!="failed" && $5!="interrupted" && $5!="stopped") ||
                   $6!~/^[0-9]+$/ || $7!~/^[0-9]+$/ || $8!~/^[0-9]+$/ || $9=="" || ++m!=1) bad=1
                next
            }
            $1=="P" {if(NF!=3 || $2!~/^[a-z-]+$/ || $3!~/^[0-9]+$/) bad=1; next}
            $1=="C" {if(NF!=3 || $2!~/^[a-z_]+$/ || $3!~/^[0-9]+$/) bad=1; next}
            $1=="F" {if(NF!=5 || $2=="" || $3!~/^[0-9]+$/ || $4!~/^[0-9]+$/ || $5!~/^[0-9]+$/) bad=1; next}
            {bad=1}
            END {if(!infile || m!=1) bad=1; exit bad}
        ' "$tmp/all.tsv"; then
            printf '失败 最近30天存在格式损坏的扫描指标\n'; invalid=1
        fi
        awk -F '\t' '$1=="M" {n++; if($5=="completed")ok++; else if($5=="failed")failed++; else if($5=="interrupted" || $5=="stopped")interrupted++}
            END {printf "30天扫描记录: %d | 成功=%d 失败=%d 中断/停止=%d\n",n,ok,failed,interrupted}' \
            "$tmp/all.tsv"
        mapfile -t durations < <(awk -F '\t' '$1=="M" && $8~/^[0-9]+$/ {print $8}' "$tmp/all.tsv" | LC_ALL=C sort -n)
        count=${#durations[@]}
        if (( count > 0 )); then
            local p50 p95
            p50=$(((count-1)/2)); p95=$(((count*95+99)/100-1))
            printf '总耗时分位数: P50=%ss P95=%ss（百分之一秒精度）\n' \
                "$(rt_seconds_text "${durations[p50]}")" "$(rt_seconds_text "${durations[p95]}")"
        fi
    fi
    if [[ -r "$STATE_DIR/last-run.tsv" ]] && IFS=$'\t' read -r id mode _ _ result duration < "$STATE_DIR/last-run.tsv"; then
        if metric=$(rt_metrics_path "$id" 2>/dev/null); then
            printf '最近扫描阶段耗时（百分之一秒精度）:\n'
            awk -F '\t' '$1=="P" {printf "  %-12s %.2fs\n",$2,$3/100}' "$metric"
            printf '最近扫描最慢文件（采集耗时）:\n'
            awk -F '\t' '$1=="F" {printf "  %s | %.2fs | %s字节 | %s行\n",$2,$3/100,$4,$5}' "$metric"
        else printf '最近一次执行无兼容耗时指标（旧版运行或记录未保存）\n'; fi
    fi
    if [[ -e "$STATE_DIR/scan/state.tsv" ]]; then
        if ! det_scan_validate_state "$STATE_DIR/scan/state.tsv" "$tmp/state-counts"; then
            printf '失败 扫描快照结构损坏；已保留现场，避免推进日志游标: %s\n' "$STATE_DIR/scan/state.tsv"
            invalid=1
        else
            IFS=$'\t' read -r _ state_cursors state_events < "$tmp/state-counts"
            printf '扫描快照: 游标=%s 窗口事件=%s | 大小=%s字节\n' \
                "$state_cursors" "$state_events" "$(wc -c < "$STATE_DIR/scan/state.tsv" | tr -d ' ')"
            [[ "$(stat -c '%a' "$STATE_DIR/scan/state.tsv" 2>/dev/null)" == 600 ]] || {
                printf '失败 扫描快照权限不是 0600: %s\n' "$STATE_DIR/scan/state.tsv"; invalid=1;
            }
        fi
    else printf '提示 尚无增量扫描快照\n'; fi
    (( invalid == 0 ))
)

rt_doctor() {
    local failures=0 warnings=0 name state_count=0 v4_rules v6_rules expected cron_text line found_cron=0 found_timer=0
    local -a deps=(iptables awk grep find stat sort flock setsid)
    printf 'SwiftBan 运维诊断 v%s\n' "$SWIFTBAN_VERSION"
    for name in "${deps[@]}"; do
        if command -v "$name" >/dev/null 2>&1; then printf '通过 依赖: %s\n' "$name"
        else printf '失败 缺少命令: %s\n  修复: 安装 %s 后重试\n' "$name" "$name"; failures=$((failures+1)); fi
    done
    if command -v ip6tables >/dev/null 2>&1; then
        printf '通过 可选依赖: ip6tables\n'
    else printf '警告 可选依赖 ip6tables 不存在，IPv6 自动封禁不可用\n'; warnings=$((warnings+1)); fi

    if det_check_config && wl_check_config; then printf '通过 配置值与白名单\n'
    else printf '失败 配置值或白名单无效\n  修复: sudo swiftban configtest 并按错误提示修改 %s\n' "$SWIFTBAN_CONF"; failures=$((failures+1)); fi
    if [[ -d "$LOG_DIR" && -r "$LOG_DIR" && -x "$LOG_DIR" ]]; then printf '通过 日志目录可读取: %s\n' "$LOG_DIR"
    else printf '失败 日志目录不存在或不可读取: %s\n  修复: 检查 LOG_DIR 和运行用户权限\n' "$LOG_DIR"; failures=$((failures+1)); fi
    if [[ -d "$STATE_DIR" && -r "$STATE_DIR" && -w "$STATE_DIR" && -x "$STATE_DIR" ]]; then printf '通过 状态目录可读写: %s\n' "$STATE_DIR"
    else printf '失败 状态目录不存在或不可读写: %s\n  修复: 创建 STATE_DIR 并授权 SwiftBan 运行用户读写\n' "$STATE_DIR"; failures=$((failures+1)); fi
    watch_doctor || failures=$((failures+1))
    geo_doctor || failures=$((failures+1))
    rt_metrics_doctor || failures=$((failures+1))
    if (( EUID == 0 )); then printf '通过 当前用户为 root\n'
    else printf '警告 当前用户不是 root，防火墙及进程控制检查可能无法完成\n'; warnings=$((warnings+1)); fi

    if [[ -r "$STATE_DIR/banlist.txt" ]]; then
        state_count=$(awk 'END {print NR+0}' "$STATE_DIR/banlist.txt")
        if awk -F'|' 'NF!=4 || $1=="" || $2!~/^[0-9]+$/ || $3!~/^[0-9]+$/ {bad=1} END {exit bad}' "$STATE_DIR/banlist.txt"; then
            printf '通过 banlist 格式（%s 条）\n' "$state_count"
        else printf '失败 banlist 含有无效记录\n  修复: 备份后检查 %s/banlist.txt 中 IP|时间戳|TTL|原因 四字段记录\n' "$STATE_DIR"; failures=$((failures+1)); fi
    else printf '失败 banlist 不存在或不可读取\n  修复: 检查 STATE_DIR 权限；需要初始化时运行 sudo swiftban start\n'; failures=$((failures+1)); fi

    if command -v iptables >/dev/null 2>&1 && iptables -L "$FIREWALL_CHAIN" -n >/dev/null 2>&1; then
        printf '通过 IPv4 防火墙链可用: %s\n' "$FIREWALL_CHAIN"
        if fw_inventory iptables > /dev/null; then
            v4_rules=$(fw_inventory iptables | awk 'END {print NR+0}')
            printf '状态 IPv4 管理规则: %s；banlist 记录: %s\n' "$v4_rules" "$state_count"
            if [[ "$v4_rules" =~ ^[0-9]+$ && "$state_count" =~ ^[0-9]+$ ]] && (( v4_rules > state_count )); then
                printf '警告 IPv4 存在无对应 banlist 的已标记规则，stop 可清理本实例规则\n'; warnings=$((warnings+1))
            fi
        else printf '失败 无法读取 IPv4 管理规则清单\n  修复: 检查 root 权限、iptables -S 和链配置\n'; failures=$((failures+1)); fi
    else printf '失败 IPv4 防火墙链不可用: %s\n  修复: 确认链已创建；裸机 Nginx 通常设置 FIREWALL_CHAIN="INPUT"\n' "$FIREWALL_CHAIN"; failures=$((failures+1)); fi
    if command -v ip6tables >/dev/null 2>&1; then
        if fw_ipv6_chain_available; then
            if fw_inventory ip6tables >/dev/null; then
                v6_rules=$(fw_inventory ip6tables | awk 'END {print NR+0}')
                printf '通过 IPv6 防火墙链可用: %s（管理规则 %s）\n' "$FIREWALL_CHAIN" "$v6_rules"
            else printf '警告 无法读取 IPv6 管理规则，IPv6 操作将跳过\n'; warnings=$((warnings+1)); fi
        else printf '警告 IPv6 防火墙链不可用或权限不足，IPv6 操作将跳过；IPv4 不受影响\n'; warnings=$((warnings+1)); fi
    elif fw_needs_ipv6; then printf '警告 banlist 含 IPv6 记录但 ip6tables 缺失，保留记录并跳过 IPv6；如需管理 IPv6 规则请安装 ip6tables\n'; warnings=$((warnings+1)); fi

    if [[ -e "$STATE_DIR/stopped.tsv" ]]; then
        IFS=$'\t' read -r state _ < "$STATE_DIR/stopped.tsv" || state=invalid
        case "$state" in
            stopped) printf '警告 正式检测当前已停止；需要恢复时运行 sudo swiftban start\n'; warnings=$((warnings+1)) ;;
            cleanup_failed) printf '失败 上次 stop 未完成；修复防火墙后运行 sudo swiftban stop\n'; failures=$((failures+1)) ;;
            stopping|starting) printf '警告 当前控制状态为 %s；用 sudo swiftban status 确认\n' "$state"; warnings=$((warnings+1)) ;;
            *) printf '失败 无法识别停止状态文件\n  修复: 检查 %s/stopped.tsv\n' "$STATE_DIR"; failures=$((failures+1)) ;;
        esac
    fi
    if [[ -e "$STATE_DIR/active.tsv" ]]; then
        if rt_read_active && rt_group_state; then printf '通过 扫描运行中: %s PID=%s 阶段=%s\n' "$(rt_mode_text "$RT_MODE")" "$RT_PID" "$(cat "$STATE_DIR/.run-$RT_ID/phase" 2>/dev/null || printf unknown)"
        elif rt_read_active; then printf '警告 存在已结束或不可验证的运行记录；查看 status，确认后执行 sudo swiftban stop\n'; warnings=$((warnings+1))
        else printf '失败 active.tsv 格式无效，停止操作前先备份状态目录\n'; failures=$((failures+1)); fi
    else printf '通过 无活动扫描记录\n'; fi

    if command -v crontab >/dev/null 2>&1; then
        if cron_text=$(crontab -l 2>/dev/null); then
            while IFS= read -r line; do
                [[ "$line" == *swiftban* && "$line" == *run* ]] || continue
                found_cron=1
                expected=$(rt_cron_line "$SWIFTBAN_ENTRY" "$SWIFTBAN_CONF" "$STATE_DIR" 2>/dev/null || true)
                if [[ -n "$expected" && "$line" == "$expected" ]]; then printf '通过 cron 指向当前入口和配置: %s\n' "$line"
                else printf '警告 cron 命令可能使用不同入口或配置: %s\n  修复: sudo swiftban install-cron（保留其他任务）\n' "$line"; warnings=$((warnings+1)); fi
            done <<< "$cron_text"
            (( found_cron )) || printf '提示 当前用户未配置 SwiftBan cron\n'
        else printf '提示 当前用户没有可读取的 crontab\n'; fi
    else printf '提示 系统未安装 crontab\n'; fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl show swiftban.timer -p LoadState -p ActiveState -p UnitFileState >/dev/null 2>&1; then
            if [[ "$(systemctl show swiftban.timer -p LoadState --value 2>/dev/null)" == loaded ]]; then
                found_timer=1
                if systemctl is-active --quiet swiftban.timer; then printf '通过 标准 systemd timer 正在运行\n'
                else printf '警告 标准 systemd timer 已加载但未运行；运行 sudo systemctl enable --now swiftban.timer\n'; warnings=$((warnings+1)); fi
            fi
        fi
    fi
    if (( ! found_cron && ! found_timer )); then printf '警告 未发现 SwiftBan 定时任务\n  修复: 运行 sudo swiftban install-cron，或启用 deploy/ 中的 systemd timer\n'; warnings=$((warnings+1)); fi
    printf '诊断完成：失败=%s 警告=%s\n' "$failures" "$warnings"
    (( failures == 0 ))
}
