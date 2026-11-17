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
    rt_record "$RT_RUN_DIR/phase" "$1"
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
    rt_record "$RT_RUN_DIR/result" "$code" "$(date -u +%s)" || return 1
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
        rt_last interrupted 1 || return 1
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
    local group_code=1 failed=0 id="" exit_code result busy=0
    rt_require_root && rt_init && rt_control_lock || return 1
    rt_record "$STATE_DIR/stopped.tsv" stopping - || return 1
    if rt_scan_busy; then busy=1; fi
    if rt_read_active; then
        id="$RT_ID"
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
            rt_last "$result" "$exit_code" || return 1
        elif [[ -d "$STATE_DIR/.run-$id" ]]; then
            rt_record "$STATE_DIR/.run-$id/cancelled" cancelled || return 1
            rt_last stopped 0 || return 1
        else
            rt_last interrupted 1 || return 1
        fi
        rm -f "$STATE_DIR/active.tsv"
        rt_cleanup_run "$id" || return 1
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
    flock -n 8 || { log_error "扫描正在执行，请稍后重试状态修改"; return 1; }
    "$@"
)

rt_mode_text() {
    case "$1" in formal) printf 'formal（正式）' ;; dry-run) printf 'dry-run（演练）' ;; *) printf '未知模式' ;; esac
}

rt_time_text() {
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        date -u -d "@$1" '+%F %T UTC' 2>/dev/null || printf '%s' "$1"
    else printf '未知'; fi
}

rt_show_status() {
    local state=- id mode started finished result code phase=unknown cnt records=0 stale=0 label
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
                echo "当前执行: $(rt_mode_text "$RT_MODE") | PID=$RT_PID | 开始=$(rt_time_text "$RT_STARTED") | 阶段=$phase | 链=$RT_CHAIN"
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
    else echo "最近执行: 无可读记录"; fi
    if [[ -r "$BANLIST" ]]; then records=$(wc -l < "$BANLIST"); fi
    echo "保存的封禁记录: $records（停止时待恢复；过期记录在 start 时清理）"
    if cnt=$(fw_managed_count); then echo "实际管理的规则: $cnt"; else echo "实际管理的规则: 无法确认"; fi
    if [[ -r "$STATE_DIR/dry-run.tsv" ]]; then
        echo "演练结果: $STATE_DIR/dry-run.tsv（最近一次完整结果，使用 list --dry-run 查看）"
        head -n 4 "$STATE_DIR/dry-run.tsv"
    else echo "演练结果: 无可读的完整结果"; fi
}

rt_cron_mode() {
    local line="$1" i=7 mode=正式 word
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
    local text line found=0
    echo "=== 定时任务配置（当前用户 cron / 标准 swiftban.timer）==="
    if command -v crontab >/dev/null 2>&1; then
        if text=$(crontab -l 2>&1); then
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                if [[ "$line" =~ (^|[[:space:]/])swiftban(\.sh)?[[:space:]]+run([[:space:]]|$) ]]; then
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
    echo "=== 演练候选：只检测，未实际封禁 ==="
    if [[ -r "$STATE_DIR/dry-run.tsv" ]]; then
        cat "$STATE_DIR/dry-run.tsv"
    else
        echo "尚无可读的完整演练结果"
    fi
}
