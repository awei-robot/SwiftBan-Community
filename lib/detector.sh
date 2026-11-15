#!/bin/bash
#==============================================================
# SwiftBan - 检测引擎
# 11 个维度: 444扫描 / 404扫描 / 恶意路径 / 漏洞载荷 / 可疑UA
#           登录爆破 / 单接口高频 / 单接口速率 / 空UA / 高频观察
#==============================================================

#---------------- 状态管理 ----------------
_state_file() { echo "${STATE_DIR}/banlist.txt"; }
_banlog_file() { echo "${STATE_DIR}/ban.log"; }

# 封禁（规则写入成功才记录状态，避免 banlist 与防火墙不一致）
det_ban() {
    local ip="$1" reason="$2"
    # 白名单静默跳过
    if wl_is_whitelisted "$ip"; then
        return 0
    fi
    if fw_is_banned "$ip"; then
        return 0
    fi
    if ! fw_ban "$ip"; then
        return 1
    fi
    echo "${ip}|${NOW}|${BAN_TTL}|${reason}" >> "$(_state_file)"
    log_action "BAN $ip | ttl=${BAN_TTL}s | $reason"
}

# 恢复历史封禁（规则丢失后）
det_restore() {
    while IFS='|' read -r ip ts ttl reason; do
        [[ -z "$ip" ]] && continue
        if [[ "$ttl" != "0" ]] && (( NOW - ts > ttl )); then
            continue
        fi
        if ! fw_is_banned "$ip"; then
            if ! fw_ban "$ip"; then
                continue
            fi
            log_action "RESTORE $ip | $reason"
        fi
    done < "$(_state_file)"
}

# 过期解封
det_unban_expired() {
    local tmp
    tmp=$(mktemp)
    while IFS='|' read -r ip ts ttl reason; do
        [[ -z "$ip" ]] && continue
        if [[ "$ttl" != "0" ]] && (( NOW - ts > ttl )); then
            fw_unban "$ip"
            log_action "UNBAN(expired) $ip | $reason"
        else
            echo "${ip}|${ts}|${ttl}|${reason}" >> "$tmp"
        fi
    done < "$(_state_file)"
    mv "$tmp" "$(_state_file)"
}

#---------------- 时间过滤 ----------------
# 只保留最近 WINDOW 秒的日志条目（日志为 UTC）
det_time_filter() {
    local src="$1" dst="$2"
    TZ=UTC awk -v now="${NOW_EPOCH}" -v win="${WINDOW}" '
    BEGIN {
        m["Jan"]=1; m["Feb"]=2; m["Mar"]=3; m["Apr"]=4; m["May"]=5; m["Jun"]=6;
        m["Jul"]=7; m["Aug"]=8; m["Sep"]=9; m["Oct"]=10; m["Nov"]=11; m["Dec"]=12
    }
    {
        ts = substr($1, 2)
        split(ts, a, "/"); split(a[3], b, ":")
        ep = mktime(b[1] " " m[a[2]] " " a[1] " " b[2] " " b[3] " " b[4])
        if (now - ep <= win) print
    }' "$src" > "$dst" 2>/dev/null || true
}

#---------------- 主检测流程 ----------------
det_run() {
    local dry_run="${1:-0}"

    # awk 能力检查（时间过滤依赖 mktime，需 gawk/mawk >=1.3.4）
    if ! awk 'BEGIN{mktime("2026 11 12 00 00 00")}' 2>/dev/null; then
        log_error "当前 awk 不支持 mktime，请安装 gawk 或 mawk (>=1.3.4)"
        return 1
    fi

    local workdir
    workdir=$(mktemp -d)
    trap 'rm -rf "${workdir}"' RETURN

    mkdir -p "${STATE_DIR}"
    touch "$(_state_file)" "$(_banlog_file)"

    NOW=$(date +%s)
    NOW_EPOCH=$(date -u +%s)

    # 1. 收集窗口内日志
    find "${LOG_DIR}" -maxdepth 1 -name "*access.log" -mmin -120 > "${workdir}/files.txt" 2>/dev/null
    xargs -r -a "${workdir}/files.txt" cat 2>/dev/null > "${workdir}/all.log"

    # 2. 时间过滤
    det_time_filter "${workdir}/all.log" "${workdir}/recent.log"
    local lines
    lines=$(wc -l < "${workdir}/recent.log")

    # 3. 各维度统计
    det_detect_all "${workdir}"

    # 4. 封禁决策
    if [[ "$dry_run" != "1" ]]; then
        det_decide "${workdir}"
        det_restore
        det_unban_expired
    else
        log_info "[DRY-RUN] 跳过封禁决策"
        det_decide "${workdir}" "dry"
    fi

    local cnt
    cnt=$(fw_count)
    log_info "完成 | 窗口内 ${lines} 行 | 当前封禁 IPv4=${cnt%:*} IPv6=${cnt#*:}"
}

# 各维度统计
det_detect_all() {
    local wd="$1"
    local recent="${wd}/recent.log"

    # 通用 IP 提取
    local extract='grep -oE "\[Client [0-9a-fA-F:.]+\]" | sed "s/\[Client //;s/\]//"'

    # 1. 444 攻击
    cat "$recent" | awk '{st=($3!="-")?$3:$4; if(st=="444") {for(i=1;i<=NF;i++) if($i=="[Client") print $(i+1)}}' | tr -d ']' | sort | uniq -c | sort -rn > "${wd}/ip_444.txt"

    # 2. 404/400 扫描（排除 SAFE_PATH）
    cat "$recent" | grep -vE "${SAFE_PATH}" | awk '{st=($3!="-")?$3:$4; if(st=="404"||st=="400") {for(i=1;i<=NF;i++) if($i=="[Client") print $(i+1)}}' | tr -d ']' | sort | uniq -c | sort -rn > "${wd}/ip_scan.txt"

    # 3. 恶意路径/敏感文件
    cat "$recent" | grep -vE "${GIT_SAFE}" | grep -iE "${EVIL_PATH}" | eval "$extract" | sort | uniq -c | sort -rn > "${wd}/ip_evilpath.txt"

    # 4. 漏洞载荷
    cat "$recent" | grep -vE "git\.43tc\.cn|${GIT_SAFE}" | grep -iE "${EVIL_PAYLOAD}" | eval "$extract" | sort | uniq -c | sort -rn > "${wd}/ip_payload.txt"

    # 5. 可疑 UA
    cat "$recent" | grep -iE "${EVIL_UA}" | eval "$extract" | sort | uniq -c | sort -rn > "${wd}/ip_ua.txt"

    # 6. 登录爆破（登录路径 401/403）
    cat "$recent" | grep -iE "${LOGIN_PATH}" | awk '{st=($3!="-")?$3:$4; if(st=="401"||st=="403") {for(i=1;i<=NF;i++) if($i=="[Client") print $(i+1)}}' | tr -d ']' | sort | uniq -c | sort -rn > "${wd}/ip_auth.txt"

    # 7. 单接口高频（总量）
    cat "$recent" | awk '{for(i=1;i<=NF;i++) if($i=="[Client") {ip=$(i+1); gsub(/\]/,"",ip); print ip" "$10}}' | sort | uniq -c | sort -rn > "${wd}/ip_api.txt"

    # 8. 单接口速率（单分钟）
    cat "$recent" | awk '{ts=substr($1,2); minute=substr(ts,1,17); for(i=1;i<=NF;i++) if($i=="[Client") {ip=$(i+1); gsub(/\]/,"",ip); print minute"|"ip"|"$10}}' | sort | uniq -c | sort -rn > "${wd}/ip_apirate.txt"

    # 9. 空 UA
    cat "$recent" | awk '{
        if (match($0, /"[^"]*" "[^"]*"$/)) {
            s = substr($0, RSTART, RLENGTH)
            if (match(s, /^"[^"]*"/)) {
                ua = substr(s, RSTART, RLENGTH)
                if (ua == "\"-\"") print
            }
        }
    }' | eval "$extract" | sort | uniq -c | sort -rn > "${wd}/ip_emptyua.txt"

    # 10. 高频观察
    cat "$recent" | eval "$extract" | sort | uniq -c | sort -rn > "${wd}/ip_freq.txt"
}

# 封禁决策
det_decide() {
    local wd="$1" mode="${2:-normal}"

    _apply() {
        local file="$1" threshold="$2" fmt="$3" reason="$4"
        while read -r count rest; do
            [ -z "$rest" ] && continue
            if (( count >= threshold )); then
                case "$fmt" in
                    ip) local ip="$rest" ;;
                    ipuri) local ip="${rest%% *}" ;;
                    iprate) local ip="${rest#*|}"; ip="${ip%%|*}" ;;
                esac
                if [[ "$mode" == "dry" ]]; then
                    log_info "[DRY-RUN] 将封禁 $ip | ${reason} ${count}次"
                else
                    det_ban "$ip" "${reason} ${count}次"
                fi
            fi
        done < "$file"
    }

    _apply "${wd}/ip_444.txt"    "$LIMIT_444"    ip     "444攻击"
    _apply "${wd}/ip_scan.txt"   "$LIMIT_SCAN"   ip     "扫描探测"
    _apply "${wd}/ip_evilpath.txt" "$LIMIT_EVILPATH" ip "恶意路径"
    _apply "${wd}/ip_payload.txt" "$LIMIT_PAYLOAD" ip    "漏洞载荷"
    _apply "${wd}/ip_ua.txt"      "$LIMIT_UA"     ip     "可疑UA"
    _apply "${wd}/ip_auth.txt"    "$LIMIT_AUTH"   ip     "登录爆破"
    _apply "${wd}/ip_api.txt"     "$LIMIT_API"    ipuri  "单接口高频"
    _apply "${wd}/ip_apirate.txt" "$LIMIT_API_RATE" iprate "单接口速率"
    _apply "${wd}/ip_emptyua.txt" "$LIMIT_EMPTYUA" ip    "空UA"

    # 高频观察（仅记录）
    while read -r count ip; do
        if (( count >= LIMIT_HIGHFREQ )); then
            if ! fw_is_banned "$ip" && ! wl_is_whitelisted "$ip"; then
                log_info "WATCH 高频 $ip ${count}次/${WINDOW}s"
            fi
        fi
    done < "${wd}/ip_freq.txt"
}
