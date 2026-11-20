#!/bin/bash
# Stateful log collection for rotation-aware scans. State is plain TSV.

det_scan_state_path() {
    printf '%s/scan/state.tsv\n' "$STATE_DIR"
}

# Input records: source<TAB>family<TAB>event-id<TAB>file-generation<TAB>raw-line
det_scan_collect() (
    local wd="$1" state file base family suffix identity generation offset last_line_offset fingerprint
    local size mtime now after_identity after_size raw chunk seen="|" bytes stored_fingerprint
    local cursor_file="$wd/cursors.pending" state_file
    state_file=$(det_scan_state_path) || return 1
    umask 077
    mkdir -p "$STATE_DIR/scan" || return 1
    chmod 700 "$STATE_DIR/scan" || return 1
    if [[ -f "$state_file" ]] && ! awk -F '\t' '
        $1=="C" {
            if(NF!=8 || $2!~/^[0-9]+:[0-9]+$/ || $3!~/^[0-9]+$/ ||
               $4!~/^[0-9]+$/ || $5!~/^[0-9]+$/ || $7!~/^[0-9]+$/ ||
               !(($4==0 && $7==0 && $8=="") || ($7<$4 && $8~/^[0-9]+ [0-9]+$/))) bad=1
            next
        }
        $1=="E" {
            if(NF!=14 || $2!~/^[0-9]+$/ ||
               $11!~/^[0-9]+:[0-9]+:[0-9]+:[0-9]+$/ ||
               $12!~/^[0-9]+:[0-9]+:[0-9]+$/) bad=1
            next
        }
        {bad=1}
        END {exit bad}
    ' "$state_file"; then
        log_error "扫描状态损坏，未推进日志游标: $state_file"
        return 1
    fi
    : > "$wd/input.tsv" || return 1
    : > "$wd/files" || return 1
    : > "$cursor_file" || return 1
    : > "$wd/line-meta.tsv" || return 1
    state="$state_file"
    now=$(date -u +%s) || return 1
    find "$LOG_DIR" -maxdepth 1 -type f -name '*access.log*' -print0 > "$wd/all-files" || return 1

    while IFS= read -r -d '' file; do
        base=$(basename "$file")
        if [[ "$base" == *access.log ]]; then
            family="$file"
        elif [[ "$base" == *access.log.* || "$base" == *access.log-* ]]; then
            family=$(printf '%s\n' "$file" | sed 's/access\.log.*$/access.log/')
            suffix=$(printf '%s\n' "$base" | sed 's/^.*access\.log//')
            [[ "$suffix" =~ ^\.[0-9]+$ || "$suffix" =~ ^[-.][0-9]{4}-?[0-9]{2}-?[0-9]{2}([-.][0-9]+)?$ ]] || continue
        else
            continue
        fi
        if [[ "$file" =~ [[:cntrl:]] ]]; then
            log_error "日志路径含不支持的控制字符"
            return 1
        fi
        read -r identity size mtime < <(
            stat -c '%d:%i %s %Y' "$file" 2>/dev/null ||
                stat -f '%d:%i %z %m' "$file"
        ) || return 1
        [[ "$identity" =~ ^[0-9]+:[0-9]+$ && "$size" =~ ^[0-9]+$ && "$mtime" =~ ^[0-9]+$ ]] || return 1
        [[ "$seen" == *"|$identity|"* ]] && continue
        seen="$seen$identity|"

        generation=0
        offset=0
        last_line_offset=0
        fingerprint=""
        if [[ -f "$state" ]]; then
            IFS=$'\t' read -r generation offset last_line_offset fingerprint < <(
                awk -F '\t' -v id="$identity" '$1=="C" && $2==id {g=$3;o=$4;p=$7;h=$8} END {if(g!="") print g "\t" o "\t" p "\t" h}' "$state"
            )
        fi
        if [[ -z "$generation" ]]; then
            generation=0
            offset=0
        elif (( size < offset )); then
            generation=$((generation + 1))
            offset=0
            last_line_offset=0
            fingerprint=""
            log_warn "检测到日志截断，已重置读取位置: $file"
        elif (( offset > 0 && last_line_offset < offset )) && [[ -n "$fingerprint" ]]; then
            stored_fingerprint=$(tail -c "+$((last_line_offset + 1))" "$file" |
                head -c "$((offset - last_line_offset))" | cksum) || return 1
            if [[ "$stored_fingerprint" != "$fingerprint" ]]; then
                generation=$((generation + 1))
                offset=0
                last_line_offset=0
                fingerprint=""
                log_warn "检测到日志内容重置，已重新读取: $file"
            fi
        fi

        # The 3-minute mtime filter discovers new files. Known inodes remain
        # eligible so a renamed/rotated file can finish being read.
        if ! awk -F '\t' -v id="$identity" '$1=="C" && $2==id {found=1} END {exit !found}' "$state" 2>/dev/null; then
            if (( now - mtime > 180 )); then continue; fi
        fi

        printf '%s\n' "$file" >> "$wd/files" || return 1
        if (( size > offset )); then
            chunk="$wd/chunk"
            if ! tail -c "+$((offset + 1))" "$file" > "$chunk"; then return 1; fi
            while IFS= read -r raw; do
                bytes=$(printf '%s\n' "$raw" | wc -c | tr -d ' ') || return 1
                printf '%s:%s:%s\t%s\t%s\t%s\n' "$identity" "$generation" "$offset" \
                    "$identity" "$last_line_offset" "$fingerprint" >> "$wd/line-meta.tsv" || return 1
                last_line_offset="$offset"
                fingerprint=$(printf '%s\n' "$raw" | cksum) || return 1
                printf '%s\t%s\t%s:%s:%s\t%s:%s\t%s\n' \
                    "$file" "$family" "$identity" "$generation" "$offset" \
                    "$identity" "$generation" "$raw" >> "$wd/input.tsv" || return 1
                offset=$((offset + bytes))
            done < "$chunk"
            rm -f "$chunk"
        fi
        read -r after_identity after_size < <(
            stat -c '%d:%i %s' "$file" 2>/dev/null ||
                stat -f '%d:%i %z' "$file"
        ) || return 1
        [[ "$identity" == "$after_identity" && "$after_size" =~ ^[0-9]+$ ]] || return 1
        if (( after_size < offset )); then
            log_warn "读取期间日志发生截断，本轮不提交游标: $file"
            return 1
        fi
        printf 'C\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$identity" "$generation" "$offset" "$now" "$family" \
            "$last_line_offset" "$fingerprint" >> "$cursor_file" || return 1
    done < "$wd/all-files"

    # Carry forward cursor rows for files temporarily absent during rotation.
    if [[ -f "$state" ]]; then
        awk -F '\t' -v now="$now" '$1=="C" && now-$5<=604800 {print}' "$state" > "$wd/cursors.old" || return 1
        {
            cat "$cursor_file"
            awk -F '\t' -v current="$cursor_file" '
                FILENAME==current {if($1=="C") seen[$2]=1; next}
                $1=="C" && !seen[$2] {print}
            ' "$cursor_file" "$wd/cursors.old"
        } > "$wd/cursors.merged" &&
            mv "$wd/cursors.merged" "$cursor_file" || return 1
    fi
)

# If a new line carries a future timestamp, keep its file cursor at that line
# so a later run can reconsider it once the server clock catches up.
det_scan_rewind_future() {
    local wd="$1" event identity generation offset meta_identity previous_offset previous_fingerprint
    local future_file="$wd/future.tsv"
    [[ -s "$future_file" ]] || return 0
    while IFS= read -r event; do
        [[ "$event" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
        identity=$(printf '%s\n' "$event" | sed -E 's/^([0-9]+:[0-9]+):[0-9]+:[0-9]+$/\1/')
        generation=$(printf '%s\n' "$event" | sed -E 's/^[0-9]+:[0-9]+:([0-9]+):[0-9]+$/\1/')
        offset=$(printf '%s\n' "$event" | sed -E 's/^[0-9]+:[0-9]+:[0-9]+:([0-9]+)$/\1/')
        IFS=$'\t' read -r meta_identity previous_offset previous_fingerprint < <(
            awk -F '\t' -v event="$event" '$1==event {print $2 "\t" $3 "\t" $4; exit}' "$wd/line-meta.tsv"
        )
        [[ "$meta_identity" == "$identity" ]] || return 1
        awk -F '\t' -v OFS='\t' -v id="$identity" -v generation="$generation" \
            -v offset="$offset" -v seen="$(date -u +%s)" -v p="$previous_offset" \
            -v h="$previous_fingerprint" '
            $1=="C" && $2==id {
                $3=generation; $4=offset; $5=seen; $7=p; $8=h
            }
            {print}
        ' "$wd/cursors.pending" > "$wd/cursors.rewind" || return 1
        mv "$wd/cursors.rewind" "$wd/cursors.pending" || return 1
        log_warn "日志时间仍在未来，暂缓推进游标: $identity"
        break
    done < "$future_file"
}

# Merge new normalized events with the previous snapshot, then aggregate them
# over the rolling time window. The snapshot is committed after enforcement.
det_scan_prepare() {
    local wd="$1" state_file now cutoff
    state_file=$(det_scan_state_path) || return 1
    now="$NOW_EPOCH"
    cutoff=$((now - WINDOW))
    : > "$wd/state-input.tsv" || return 1
    if [[ -f "$state_file" ]]; then
        awk -F '\t' '$1=="E" {print}' "$state_file" >> "$wd/state-input.tsv" || return 1
    fi
    awk -F '\t' 'NF>=13 {print "E\t" $0}' "$wd/recent.new.tsv" >> "$wd/state-input.tsv" || return 1

    {
        cat "$wd/cursors.pending"
        awk -F '\t' -v cutoff="$cutoff" -v now="$now" '
            $1=="E" && $2>=cutoff && $2<=now && !event[$11]++ {print}
        ' "$wd/state-input.tsv"
    } > "$wd/state.next" || return 1

    det_awk -F '\t' -v cutoff="$cutoff" -v now="$now" '
        BEGIN {OFS="\t"}
        $1=="E" && $2>=cutoff && $2<=now {
            n++
            row[n]=$0
            rawkey=$13 SUBSEP $14
            groupkey=rawkey SUBSEP $12
            count[groupkey]++
            if(!(rawkey in best) || count[groupkey]>max[rawkey] ||
               (count[groupkey]==max[rawkey] && $12<best[rawkey])) {
                best[rawkey]=$12
                max[rawkey]=count[groupkey]
            }
        }
        END {
            for(i=1;i<=n;i++) {
                split(row[i],f,"\t")
                rawkey=f[13] SUBSEP f[14]
                groupkey=rawkey SUBSEP f[12]
                if(f[12]==best[rawkey] && ++kept[groupkey]<=max[rawkey])
                    print f[2],f[3],f[4],f[5],f[6],f[7],f[8],f[9],f[10]
            }
        }
    ' "$wd/state.next" > "$wd/recent.log" || return 1
}

det_scan_commit() {
    local wd="$1" state_file staged
    state_file=$(det_scan_state_path) || return 1
    staged=$(mktemp "$STATE_DIR/scan/.state.XXXXXX") || return 1
    if cat "$wd/state.next" > "$staged" && chmod 600 "$staged" && mv "$staged" "$state_file"; then
        return 0
    fi
    rm -f "$staged"
    return 1
}
