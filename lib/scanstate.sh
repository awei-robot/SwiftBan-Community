#!/bin/bash
# Stateful log collection for rotation-aware scans. State is plain TSV.

det_scan_state_path() {
    printf '%s/scan/state.tsv\n' "$STATE_DIR"
}

det_scan_validate_state() {
    local file="$1" output="$2"
    awk -F '\t' -v OFS='\t' '
        $1=="C" {
            if(NF!=8 || $2!~/^[0-9]+:[0-9]+$/ || $3!~/^[0-9]+$/ ||
               $4!~/^[0-9]+$/ || $5!~/^[0-9]+$/ ||
               !(($4==0 && ($7==0 || $7=="") && $8=="") ||
                 ($7~/^[0-9]+$/ && $7<$4 && $8~/^[0-9]+ [0-9]+$/))) bad=1
            else cursors++
            next
        }
        $1=="E" {
            if(NF!=14 || $2!~/^[0-9]+$/ ||
               $11!~/^[0-9]+:[0-9]+:[0-9]+:[0-9]+$/ ||
               $12!~/^[0-9]+:[0-9]+:[0-9]+$/) bad=1
            else events++
            next
        }
        {bad=1}
        END {
            if(!bad) print "ok",cursors+0,events+0
            exit bad
        }
    ' "$file" > "$output"
}

# Return a safe cursor at the last complete line without parsing old contents.
det_scan_cursor_at_eof() (
    set -o pipefail
    local file="$1" size="$2" last_byte bytes offset last_line_offset fingerprint
    if (( size == 0 )); then
        printf '0\t0\t\n'
        return 0
    fi
    last_byte=$(tail -c 1 "$file" | od -An -tu1 | tr -d '[:space:]') || return 1
    if [[ "$last_byte" == 10 ]]; then
        bytes=$(tail -n 1 "$file" | wc -c | tr -d ' ') || return 1
        offset="$size"
        last_line_offset=$((offset - bytes))
        fingerprint=$(tail -n 1 "$file" | cksum) || return 1
    else
        bytes=$(tail -n 1 "$file" | wc -c | tr -d ' ') || return 1
        offset=$((size - bytes))
        if (( offset == 0 )); then
            printf '0\t0\t\n'
            return 0
        fi
        bytes=$(tail -n 2 "$file" | sed '$d' | wc -c | tr -d ' ') || return 1
        last_line_offset=$((offset - bytes))
        fingerprint=$(tail -n 2 "$file" | sed '$d' | cksum) || return 1
    fi
    printf '%s\t%s\t%s\n' "$offset" "$last_line_offset" "$fingerprint"
)

# Input records: source<TAB>family<TAB>event-id<TAB>file-generation<TAB>raw-line
det_scan_collect() (
    local wd="$1" state file base family suffix identity generation offset last_line_offset fingerprint
    local size mtime now after_identity after_size chunk chunk_size seen="|" stored_fingerprint
    local fingerprint_start fingerprint_bytes
    local cursor_offset priority candidate_mtime abandoned_files=0 after_mtime
    local file_started='' file_elapsed=0 file_start_offset=0 file_lines=0 file_bytes=0
    local cursor_file="$wd/cursors.pending" state_file
    state_file=$(det_scan_state_path) || return 1
    umask 077
    mkdir -p "$STATE_DIR/scan" || return 1
    chmod 700 "$STATE_DIR/scan" || return 1
    if [[ -f "$state_file" ]] && ! det_scan_validate_state "$state_file" "$wd/state-counts"; then
        log_error "扫描状态损坏，未推进日志游标: $state_file"
        return 1
    fi
    : > "$wd/input.tsv" || return 1
    : > "$wd/files" || return 1
    : > "$wd/identity-files.tsv" || return 1
    : > "$cursor_file" || return 1
    : > "$wd/line-meta.tsv" || return 1
    state="$state_file"
    now=$(date -u +%s) || return 1
    find "$LOG_DIR" -maxdepth 1 -type f -name '*access.log*' -print0 > "$wd/all-files" || return 1

    # Snapshot eligible files before reading: recent mtime files always run
    # first; older files are included only when a cursor already tracks them.
    : > "$wd/candidates.tsv" || return 1
    while IFS= read -r -d '' file; do
        base=$(basename "$file")
        if [[ "$base" == *access.log ]]; then
            :
        elif [[ "$base" == *access.log.* || "$base" == *access.log-* ]]; then
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
        cursor_offset=""
        if [[ -f "$state" ]]; then
            cursor_offset=$(awk -F '\t' -v id="$identity" '$1=="C" && $2==id {print $4; exit}' "$state")
        fi
        if (( now - mtime <= 180 )); then
            priority=0
        elif [[ -n "$cursor_offset" ]]; then
            priority=1
        else
            continue
        fi
        [[ "$cursor_offset" =~ ^[0-9]+$ ]] || cursor_offset=0
        printf '%s\t%s\t%s\t%s\n' "$priority" "$cursor_offset" "$mtime" "$file" >> "$wd/candidates.tsv" || return 1
    done < "$wd/all-files"
    LC_ALL=C sort -t $'\t' -k1,1n -k2,2n -k3,3nr -k4,4 "$wd/candidates.tsv" > "$wd/candidates.sorted" || return 1
    cut -f1,3,4 "$wd/candidates.sorted" > "$wd/ordered-candidates.tsv" || return 1

    while IFS=$'\t' read -r priority candidate_mtime file; do
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
        if (( priority == 1 )) && [[ "$mtime" != "$candidate_mtime" ]]; then
            log_warn "旧日志在调度期间已更新，留待下轮按近期优先扫描: $file"
            return 1
        fi
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
        # Older snapshots may leave the last-line offset blank for a file
        # that has never been read. Normalize that zero-offset cursor.
        if [[ "$offset" == 0 && -z "$last_line_offset" && -z "$fingerprint" ]]; then
            last_line_offset=0
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

        if (( priority == 1 )); then
            # Abandon unread history after the mtime window. Rebase to the
            # last complete line so later appends resume without replaying it.
            IFS=$'\t' read -r offset last_line_offset fingerprint < <(
                det_scan_cursor_at_eof "$file" "$size"
            ) || return 1
            read -r after_identity after_size after_mtime < <(
                stat -c '%d:%i %s %Y' "$file" 2>/dev/null ||
                    stat -f '%d:%i %z %m' "$file"
            ) || return 1
            if [[ "$identity" != "$after_identity" || "$after_size" != "$size" || "$after_mtime" != "$mtime" ]]; then
                log_warn "旧日志在游标重建期间发生变化，本轮不推进游标: $file"
                return 1
            fi
            printf 'C\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$identity" "$generation" "$offset" "$now" "$family" \
                "$last_line_offset" "$fingerprint" >> "$cursor_file" || return 1
            abandoned_files=$((abandoned_files + 1))
            continue
        fi

        file_start_offset="$offset"
        file_lines=0
        file_started=""
        if [[ "${RT_METRICS_ENABLED:-0}" == 1 ]] && declare -F rt_clock_cs >/dev/null && rt_clock_cs; then
            file_started="$REPLY"
        fi
        printf '%s\n' "$file" >> "$wd/files" || return 1
        if (( size > offset )); then
            chunk="$wd/chunk"
            if ! tail -c "+$((offset + 1))" "$file" > "$chunk"; then return 1; fi
            chunk_size=$(stat -c '%s' "$chunk" 2>/dev/null || stat -f '%z' "$chunk") || return 1
            printf '%s\t%s\n' "$identity" "$file" >> "$wd/identity-files.tsv" || return 1
            SWIFTBAN_SOURCE="$file" SWIFTBAN_FAMILY="$family" SWIFTBAN_IDENTITY="$identity" \
                SWIFTBAN_GENERATION="$generation" SWIFTBAN_BASE_OFFSET="$offset" \
                SWIFTBAN_PREVIOUS_LINE_OFFSET="$last_line_offset" SWIFTBAN_CHUNK_SIZE="$chunk_size" \
                SWIFTBAN_INPUT="$wd/input.tsv" SWIFTBAN_LINE_META="$wd/line-meta.tsv" \
                SWIFTBAN_CURSOR_RESULT="$wd/file-cursor.tsv" LC_ALL=C awk '
                    BEGIN {
                        CONVFMT="%.0f"
                        OFMT="%.0f"
                        offset=ENVIRON["SWIFTBAN_BASE_OFFSET"]+0
                        previous=ENVIRON["SWIFTBAN_PREVIOUS_LINE_OFFSET"]+0
                        chunk_size=ENVIRON["SWIFTBAN_CHUNK_SIZE"]+0
                        identity=ENVIRON["SWIFTBAN_IDENTITY"]
                        generation=ENVIRON["SWIFTBAN_GENERATION"]
                        source=ENVIRON["SWIFTBAN_SOURCE"]
                        family=ENVIRON["SWIFTBAN_FAMILY"]
                    }
                    {
                        line_bytes=length($0)+1
                        if(consumed+line_bytes>chunk_size) exit
                        event=identity ":" generation ":" offset
                        printf "%s\t%s\t%s\t%s\t%s\n", source,family,event,identity ":" generation,$0 >> ENVIRON["SWIFTBAN_INPUT"]
                        printf "%s\t%s\t%d\n", event,identity,previous >> ENVIRON["SWIFTBAN_LINE_META"]
                        previous=offset
                        offset+=line_bytes
                        consumed+=line_bytes
                        lines++
                    }
                    END {
                        printf "%.0f\t%.0f\t%.0f\n",offset,previous,lines > ENVIRON["SWIFTBAN_CURSOR_RESULT"]
                        close(ENVIRON["SWIFTBAN_INPUT"])
                        close(ENVIRON["SWIFTBAN_LINE_META"])
                        close(ENVIRON["SWIFTBAN_CURSOR_RESULT"])
                    }
                ' "$chunk" || return 1
            IFS=$'\t' read -r offset last_line_offset file_lines < "$wd/file-cursor.tsv" || return 1
            if (( file_lines > 0 )); then
                fingerprint_start=$((last_line_offset - file_start_offset + 1))
                fingerprint_bytes=$((offset - last_line_offset))
                fingerprint=$(tail -c "+$fingerprint_start" "$chunk" | head -c "$fingerprint_bytes" | cksum) || return 1
            fi
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
        if [[ -n "$file_started" ]] && rt_clock_cs; then
            file_elapsed=$((REPLY-file_started)); (( file_elapsed >= 0 )) || file_elapsed=0
            file_bytes=$((offset-file_start_offset)); (( file_bytes >= 0 )) || file_bytes=0
            rt_metrics_file "$file" "$file_elapsed" "$file_bytes" "$file_lines"
        fi
    done < "$wd/ordered-candidates.tsv"

    if (( abandoned_files > 0 )); then
        log_info "超过3分钟的日志已跳过旧内容并重建游标: ${abandoned_files}个文件"
    fi

    # Carry forward cursor rows for files temporarily absent during rotation.
    if [[ -f "$state" ]]; then
        awk -F '\t' -v OFS='\t' -v now="$now" '
            $1=="C" && now-$5<=180 {
                if($4==0 && $7=="" && $8=="") $7=0
                print
            }
        ' "$state" > "$wd/cursors.old" || return 1
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
det_scan_find_identity_file() {
    local target="$1" file identity
    while IFS= read -r -d '' file; do
        read -r identity < <(
            stat -c '%d:%i' "$file" 2>/dev/null || stat -f '%d:%i' "$file" 2>/dev/null
        ) || continue
        if [[ "$identity" == "$target" ]]; then
            printf '%s\n' "$file"
            return 0
        fi
    done < <(find "$LOG_DIR" -maxdepth 1 -type f -name '*access.log*' -print0)
    return 1
}

det_scan_rewind_future() {
    local wd="$1" event identity generation offset meta_identity previous_offset previous_fingerprint
    local source_file source_identity span checksum checksum_bytes
    local future_file="$wd/future.tsv"
    [[ -s "$future_file" ]] || return 0
    while IFS= read -r event; do
        [[ "$event" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
        identity=$(printf '%s\n' "$event" | sed -E 's/^([0-9]+:[0-9]+):[0-9]+:[0-9]+$/\1/')
        generation=$(printf '%s\n' "$event" | sed -E 's/^[0-9]+:[0-9]+:([0-9]+):[0-9]+$/\1/')
        offset=$(printf '%s\n' "$event" | sed -E 's/^[0-9]+:[0-9]+:[0-9]+:([0-9]+)$/\1/')
        IFS=$'\t' read -r meta_identity previous_offset < <(
            awk -F '\t' -v event="$event" '$1==event {print $2 "\t" $3; exit}' "$wd/line-meta.tsv"
        )
        [[ "$meta_identity" == "$identity" ]] || return 1
        source_file=$(awk -F '\t' -v id="$identity" '$1==id {print $2; exit}' "$wd/identity-files.tsv")
        [[ -n "$source_file" ]] || return 1
        read -r source_identity < <(
            stat -c '%d:%i' "$source_file" 2>/dev/null || stat -f '%d:%i' "$source_file" 2>/dev/null
        ) || return 1
        if [[ "$source_identity" != "$identity" ]]; then
            source_file=$(det_scan_find_identity_file "$identity") || return 1
        fi
        previous_fingerprint=""
        if (( offset > previous_offset )); then
            span=$((offset - previous_offset))
            checksum=$(tail -c "+$((previous_offset + 1))" "$source_file" | head -c "$span" | cksum) || return 1
            read -r _ checksum_bytes <<< "$checksum"
            [[ "$checksum_bytes" == "$span" ]] || return 1
            previous_fingerprint="$checksum"
        fi
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

    : > "$wd/recent.events.unsorted" || return 1
    SWIFTBAN_EVENTS="$wd/recent.events.unsorted" det_awk -F '\t' -v cutoff="$cutoff" -v now="$now" '
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
                if(f[12]==best[rawkey] && ++kept[groupkey]<=max[rawkey]) {
                    print f[2],f[3],f[4],f[5],f[6],f[7],f[8],f[9],f[10]
                    split(f[11],event_parts,":")
                    print f[2],f[3],f[4],f[5],f[6],f[7],f[8],f[9],f[10],f[11],f[12],f[13],f[14],event_parts[4] > ENVIRON["SWIFTBAN_EVENTS"]
                }
            }
        }
    ' "$wd/state.next" > "$wd/recent.log" || return 1
    LC_ALL=C sort -t $'\t' -k1,1n -k9,9 -k14,14n "$wd/recent.events.unsorted" > "$wd/recent.events.tsv" || return 1
    rm -f "$wd/recent.events.unsorted"
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
