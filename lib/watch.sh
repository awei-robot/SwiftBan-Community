#!/bin/bash
# WATCH 仅记录观察；每次完整扫描发布一个不可变文件，查询无需加锁。
watch_record() {
    [[ -n "${WATCH_PENDING:-}" ]] || return 0
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$NOW" "$1" "$2" "$3" "$4" "$5" "$6" >> "$WATCH_PENDING"
}

watch_publish() (
    local mode="$1" pending="$2" day dir tmp cutoff file stamp header rest
    day=$(date -u '+%Y-%m-%d') || return 1
    dir="$STATE_DIR/watch/$mode/$day"
    mkdir -p "$dir" || return 1
    chmod 700 "$STATE_DIR/watch" "$STATE_DIR/watch/$mode" "$dir" || return 1
    tmp=$(mktemp "$dir/.pending.XXXXXX") || return 1
    trap 'rm -f "$tmp"' EXIT
    {
        printf '# watch-v1\t%s\t%s\t%s\n' "$NOW" "$mode" "${RT_RUN_ID:-standalone}"
        # 同一扫描可能有多个超限分钟；每个分组只计一个命中轮次，取最大分钟计数。
        awk -F '\t' '{k=$2 SUBSEP $3 SUBSEP $7; if(!(k in row) || $4>peak[k]) {row[k]=$0;peak[k]=$4}} END {for(k in row)print row[k]}' "$pending"
    } > "$tmp" || return 1
    mv "$tmp" "$tmp.tsv" || return 1
    # 以扫描时间精确保留，清理只处理本模块发布的文件。
    cutoff=$(( NOW - ${WATCH_RETENTION_DAYS:-7} * 86400 ))
    while IFS= read -r file; do
        IFS=$'\t' read -r header stamp rest < "$file" || continue
        [[ "$header" == "# watch-v1" && "$stamp" =~ ^[0-9]+$ ]] || continue
        (( stamp >= cutoff )) || rm -f "$file" || return 1
    done < <(find "$STATE_DIR/watch" -type f -name '.pending.*.tsv')
    find "$STATE_DIR/watch" -mindepth 2 -type d -empty -delete || return 1
)

cmd_watch() (
    local mode=formal ip='' rule='' since=24h limit=50 json=0 seconds now tmp file
    while (( $# )); do
        case "$1" in
            --dry-run) mode=dry-run; shift ;;
            --json) json=1; shift ;;
            --ip|--rule|--since|--limit)
                (( $# >= 2 )) || { echo "缺少参数: $1" >&2; return 1; }
                case "$1" in
                    --ip) ip=$(wl_normalize_ip "$2") || return 1 ;;
                    --rule) rule="$2"; [[ "$rule" == api || "$rule" == apirate || "$rule" == freq ]] || return 1 ;;
                    --since) since="$2" ;;
                    --limit) limit="$2" ;;
                esac
                shift 2 ;;
            *) echo '用法: swiftban watch [--ip IP] [--rule api|apirate|freq] [--since 24h|7d] [--limit N] [--dry-run] [--json]' >&2; return 1 ;;
        esac
    done
    [[ "$since" =~ ^([1-9][0-9]{0,4})([hHdD])$ && "$limit" =~ ^[1-9][0-9]{0,5}$ ]] || return 1
    seconds="${since%?}"
    case "$since" in *h|*H) seconds=$((seconds * 3600));; *) seconds=$((seconds * 86400));; esac
    now=$(date -u +%s)
    tmp=$(mktemp -d) || return 1
    trap 'rm -rf "$tmp"' EXIT
    : > "$tmp/input"
    if [[ -d "$STATE_DIR/watch/$mode" ]]; then
        while IFS= read -r file; do
            # 过期清理可能同时删除文件；已删除的文件跳过。
            [[ -e "$file" ]] || continue
            cat "$file" >> "$tmp/input" || return 1
        done < <(find "$STATE_DIR/watch/$mode" -type f -name '.pending.*.tsv')
    fi
    SWIFTBAN_WATCH_IP="$ip" det_awk -F '\t' -v cutoff="$((now-seconds))" -v rule="$rule" '
        /^#/ {next}
        NF==7 && $1~/^[0-9]+$/ && $3~/^(api|apirate|freq)$/ && $4~/^[0-9]+$/ && $5~/^[0-9]+$/ && $6~/^[0-9]+$/ && $1>=cutoff && (rule=="" || $3==rule) && (ENVIRON["SWIFTBAN_WATCH_IP"]=="" || $2==ENVIRON["SWIFTBAN_WATCH_IP"]) {
            k=$2 SUBSEP $3 SUBSEP $7
            if (!(k in first) || $1<first[k]) first[k]=$1
            hits[k]++; if ($4>peak[k]) peak[k]=$4
            if (!(k in last) || $1>=last[k]) {last[k]=$1; row[k]=$0}
        }
        END {for(k in row) print last[k] "\t" first[k] "\t" peak[k] "\t" hits[k] "\t" row[k]}
    ' "$tmp/input" | LC_ALL=C sort -t $'\t' -k1,1nr -k6,6 -k7,7 -k11,11 > "$tmp/rows" || return 1
    det_awk -F '\t' -v limit="$limit" -v json="$json" -v mode="$mode" '
        function esc(s, i,c,r,j,encoded) {
            r=""; for(i=1;i<=length(s);i++) {c=substr(s,i,1); if(c=="\\" || c=="\"") r=r "\\" c; else {encoded=0;for(j=1;j<32;j++) if(c==sprintf("%c",j)) {r=r sprintf("\\u%04x",j);encoded=1;break} if(!encoded) r=r c}} return r
        }
        BEGIN {if(json) printf "["; else print "=== WATCH 观察列表（" mode "，次数不跨扫描累加；时间为 UTC）===\nIP\t规则\t最近计数/阈值\t峰值\t命中轮次\t首次发现\t最后发现\t窗口秒\t接口"}
        NR<=limit {
            if(json) {
                if(n++) printf ","
                printf "{\"ip\":\"%s\",\"rule\":\"%s\",\"count\":%s,\"threshold\":%s,\"peak\":%s,\"scans\":%s,\"first_seen\":%s,\"last_seen\":%s,\"window_seconds\":%s,\"endpoint\":\"%s\"}", esc($6),$7,$8,$9,$3,$4,$2,$1,$10,esc($11)
            } else {
                label=($7=="api"?"单接口高频":($7=="apirate"?"单接口速率":"总请求高频"))
                print $6 "\t" label "\t" $8 "/" $9 "\t" $3 "\t" $4 "\t" strftime("%m-%d %H:%M",$2,1) "\t" strftime("%m-%d %H:%M",$1,1) "\t" $10 "\t" $11
            }
        }
        END {if(json) print "]"; else if(NR==0) print "(无观察记录)"}
    ' "$tmp/rows"
)

watch_summary() (
    local mode file tmp
    for mode in formal dry-run; do
        tmp=$(mktemp) || return 1
        if [[ -d "$STATE_DIR/watch/$mode" ]]; then
            while IFS= read -r file; do
                [[ -e "$file" ]] || continue
                cat "$file" >> "$tmp" || { rm -f "$tmp"; return 1; }
            done < <(find "$STATE_DIR/watch/$mode" -type f -name '.pending.*.tsv')
        fi
        det_awk -F '\t' -v mode="$mode" -v cutoff="$(( $(date +%s) - 86400 ))" '
            /^# watch-v1/ {if($2>last) last=$2;next}
            NF==7 && $1>=cutoff {ips[$2]=1}
            END {for(ip in ips)n++; print "WATCH " mode ": 最近扫描=" (last?strftime("%Y-%m-%d %H:%M:%S UTC",last,1):"无记录") " | 近24小时命中IP=" n+0 "（使用 swiftban watch 查看）"}
        ' "$tmp"
        rm -f "$tmp"
    done
)

watch_doctor() (
    local file bad=0
    [[ -e "$STATE_DIR/watch" ]] || { echo '警告 尚无 WATCH 记录（完成一次扫描后生成）'; return 0; }
    [[ -d "$STATE_DIR/watch" && -r "$STATE_DIR/watch" && -w "$STATE_DIR/watch" && -x "$STATE_DIR/watch" ]] || {
        echo '失败 WATCH 目录不可读写，请检查目录权限'; return 1;
    }
    while IFS= read -r file; do
        if [[ ! -r "$file" ]] || ! awk -F '\t' '
            NR==1 {if(NF!=4 || $1!="# watch-v1" || $2!~/^[0-9]+$/ || ($3!="formal" && $3!="dry-run"))bad=1;next}
            NF!=7 || $1!~/^[0-9]+$/ || $2=="" || $3!~/^(api|apirate|freq)$/ || $4!~/^[0-9]+$/ || $5!~/^[0-9]+$/ || $6!~/^[0-9]+$/ {bad=1}
            END {exit (bad || NR==0)}' "$file"; then
            printf '失败 WATCH 文件不可读或格式错误: %s\n' "$file"; bad=1
        fi
    done < <(find "$STATE_DIR/watch" -type f -name '.pending.*.tsv')
    (( bad )) || echo '通过 WATCH 目录权限及文件格式'
    (( bad == 0 ))
)
