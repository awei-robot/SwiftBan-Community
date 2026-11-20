#!/bin/bash
# WATCH 仅记录观察；每次完整扫描发布一个不可变文件，查询无需加锁。
watch_record() {
    [[ -n "${WATCH_PENDING:-}" ]] || return 0
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$NOW" "$1" "$2" "$3" "$4" "$5" "$6" "${7:--}" >> "$WATCH_PENDING"
}

watch_publish() (
    set -o pipefail
    local mode="$1" pending="$2" events="${3:-}" day dir tmp cutoff file stamp header rest runid
    local -a awk_files
    day=$(date -u '+%Y-%m-%d') || return 1
    dir="$STATE_DIR/watch/$mode/$day"
    mkdir -p "$dir" || return 1
    chmod 700 "$STATE_DIR/watch" "$STATE_DIR/watch/$mode" "$dir" || return 1
    tmp=$(mktemp "$dir/.pending.XXXXXX") || return 1
    local build="$tmp.build" groups="$tmp.groups"
    trap 'rm -f "$tmp" "$build" "$groups"' EXIT
    runid="${RT_RUN_ID:-${NOW}-$$}"
    if [[ -n "$events" && ! -r "$events" ]]; then
        log_error "WATCH 样本事件文件不可读: $events"
        return 1
    fi
    # Collapse multiple rate-limit minute hits to the maximum minute per endpoint.
    awk -F '\t' '{k=$2 SUBSEP $3 SUBSEP $7; if(!(k in row) || $4>peak[k]) {row[k]=$0;peak[k]=$4}} END {for(k in row)print row[k]}' "$pending" |
        LC_ALL=C sort -t $'\t' -k2,2 -k3,3 -k7,7 > "$groups" || return 1
    awk_files=("$groups")
    [[ -n "$events" ]] && awk_files+=("$events")
    {
        printf '# watch-v2\t%s\t%s\t%s\n' "$NOW" "$mode" "$runid"
        awk -F '\t' -v OFS='\t' -v runid="$runid" '
            FILENAME==ARGV[1] {
                i=++n; id[i]=sprintf("%s-W%05d",runid,i)
                stamp[i]=$1; ip[i]=$2; rule[i]=$3; count[i]=$4; threshold[i]=$5
                window[i]=$6; endpoint[i]=$7; minute[i]=$8
                if(rule[i]=="api") api[ip[i] SUBSEP endpoint[i]]=i
                else if(rule[i]=="apirate") rate[ip[i] SUBSEP endpoint[i] SUBSEP minute[i]]=i
                else if(rule[i]=="freq") freq[ip[i]]=i
                next
            }
            NF==14 {
                epoch=$1; client=$2; host=$5; uri=$6; source=$9; event_id=$10; raw=$13
                endpoint_key=length(host) ":" host uri
                sample=epoch SUBSEP source SUBSEP event_id SUBSEP raw
                i=api[client SUBSEP endpoint_key]; if(i>0) remember(i,sample)
                i=rate[client SUBSEP endpoint_key SUBSEP int(epoch/60)]; if(i>0) remember(i,sample)
                i=freq[client]; if(i>0) remember(i,sample)
            }
            END {
                for(i=1;i<=n;i++) {
                    samples=(matched[i]<5 ? matched[i] : 5)
                    if(matched[i]!=count[i]) {printf "WATCH sample count mismatch for %s: expected %s, matched %s\n",id[i],count[i],matched[i] > "/dev/stderr"; bad=1}
                    printf "A\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",id[i],stamp[i],ip[i],rule[i],count[i],threshold[i],window[i],endpoint[i],matched[i]+0,samples
                }
                for(i=1;i<=n;i++) {
                    if(matched[i]<=5) {
                        for(j=1;j<=matched[i];j++) emit(id[i],first[i,j])
                    } else {
                        emit(id[i],first[i,1]); emit(id[i],first[i,2])
                        start=(matched[i]%3)+1
                        for(j=0;j<3;j++) emit(id[i],latest[i,((start+j-1)%3)+1])
                    }
                }
                exit bad
            }
            function emit(id,sample, a) {
                split(sample,a,SUBSEP)
                printf "S\t%s\t%s\t%s\t%s\t%s\n",id,a[1],a[2],a[3],a[4]
            }
            function remember(i,sample,slot) {
                matched[i]++
                if(matched[i]<=5) first[i,matched[i]]=sample
                slot=((matched[i]-1)%3)+1
                latest[i,slot]=sample
            }
        ' "${awk_files[@]}"
    } > "$build" || { log_error "WATCH 样本与告警计数不一致，未发布本轮记录"; return 1; }
    cat "$build" > "$tmp" && chmod 600 "$tmp" || return 1
    mv "$tmp" "$tmp.tsv" || return 1
    # 以扫描时间精确保留，清理只处理本模块发布的文件。
    cutoff=$(( NOW - ${WATCH_RETENTION_DAYS:-7} * 86400 ))
    while IFS= read -r file; do
        IFS=$'\t' read -r header stamp rest < "$file" || continue
        [[ "$header" == "# watch-v1" || "$header" == "# watch-v2" ]] && [[ "$stamp" =~ ^[0-9]+$ ]] || continue
        (( stamp >= cutoff )) || rm -f "$file" || return 1
    done < <(find "$STATE_DIR/watch" -type f -name '.pending.*.tsv')
    find "$STATE_DIR/watch" -mindepth 2 -type d -empty -delete || return 1
)

cmd_watch() (
    set -o pipefail
    local mode=formal ip='' rule='' since=24h limit=50 json=0 geo=0 sample_id='' seconds now tmp file
    while (( $# )); do
        case "$1" in
            -h|--help) watch_usage; return ;;
            --dry-run) mode=dry-run; shift ;;
            --json) json=1; shift ;;
            --geo) geo=1; shift ;;
            --samples)
                (( $# >= 2 )) || { echo "缺少参数: --samples" >&2; return 1; }
                sample_id="$2"; shift 2 ;;
            --ip|--rule|--since|--limit)
                (( $# >= 2 )) || { echo "缺少参数: $1" >&2; return 1; }
                case "$1" in
                    --ip) ip=$(wl_normalize_ip "$2") || return 1 ;;
                    --rule) rule="$2"; [[ "$rule" == api || "$rule" == apirate || "$rule" == freq ]] || return 1 ;;
                    --since) since="$2" ;;
                    --limit) limit="$2" ;;
                esac
                shift 2 ;;
            *) echo "未知选项: $1；使用 swiftban watch --help 查看参数说明" >&2; return 1 ;;
        esac
    done
    if [[ -n "$sample_id" && ( -n "$ip" || -n "$rule" || "$since" != 24h || "$limit" != 50 || "$json" == 1 || "$geo" == 1 ) ]]; then
        echo "--samples 不能与筛选、--json 或 --geo 组合" >&2
        return 1
    fi
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
            if [[ -n "$sample_id" ]]; then
                cat "$file" >> "$tmp/input" || return 1
            else
                # v2 files store all alert rows before samples; stop at the
                # first sample so ordinary list queries never load raw lines.
                awk -F '\t' '$1=="S" {exit} {print}' "$file" >> "$tmp/input" || return 1
            fi
        done < <(find "$STATE_DIR/watch/$mode" -type f -name '.pending.*.tsv')
    fi
    if [[ -n "$sample_id" ]]; then
        det_awk -F '\t' -v wanted="$sample_id" '
            $1=="# watch-v2" {run=$4;next}
            $1=="A" && $2==wanted {
                found=1; stamp=$3; ip=$4; rule=$5; matched=$10; samples=$11
                print "=== WATCH 告警样本: " wanted " ==="
                print "IP=" ip " | 规则=" rule " | 匹配事件=" matched " | 保存样本=" samples " | 运行=" run
            }
            $1=="S" && $2==wanted {
                split($5,event_parts,":")
                print "[" strftime("%Y-%m-%d %H:%M:%S UTC",$3,1) "] " $4 " | byte_offset=" event_parts[4] " | event_id=" $5
                print $6
                printed++
            }
            END {if(!found) exit 2; if(!printed) print "（该告警没有保存样本）"}
        ' "$tmp/input" || { echo "未找到 WATCH 告警 ID: $sample_id" >&2; return 1; }
        return 0
    fi
    det_awk -F '\t' -v OFS='\t' '
        /^#/ {next}
        NF==7 && $1~/^[0-9]+$/ && $3~/^(api|apirate|freq)$/ {
            print $1,$2,$3,$4,$5,$6,$7,"-",$4,0
            next
        }
        $1=="A" && NF==11 {
            print $3,$4,$5,$6,$7,$8,$9,$2,$10,$11
        }
    ' "$tmp/input" > "$tmp/normalized" || return 1
    SWIFTBAN_WATCH_IP="$ip" det_awk -F '\t' -v cutoff="$((now-seconds))" -v rule="$rule" '
        $1~/^[0-9]+$/ && $3~/^(api|apirate|freq)$/ && $4~/^[0-9]+$/ && $5~/^[0-9]+$/ && $6~/^[0-9]+$/ && $1>=cutoff && (rule=="" || $3==rule) && (ENVIRON["SWIFTBAN_WATCH_IP"]=="" || $2==ENVIRON["SWIFTBAN_WATCH_IP"]) {
            k=$2 SUBSEP $3 SUBSEP $7
            if (!(k in first) || $1<first[k]) first[k]=$1
            hits[k]++; if ($4>peak[k]) peak[k]=$4
            if (!(k in last) || $1>=last[k]) {last[k]=$1; row[k]=$0}
        }
        END {for(k in row) print last[k] "\t" first[k] "\t" peak[k] "\t" hits[k] "\t" row[k]}
    ' "$tmp/normalized" | LC_ALL=C sort -t $'\t' -k1,1nr -k6,6 -k7,7 -k11,11 > "$tmp/rows" || return 1
    if (( geo )); then geo_enrich "$tmp/rows" "$tmp/enriched" 6 "$limit" || return 1
    else cp "$tmp/rows" "$tmp/enriched" || return 1; fi
    LC_ALL=C det_awk -F '\t' -v limit="$limit" -v json="$json" -v mode="$mode" -v geo="$geo" '
        function esc(s, i,c,r,j,encoded) {
            r=""; for(i=1;i<=length(s);i++) {c=substr(s,i,1); if(c=="\\" || c=="\"") r=r "\\" c; else {encoded=0;for(j=1;j<32;j++) if(c==sprintf("%c",j)) {r=r sprintf("\\u%04x",j);encoded=1;break} if(!encoded) r=r c}} return r
        }
        # 在 C locale 下逐字节计算 UTF-8 宽度；对齐列仅含 ASCII 和中文。
        function display_width(s, i,c,w) {
            w=0
            for(i=1;i<=length(s);) {
                c=substr(s,i,1)
                if(c~/[\340-\357]/) {w+=2;i+=3}
                else if(c~/[\360-\367]/) {w+=2;i+=4}
                else if(c~/[\300-\337]/) {w++;i+=2}
                else {w++;i++}
            }
            return w
        }
        function cell(r,c,s, w) {
            cells[r,c]=s;w=display_width(s)
            if(w>widths[c]) widths[c]=w
        }
        BEGIN {
            if(json) printf "["
            else {
                cell(0,1,"IP")
                cell(0,2,"告警ID");cell(0,3,"样本/匹配数")
                cell(0,4,"规则");cell(0,5,"最近计数/阈值")
                cell(0,6,"峰值");cell(0,7,"命中轮次");cell(0,8,"首次发现")
                cell(0,9,"最后发现");cell(0,10,"窗口秒")
                if(geo) {cell(0,11,"来源地");cell(0,12,"运营商");cell(0,13,"接口")}
                else cell(0,11,"接口")
            }
        }
        NR<=limit {
            if(json) {
                if(n++) printf ","
                printf "{\"ip\":\"%s\",\"id\":\"%s\",\"matched_events\":%s,\"sample_count\":%s,\"rule\":\"%s\",\"count\":%s,\"threshold\":%s,\"peak\":%s,\"scans\":%s,\"first_seen\":%s,\"last_seen\":%s,\"window_seconds\":%s,\"endpoint\":\"%s\"", esc($6),$12,$13,$14,$7,$8,$9,$3,$4,$2,$1,$10,esc($11)
                if(geo) printf ",\"geo\":%s",$17
                printf "}"
            } else {
                label=($7=="api"?"单接口高频":($7=="apirate"?"单接口速率":"总请求高频"))
                shown++
                cell(shown,1,$6);cell(shown,2,$12);cell(shown,3,$14 "/" $13)
                cell(shown,4,label);cell(shown,5,$8 "/" $9)
                cell(shown,6,$3);cell(shown,7,$4)
                cell(shown,8,strftime("%m-%d %H:%M",$2,1))
                cell(shown,9,strftime("%m-%d %H:%M",$1,1))
                cell(shown,10,$10)
                if(geo) {cell(shown,11,$15);cell(shown,12,$16);cell(shown,13,$11)}
                else cell(shown,11,$11)
            }
        }
        END {
            if(json) print "]"
            else {
                print "=== WATCH 观察列表（" mode "，次数不跨扫描累加；时间为 UTC）==="
                for(r=0;r<=shown;r++) {
                    columns=(geo?13:11)
                    for(c=1;c<=columns;c++) {
                        printf "%s",cells[r,c]
                        if(c<columns) printf "%*s",widths[c]-display_width(cells[r,c])+2,""
                    }
                    printf "\n"
                }
                if(!shown) print "(无观察记录)"
            }
        }
    ' "$tmp/enriched"
)

watch_summary() (
    local mode file tmp
    for mode in formal dry-run; do
        tmp=$(mktemp) || return 1
        if [[ -d "$STATE_DIR/watch/$mode" ]]; then
            while IFS= read -r file; do
                [[ -e "$file" ]] || continue
                awk -F '\t' '$1=="S" {exit} {print}' "$file" >> "$tmp" || { rm -f "$tmp"; return 1; }
            done < <(find "$STATE_DIR/watch/$mode" -type f -name '.pending.*.tsv')
        fi
        det_awk -F '\t' -v mode="$mode" -v cutoff="$(( $(date +%s) - 86400 ))" '
            /^# watch-v[12]/ {if($2>last) last=$2;next}
            NF==7 && $1>=cutoff {ips[$2]=1;next}
            $1=="A" && NF==11 && $3>=cutoff {ips[$4]=1}
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
            NR==1 {
                if(NF!=4 || ($1!="# watch-v1" && $1!="# watch-v2") || $2!~/^[0-9]+$/ || ($3!="formal" && $3!="dry-run")) bad=1
                version=($1=="# watch-v2"?2:1); next
            }
            version==1 {
                if(NF!=7 || $1!~/^[0-9]+$/ || $2=="" || $3!~/^(api|apirate|freq)$/ || $4!~/^[0-9]+$/ || $5!~/^[0-9]+$/ || $6!~/^[0-9]+$/) bad=1
                next
            }
            $1=="A" {
                if(NF!=11 || $2!~/^[A-Za-z0-9._-]+-W[0-9]{5,}$/ || $3!~/^[0-9]+$/ || $4=="" ||
                   $5!~/^(api|apirate|freq)$/ || $6!~/^[0-9]+$/ || $7!~/^[0-9]+$/ || $8!~/^[0-9]+$/ ||
                   $10!~/^[0-9]+$/ || $11!~/^[0-5]$/ || $10!=$6 || $11!=($6<5?$6:5) || ($2 in alerts)) bad=1
                alerts[$2]=1; expected[$2]=$11; next
            }
            $1=="S" {
                if(NF!=6 || !($2 in alerts) || $3!~/^[0-9]+$/ || $4=="" || $5!~/^[0-9]+:[0-9]+:[0-9]+:[0-9]+$/ || $6=="") bad=1
                samples[$2]++; next
            }
            {bad=1}
            END {
                if(NR==0) bad=1
                for(id in alerts) if(samples[id]+0!=expected[id]) bad=1
                exit bad
            }' "$file"; then
            printf '失败 WATCH 文件不可读或格式错误: %s\n' "$file"; bad=1
        fi
    done < <(find "$STATE_DIR/watch" -type f -name '.pending.*.tsv')
    (( bad )) || echo '通过 WATCH 目录权限及文件格式'
    (( bad == 0 ))
)
