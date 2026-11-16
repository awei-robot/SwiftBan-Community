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

#---------------- 日志解析与收集 ----------------
# macOS 系统 awk 缺少 mktime；优先选择 gawk，否则保留 mawk 支持。
det_awk() {
    if command -v gawk >/dev/null 2>&1; then gawk "$@"; else awk "$@"; fi
}

det_check_config() {
    case "$LOG_FORMAT" in
        auto|npm_standard|npm_proxy|combined) ;;
        *) log_error "不支持的 LOG_FORMAT: $LOG_FORMAT"; return 1 ;;
    esac
    if [[ ! "$WINDOW" =~ ^[1-9][0-9]*$ ]]; then
        log_error "WINDOW 必须为正整数秒"
        return 1
    fi
}

# 输入协议：来源文件<TAB>日志家族<TAB>原始行；只读最近3分钟修改的文件，同一 inode 只读一次。
det_collect() {
    local wd="$1" file base family suffix identity after seen="|"
    find "$LOG_DIR" -maxdepth 1 -type f -name '*access.log*' -mmin -3 -print0 > "$wd/files" || return 1
    : > "$wd/input.tsv" || return 1
    while IFS= read -r -d '' file; do
        base="${file##*/}"
        if [[ "$base" == *access.log ]]; then
            family="$file"
        elif [[ "$base" == *access.log.* || "$base" == *access.log-* ]]; then
            family="${file%access.log*}access.log"
            suffix="${file#"$family"}"
            [[ "$suffix" =~ ^\.[0-9]+$ || "$suffix" =~ ^[-.][0-9]{4}-?[0-9]{2}-?[0-9]{2}([-.][0-9]+)?$ ]] || continue
        else
            continue
        fi
        if [[ "$file" =~ [[:cntrl:]] ]]; then
            log_error "日志路径含不支持的控制字符"
            return 1
        fi
        identity=$(stat -c '%d:%i' "$file" 2>/dev/null) ||
            identity=$(stat -f '%d:%i' "$file") || return 1
        [[ "$seen" == *"|$identity|"* ]] && continue
        seen="$seen$identity|"
        # shellcheck disable=SC2094 # 读取日志文件，追加的是独立临时目录中的协议文件。
        if ! SWIFTBAN_SOURCE="$file" SWIFTBAN_FAMILY="$family" det_awk '
            { print ENVIRON["SWIFTBAN_SOURCE"] "\t" ENVIRON["SWIFTBAN_FAMILY"] "\t" $0 }
        ' < "$file" >> "$wd/input.tsv"; then
            return 1
        fi
        after=$(stat -c '%d:%i' "$file" 2>/dev/null) ||
            after=$(stat -f '%d:%i' "$file") || return 1
        [[ "$identity" == "$after" ]] || return 1
    done < "$wd/files"
}

# 输出 TSV：epoch、IP、最终状态、方法、Host、完整 URI、UA、Referer、来源。
# 保留转义文本，不解码 URL 或 \xXX，防止记录/字段分隔符注入。
det_parse() {
    local src="$1" dst="$2" stats="$3"
    LC_ALL=C TZ=UTC SWIFTBAN_STATS="$stats" det_awk \
        -v now="$NOW_EPOCH" -v win="$WINDOW" -v fmt="$LOG_FORMAT" '
    function ipv4(s, a,n,i) {
        n=split(s,a,".")
        if(n!=4) return 0
        for(i=1;i<=4;i++)
            if(a[i]!~/^[0-9]{1,3}$/ || a[i]+0>255 || (length(a[i])>1 && a[i]~/^0/)) return 0
        return 1
    }
    function hexgroups(s, a,n,i) {
        if(s=="") return 0
        n=split(s,a,":")
        for(i=1;i<=n;i++) if(a[i]!~/^[0-9a-fA-F]{1,4}$/) return -100
        return n
    }
    function validip(s, p,left,right,tail,i) {
        if(index(s,":")==0) return ipv4(s)
        if(s!~/^[0-9a-fA-F:.]+$/) return 0
        if(index(s,".")) {
            for(i=length(s);i>0 && substr(s,i,1)!=":";i--) {}
            tail=substr(s,i+1)
            if(!ipv4(tail)) return 0
            s=substr(s,1,i) "0:0"
        }
        p=index(s,"::")
        if(!p) return hexgroups(s)==8
        if(index(substr(s,p+2),"::")) return 0
        left=hexgroups(substr(s,1,p-1)); right=hexgroups(substr(s,p+2))
        return left>=0 && right>=0 && left+right<8
    }
    # 引号内的 [Client ...] 只是字符串，不是结构化字段。
    function tokens(s, i,c,start,q,v,n) {
        for(i in t) delete t[i]
        for(i in kind) delete kind[i]
        i=1; n=0
        while(i<=length(s)) {
            if(substr(s,i,1)==" ") {i++; continue}
            c=substr(s,i,1); v=""
            if(c=="\"" || c=="[") {
                q=(c=="\"" ? "\"" : "]")
                kind[++n]=(c=="\"" ? "q" : "b"); i++
                while(i<=length(s) && substr(s,i,1)!=q) {
                    c=substr(s,i,1)
                    if(c=="\\" && q=="\"") {
                        if(i==length(s)) return 0
                        v=v c substr(s,i+1,1); i+=2
                    } else {v=v c; i++}
                }
                if(i>length(s)) return 0
                i++
                if(i<=length(s) && substr(s,i,1)!=" ") return 0
            } else {
                kind[++n]="w"; start=i
                while(i<=length(s) && substr(s,i,1)!=" ") i++
                v=substr(s,start,i-start)
                if(v~/["\[\]]/) return 0
            }
            t[n]=v
        }
        return n
    }
    function timestamp(s, a,n,date,zone,wall,h,m) {
        n=split(s,a," ")
        if(n!=2) return -1
        date=a[1]; zone=a[2]
        if(date!~/^[0-9]{2}\/[A-Z][a-z]{2}\/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}$/ ||
           zone!~/^[+-][0-9]{4}$/) return -1
        split(date,a,/[\/:]/)
        if(!(a[2] in months) || a[3]+0<1970) return -1
        wall=mktime(a[3] " " months[a[2]] " " a[1] " " a[4] " " a[5] " " a[6] " 0")
        if(wall<0 || strftime("%d/%b/%Y:%H:%M:%S",wall)!=date) return -1
        h=substr(zone,2,2)+0; m=substr(zone,4,2)+0
        if(h>23 || m>59) return -1
        return wall-(substr(zone,1,1)=="+" ? 1 : -1)*(h*3600+m*60)
    }
    function method(s) {return s=="-" || s~/^[A-Z]+$/}
    function parse(s, family, n,i,j,k,up,a,num,detected) {
        n=tokens(s)
        if(!n) return 0
        if(kind[1]=="b") {
            j=0
            for(i=3;i+9<=n;i++) {
                if(t[i]=="-" && kind[i]=="w" && method(t[i+1]) &&
                   kind[i+1]=="w" && t[i+2]~/^https?$/ && kind[i+2]=="w" &&
                   (kind[i+3]=="w" || (kind[i+3]=="b" && index(t[i+3],":") && validip(t[i+3]))) &&
                   kind[i+4]=="q" && kind[i+5]=="b" &&
                   t[i+5]~/^Client /) {
                    if(j) return 0
                    j=i
                }
            }
            if(!j || t[j-1]!~/^[1-5][0-9]{2}$/ || kind[j-1]!="w") return 0
            detected=(j==3 ? "npm_standard" : "npm_proxy")
            if(detected=="npm_proxy") {
                if(j<5 || t[2]!~/^(-|MISS|BYPASS|EXPIRED|STALE|UPDATING|REVALIDATED|HIT)$/) return 0
                up=t[3]
                for(k=4;k<=j-2;k++) up=up " " t[k]
                if(up!~/^(-|[0-9]{3})( *[,:] *(-|[0-9]{3}))*$/) return 0
                for(k=2;k<=j-2;k++) if(kind[k]!="w") return 0
            }
            if(kind[j+6]!="b" || t[j+6]!~/^Length [0-9]+$/ ||
               kind[j+7]!="b" || t[j+7]!~/^Gzip /) return 0
            k=j+8
            if(kind[k]=="b" && t[k]~/^Sent-to /) k++
            if(k+1>n || kind[k]!="q" || kind[k+1]!="q") return 0
            ip=substr(t[j+5],8); status=t[j-1]; verb=t[j+1]
            host=tolower(t[j+3]); uri=t[j+4]; ua=t[k]; ref=t[k+1]; stamp=t[1]
            if(kind[j+3]=="b") host="[" host "]"
            if(host=="" || host~/[[:space:]]/) return 0
        } else {
            detected="combined"
            if(n<9 || kind[1]!="w" || kind[2]!="w" || kind[3]!="w" ||
               kind[4]!="b" || kind[5]!="q" || kind[6]!="w" ||
               t[6]!~/^[1-5][0-9]{2}$/ || t[7]!~/^[0-9]+$/ ||
               kind[7]!="w" || kind[8]!="q" || kind[9]!="q") return 0
            ip=t[1]; stamp=t[4]; status=t[6]; host="@file:" family
            ua=t[9]; ref=t[8]
            if(t[5]=="-") {verb="-"; uri="-"}
            else {
                num=split(t[5],a," ")
                if(num!=3 || !method(a[1]) || a[3]!~/^HTTP\/[0-9]+(\.[0-9]+)?$/) return 0
                verb=a[1]; uri=a[2]
            }
        }
        if(fmt!="auto" && fmt!=detected) return 0
        if(!validip(ip) || uri=="" || uri~/[[:space:]]/) return 0
        epoch=timestamp(stamp)
        if(epoch<0) return 0
        ip=tolower(ip)
        return 1
    }
    BEGIN {
        OFS="\t"
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", names, " ")
        for(i=1;i<=12;i++) months[names[i]]=i
    }
    {
        first=index($0,"\t")
        source=substr($0,1,first-1); rest=substr($0,first+1)
        second=index(rest,"\t"); family=substr(rest,1,second-1); raw=substr(rest,second+1)
        sources[source]=1
        if(!first || !second || raw~/[[:cntrl:]]/ || !parse(raw,family)) {
            invalid[source]++; next
        }
        if(epoch>now) {future[source]++; next}
        if(epoch<now-win) {expired[source]++; next}
        valid[source]++
        # 同家族跨文件采用最大重数，避免轮转重叠引起重复封禁统计。
        occurrence=++perfile[source SUBSEP raw]
        key=family SUBSEP raw
        if(occurrence<=maximum[key]) {duplicate[source]++; next}
        maximum[key]=occurrence
        print epoch,ip,status,verb,host,uri,ua,ref,source
    }
    END {
        for(source in sources)
            print source,valid[source]+0,invalid[source]+0,expired[source]+0,future[source]+0,duplicate[source]+0 > ENVIRON["SWIFTBAN_STATS"]
    }' "$src" > "$dst"
}

#---------------- 主检测流程 ----------------
det_run() (
    local dry_run="${1:-0}" workdir cnt lines source valid invalid expired future duplicate
    det_check_config || return 1
    if ! det_awk 'BEGIN {if(mktime("2026 11 12 00 00 00")<0 || "123" !~ /^[0-9]{3}$/) exit 1}' >/dev/null 2>&1; then
        log_error "当前 awk 需要支持 mktime 和区间正则，请安装 gawk 或较新版本 mawk"
        return 1
    fi
    workdir=$(mktemp -d) || return 1
    trap 'rm -rf "$workdir"' EXIT
    NOW=$(date -u +%s)
    NOW_EPOCH="$NOW"
    if [[ "$dry_run" != "1" ]]; then
        mkdir -p "$STATE_DIR" || return 1
        touch "$(_state_file)" "$(_banlog_file)" || return 1
        det_restore
        det_unban_expired || return 1
    fi
    if ! det_collect "$workdir"; then
        log_error "日志收集失败，本轮停止新增封禁"
        return 1
    fi
    : > "$workdir/stats.tsv" || return 1
    if ! det_parse "$workdir/input.tsv" "$workdir/recent.log" "$workdir/stats.tsv"; then
        log_error "日志解析程序失败，本轮停止新增封禁"
        return 1
    fi
    while IFS=$'\t' read -r source valid invalid expired future duplicate; do
        log_info "日志解析 $source | 有效=$valid 格式错误=$invalid 过期=$expired 未来=$future 重复=$duplicate"
        if (( invalid > 0 )); then
            log_warn "日志 $source 存在无法解析的记录，已跳过"
        fi
    done < "$workdir/stats.tsv"
    if ! det_detect_all "$workdir"; then
        log_error "日志统计失败，本轮停止新增封禁"
        return 1
    fi
    if [[ "$dry_run" == "1" ]]; then det_decide "$workdir" dry; else det_decide "$workdir"; fi
    lines=$(wc -l < "$workdir/recent.log")
    cnt=$(fw_count)
    log_info "完成 | 窗口内 $lines 行 | 当前封禁 IPv4=${cnt%:*} IPv6=${cnt#*:}"
)

# 只对标准化字段执行匹配，不再对整条原始日志运行 grep。
det_detect_all() {
    local wd="$1" category
    for category in 444 scan evilpath payload ua auth api apirate emptyua freq; do
        : > "$wd/ip_$category.txt" || return 1
    done
    SWIFTBAN_WORKDIR="$wd" SAFE_PATH="$SAFE_PATH" GIT_SAFE="$GIT_SAFE" \
    EVIL_PATH="$EVIL_PATH" EVIL_PAYLOAD="$EVIL_PAYLOAD" EVIL_UA="$EVIL_UA" \
    LOGIN_PATH="$LOGIN_PATH" det_awk -F '\t' '
    function count(category,key) {counts[category SUBSEP key]++}
    {
        ip=$2; status=$3; host=$5; uri=$6; ua=$7; ref=$8
        path=uri; sub(/\?.*$/,"",path)
        if(path ~ /^[A-Za-z][A-Za-z0-9+.-]*:\/\//) {
            sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/]*/,"",path)
            if(path=="") path="/"
        }
        lowpath=tolower(path)
        git=(path ~ ENVIRON["GIT_SAFE"])
        if(status=="444") count("444",ip)
        if((status=="404" || status=="400") && path !~ ENVIRON["SAFE_PATH"]) count("scan",ip)
        if(!git && lowpath ~ tolower(ENVIRON["EVIL_PATH"])) count("evilpath",ip)
        payload=tolower(ENVIRON["EVIL_PAYLOAD"])
        if(!git && host!="git.43tc.cn" &&
           (tolower(uri) ~ payload || tolower(ua) ~ payload || tolower(ref) ~ payload)) count("payload",ip)
        if(tolower(ua) ~ tolower(ENVIRON["EVIL_UA"])) count("ua",ip)
        if((status=="401" || status=="403") && lowpath ~ tolower(ENVIRON["LOGIN_PATH"])) count("auth",ip)
        # 长度前缀避免域名、文件路径或 URI 中的分隔字符造成键碰撞。
        endpoint=length(host) ":" host uri
        count("api",ip " " endpoint)
        count("apirate",int($1/60) "|" ip "|" endpoint)
        if(ua=="" || ua=="-") count("emptyua",ip)
        count("freq",ip)
    }
    END {
        for(key in counts) {
            splitat=index(key,SUBSEP)
            category=substr(key,1,splitat-1)
            print counts[key],substr(key,splitat+1) > (ENVIRON["SWIFTBAN_WORKDIR"] "/ip_" category ".txt")
        }
    }' "$wd/recent.log" || return 1
    for category in 444 scan evilpath payload ua auth api apirate emptyua freq; do
        LC_ALL=C sort -rn "$wd/ip_$category.txt" > "$wd/sorted" &&
            mv "$wd/sorted" "$wd/ip_$category.txt" || return 1
    done
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
                    wl_is_whitelisted "$ip" && continue
                    fw_is_banned "$ip" && continue
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
