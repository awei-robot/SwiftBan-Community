#!/bin/bash
# 归属地为可选展示信息；只有显式 geo refresh 可以联网。
geo_usage() {
    cat <<'HELP'
用法:
  swiftban geo refresh [--ip IP] [--force]
  swiftban geo show IP
手动查询 ip-api 并缓存。默认刷新封禁及保留期内正式/演练 WATCH，最多请求30个IP。
有效缓存保留7天；失败退避1小时。--force 绕过缓存期限，不绕过服务限流。
list/watch/doctor/扫描均不联网。需要可选 curl + jq；缓存位于 STATE_DIR/geo。
HELP
}

# 用本地地址分类跳过无须查询的地址。
geo_local() {
    local ip="$1" net first
    if [[ "$ip" == *:* ]]; then
        first="${ip%%:*}"
        # IPv4 映射 IPv6 仍按其底层 IPv4 范围判断。
        if [[ "$ip" == 0000:0000:0000:0000:0000:ffff:* ]]; then
            local tail="${ip##*:}" prev="${ip%:*}"
            prev="${prev##*:}"
            geo_local "$((16#$prev >> 8)).$((16#$prev & 255)).$((16#$tail >> 8)).$((16#$tail & 255))"
            return
        fi
        [[ "$ip" == 0000:0000:0000:0000:0000:0000:0000:0000 || "$ip" == 0000:0000:0000:0000:0000:0000:0000:0001 ]] && return 0
        (( (16#$first & 0xfe00) == 0xfc00 || (16#$first & 0xffc0) == 0xfe80 || (16#$first & 0xff00) == 0xff00 ))
    else
        for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
            wl_ip_in_cidr "$ip" "$net" && return 0
        done
        return 1
    fi
}

geo_valid() {
    jq -e --arg ip "$1" '
      .version==1 and .ip==$ip and (.updated_at|type)=="number" and
      (.last_attempt|type)=="number" and (.retry_after|type)=="number" and
      (.last_error|type)=="string" and
      ([.updated_at,.last_attempt,.retry_after]|all(.[];.>=0 and .<=99999999999 and .==floor)) and
      (.geo==null or (.geo|type)=="object" and
        ([.geo.country,.geo.regionName,.geo.city,.geo.isp,.geo.org,.geo["as"],.geo.query] | all(.[];type=="string")))
    ' "$2" >/dev/null 2>&1
}

# 每次读取一个原子发布的快照；损坏/缺失缓存降级，不联网也不写文件。
geo_read() (
    local ip="$1" file="$STATE_DIR/geo/$1.json" tmp now
    command -v jq >/dev/null 2>&1 || { echo '{"geo":null,"state":"unavailable","location":"功能不可用","isp":"-"}'; return; }
    if geo_local "$ip"; then echo '{"geo":null,"state":"local","location":"内网/保留地址","isp":"-"}'; return; fi
    tmp=$(mktemp) || return 1
    trap 'rm -f "$tmp"' EXIT
    if [[ ! -f "$file" ]] || ! cat "$file" > "$tmp" || ! geo_valid "$ip" "$tmp"; then
        echo '{"geo":null,"state":"missing","location":"未查询","isp":"-"}'
        return
    fi
    now=$(date +%s)
    jq -c --argjson now "$now" '
      def clean: gsub("[\u0000-\u001f\u007f-\u009f]";" ")|.[0:256];
      .last_error |= clean |
      if .geo==null then .+{state:"failed",location:"查询失败",isp:"-"}
      else .geo |= ({"country":.country,"regionName":.regionName,"city":.city,"isp":.isp,"org":.org,"as":.["as"],"query":.query}|with_entries(.value |= clean)) |
        .+{state:(if $now-.updated_at>=604800 then "stale" else "fresh" end),
        location:([.geo.country,.geo.regionName,.geo.city]|map(select(length>0))|reduce .[] as $x ([];if index($x)==null then .+[$x] else . end)|join("/")),isp:.geo.isp} |
        .location=(if .location=="" then "未知" else .location end) |
        if .state=="stale" then .location+="（已过期）" else . end
      end' "$tmp"
)

# 为当前展示的行附加来源地/运营商/geo JSON；相同IP仅读一次缓存。
geo_enrich() (
    local input="$1" output="$2" column="$3" limit="$4" line ip data location isp object
    local cache
    cache=$(mktemp -d) || return 1
    trap 'rm -rf "$cache"' EXIT
    : > "$output" || return 1
    while IFS= read -r line; do
        ip=$(printf '%s\n' "$line" | awk -F '\t' -v c="$column" '{print $c}')
        ip=$(wl_normalize_ip "$ip") || return 1
        if [[ ! -f "$cache/$ip" ]]; then
            data=$(geo_read "$ip") || return 1
            if command -v jq >/dev/null 2>&1; then
                location=$(jq -r '.location' <<< "$data") || return 1
                isp=$(jq -r '.isp|if length==0 then "-" else . end' <<< "$data") || return 1
                object=$(jq -c '.geo' <<< "$data") || return 1
            else location="功能不可用"; isp="-"; object=null; fi
            printf '%s\t%s\t%s\n' "$location" "$isp" "$object" > "$cache/$ip" || return 1
        fi
        printf '%s\t' "$line" >> "$output" && cat "$cache/$ip" >> "$output" || return 1
    done < <(awk -v limit="$limit" 'NR<=limit' "$input")
)

# 通用表格：ASCII/中文UTF-8按终端宽度补空格；最后一列不补齐。
geo_table() {
    LC_ALL=C det_awk -F '\t' '
    function width(s,i,c,n) {n=0;for(i=1;i<=length(s);){c=substr(s,i,1);if(c~/[\340-\357]/){n+=2;i+=3}else if(c~/[\360-\367]/){n+=2;i+=4}else if(c~/[\300-\337]/){n++;i+=2}else{n++;i++}}return n}
    {for(i=1;i<=NF;i++){v[NR,i]=$i;w=width($i);if(w>ws[i])ws[i]=w}if(NF>cols)cols=NF}
    END {for(r=1;r<=NR;r++){for(i=1;i<=cols;i++){printf "%s",v[r,i];if(i<cols)printf "%*s",ws[i]-width(v[r,i])+2,""}print ""}}' "$1"
}

geo_save() (
    local ip="$1" tmp
    tmp=$(mktemp "$STATE_DIR/geo/.cache.XXXXXX") || return 1
    trap 'rm -f "$tmp"' EXIT
    cat > "$tmp" && geo_valid "$ip" "$tmp" && mv -f "$tmp" "$STATE_DIR/geo/$ip.json"
)

geo_rate_save() {
    local next="$1" tmp
    tmp=$(mktemp "$STATE_DIR/geo/.rate.XXXXXX") || return 1
    if printf '%s\n' "$next" > "$tmp" && mv -f "$tmp" "$STATE_DIR/geo/rate-limit"; then return 0; fi
    rm -f "$tmp"; return 1
}

geo_refresh() (
    local wanted='' force=0 ip file now next=0 snapshot result code query error body headers
    local requested=0 success=0 failed=0 skipped=0 remaining=0 quota=0 ttl rl cutoff
    local wd
    while (( $# )); do
        case "$1" in
            --ip) (( $#>=2 )) || return 1; wanted=$(wl_normalize_ip "$2") || return 1; shift 2 ;;
            --force) force=1; shift ;;
            -h|--help) geo_usage; return ;;
            *) geo_usage >&2; return 1 ;;
        esac
    done
    rt_require_root || return 1
    for file in curl jq flock; do command -v "$file" >/dev/null 2>&1 || { echo "错误: 归属地刷新需要 $file" >&2; return 1; }; done
    umask 077
    mkdir -p "$STATE_DIR/geo" || return 1
    chmod 700 "$STATE_DIR/geo" || return 1
    exec 7> "$STATE_DIR/geo/.refresh.lock" || return 1
    flock -n 7 || { echo '错误: 归属地刷新正在执行' >&2; return 1; }
    wd=$(mktemp -d) || return 1
    trap 'rm -rf "$wd"' EXIT
    : > "$wd/ips"
    if [[ -n "$wanted" ]]; then echo "$wanted" > "$wd/ips"
    else
        if [[ -f "$BANLIST" ]]; then awk -F '|' '$1!="" {print $1}' "$BANLIST" >> "$wd/ips" || return 1; fi
        : > "$wd/watch"
        cutoff=$(( $(date +%s) - ${WATCH_RETENTION_DAYS:-7} * 86400 ))
        if [[ -d "$STATE_DIR/watch" ]]; then
            find "$STATE_DIR/watch" -type f -name '.pending.*.tsv' > "$wd/files" || return 1
            while IFS= read -r file; do
                [[ -e "$file" ]] || continue
                awk -F '\t' -v cutoff="$cutoff" '!/^#/ && NF==7 && $1>=cutoff {print $1 "\t" $2}' "$file" >> "$wd/watch" || return 1
            done < "$wd/files"
        fi
        sort -t $'\t' -k1,1nr "$wd/watch" | cut -f2 >> "$wd/ips" || return 1
    fi
    # 统一规范化，同时保留封禁优先/最新观察优先顺序。
    : > "$wd/normalized"
    while IFS= read -r ip; do
        ip=$(wl_normalize_ip "$ip") || { echo '错误: 候选记录包含非法 IP' >&2; return 1; }
        echo "$ip" >> "$wd/normalized"
    done < "$wd/ips"
    awk '!seen[$0]++' "$wd/normalized" > "$wd/unique" || return 1
    if [[ -r "$STATE_DIR/geo/rate-limit" ]]; then
        IFS= read -r next < "$STATE_DIR/geo/rate-limit" || return 1
        [[ "$next" =~ ^(0|[1-9][0-9]{0,11})$ ]] || { echo '错误: 归属地限流记录损坏' >&2; return 1; }
    fi
    while IFS= read -r ip; do
        if geo_local "$ip"; then skipped=$((skipped+1)); continue; fi
        snapshot=$(geo_read "$ip") || return 1
        now=$(date +%s)
        if (( !force )) && jq -e --argjson now "$now" '.state=="fresh" or (.retry_after // 0)>$now' <<< "$snapshot" >/dev/null; then
            skipped=$((skipped+1)); continue
        fi
        if (( requested>=30 || quota )); then remaining=$((remaining+1)); continue; fi
        if (( next>now )); then
            if (( next-now>3 )); then quota=1; remaining=$((remaining+1)); continue; fi
            sleep "$((next-now))"
        fi
        now=$(date +%s)
        # 请求发出前持久化间隔；中断后下次刷新仍遵守间隔。
        geo_rate_save "$((now+3))" || return 1
        body="$wd/body"; headers="$wd/headers"
        : > "$body"; : > "$headers"
        requested=$((requested+1))
        error=''
        if code=$(curl --silent --show-error --proto '=http' --connect-timeout 2 --max-time 5 --max-filesize 65536 \
            --dump-header "$headers" --output "$body" --write-out '%{http_code}' \
            "http://ip-api.com/json/$ip?lang=zh-CN&fields=status,message,country,regionName,city,isp,org,as,query" 2> "$wd/error"); then :
        else error='请求超时或网络错误'; fi
        next=$((now+3))
        rl=$(awk 'tolower($1)=="x-rl:" {gsub(/\r/,"",$2);v=$2} END{print v}' "$headers")
        ttl=$(awk 'tolower($1)=="x-ttl:" {gsub(/\r/,"",$2);v=$2} END{print v}' "$headers")
        if [[ "$rl" == 0 || "$code" == 429 ]]; then
            if [[ "$ttl" =~ ^[0-9]{1,6}$ ]] && (( 10#$ttl>0 )); then ttl=$((10#$ttl)); else ttl=60; fi
            next=$(( $(date +%s)+ttl )); quota=1
        fi
        geo_rate_save "$next" || return 1
        if [[ -z "$error" && "$code" != 200 ]]; then error="HTTP $code"; fi
        result='null'
        if [[ -z "$error" ]]; then
            if ! jq -e 'type=="object" and .status=="success" and ([.country,.regionName,.city,.isp,.org,.["as"],.query]|all(.[];type=="string"))' "$body" >/dev/null 2>&1; then
                error='接口失败或返回无效 JSON'
                if jq -e '.status=="fail" and (.message|type)=="string"' "$body" >/dev/null 2>&1; then
                    error=$(jq -r '.message|gsub("[\u0000-\u001f\u007f-\u009f]";" ")|.[0:256]' "$body")
                fi
            else
                query=$(jq -r '.query' "$body")
                query=$(wl_normalize_ip "$query") || query=''
                if [[ "$query" != "$ip" ]]; then error='返回 IP 与请求不一致'
                else result=$(jq -c '.|{"country":.country,"regionName":.regionName,"city":.city,"isp":.isp,"org":.org,"as":.["as"],"query":.query}|with_entries(.value |= (gsub("[\u0000-\u001f\u007f-\u009f]";" ")|.[0:256]))' "$body") || return 1; fi
            fi
        fi
        now=$(date +%s)
        if [[ -z "$error" ]]; then
            jq -n --arg ip "$ip" --argjson now "$now" --argjson geo "$result" \
                '{version:1,ip:$ip,updated_at:$now,last_attempt:$now,retry_after:0,last_error:"",geo:$geo}' > "$wd/cache" || return 1
            success=$((success+1))
        else
            jq -n --arg ip "$ip" --argjson now "$now" --arg error "$error" --argjson old "$snapshot" \
                '{version:1,ip:$ip,updated_at:($old.updated_at//0),last_attempt:$now,retry_after:($now+3600),last_error:$error,geo:$old.geo}' > "$wd/cache" || return 1
            failed=$((failed+1)); printf '查询失败 %s: %s\n' "$ip" "$error" >&2
        fi
        geo_save "$ip" < "$wd/cache" || return 1
    done < "$wd/unique"
    printf '归属地刷新: 请求=%s 成功=%s 失败=%s 跳过=%s 剩余=%s\n' "$requested" "$success" "$failed" "$skipped" "$remaining"
    if (( quota )); then printf '限流暂停，请在 Unix 时间 %s 后重试\n' "$next"; fi
    (( failed==0 && remaining==0 ))
)

cmd_geo() {
    case "${1:---help}" in
        -h|--help) geo_usage ;;
        refresh) shift; geo_refresh "$@" ;;
        show)
            [[ $# == 2 ]] || { geo_usage >&2; return 1; }
            local ip data
            ip=$(wl_normalize_ip "$2") || return 1
            data=$(geo_read "$ip") || return 1
            echo "=== IP 来源地缓存: $ip ==="
            if command -v jq >/dev/null 2>&1; then
                jq -r 'def time: if .==null or .==0 then "-" else todateiso8601 end;
                  "缓存状态: \({fresh:"有效",stale:"已过期",failed:"查询失败",missing:"未查询",local:"内网/保留地址",unavailable:"功能不可用"}[.state])\n来源地: \(.location)\n运营商: \(.isp)",
                  (if .geo then "国家: \(.geo.country)\n省/州: \(.geo.regionName)\n城市: \(.geo.city)\n组织: \(.geo.org)\nAS: \(.geo["as"])\n更新时间: \(.updated_at|todateiso8601)" else empty end),
                  "最近尝试: \(.last_attempt|time)\n重试时间: \(.retry_after|time)\n最近错误: \(.last_error//"")"' <<< "$data"
            else echo '归属地功能不可用，需要 jq'; fi ;;
        *) geo_usage >&2; return 1 ;;
    esac
}

geo_doctor() (
    local dep file mode bad=0
    for dep in curl jq; do
        if command -v "$dep" >/dev/null 2>&1; then echo "通过 归属地可选依赖: $dep"
        else echo "警告 归属地缺少可选依赖: $dep"; fi
    done
    [[ -e "$STATE_DIR/geo" ]] || { echo '提示 尚无归属地缓存，使用 swiftban geo refresh 手动刷新'; return 0; }
    [[ -d "$STATE_DIR/geo" && -r "$STATE_DIR/geo" && -w "$STATE_DIR/geo" && -x "$STATE_DIR/geo" ]] || { echo '失败 归属地缓存目录不可读写'; return 1; }
    mode=$(stat -c '%a' "$STATE_DIR/geo" 2>/dev/null || stat -f '%Lp' "$STATE_DIR/geo") || return 1
    if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 077) != 0 )); then
        echo '失败 归属地缓存目录对组或其他用户开放，请设置权限700'; bad=1
    fi
    command -v jq >/dev/null 2>&1 || { (( bad==0 )); return; }
    for file in "$STATE_DIR/geo/"*.json; do
        [[ -e "$file" ]] || continue
        mode=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file") || return 1
        if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 077) != 0 )); then echo "失败 归属地缓存权限应为600: $file"; bad=1; fi
        if ! geo_valid "$(basename "$file" .json)" "$file"; then echo "失败 归属地缓存格式: $file"; bad=1; fi
    done
    (( bad==0 ))
)

geo_brief() {
    local data
    data=$(geo_read "$1") || return 1
    if command -v jq >/dev/null 2>&1; then
        jq -r '"来源地: \(.location) | 运营商: \(.isp) | 缓存状态: \(.state)"' <<< "$data"
    else echo '来源地: 功能不可用（需要 jq）'; fi
}
