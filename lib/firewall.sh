#!/bin/bash
#==============================================================
# SwiftBan - 防火墙抽象层
# 支持: iptables / ip6tables（DOCKER-USER 链）
#==============================================================

# 判断是否 IPv6
is_ipv6() { [[ "$1" == *:* ]]; }

# 封禁 IP（失败返回非零并记录错误，不静默吞掉）
fw_ban() {
    local ip="$1" err
    local -a mark=(-j DROP)
    if [[ -n "${RT_OWNER:-}" ]]; then
        rt_may_enforce || { log_error "检测已停止，不再写入封禁规则"; return 1; }
        mark=(-m comment --comment "$RT_OWNER" -j DROP)
    fi
    if is_ipv6 "$ip"; then
        if ! command -v ip6tables >/dev/null 2>&1; then
            log_error "未安装 ip6tables，无法封禁 IPv6 地址 ${ip}"
            return 1
        fi
        [[ -z "${RT_OWNER:-}" ]] || rt_record "$STATE_DIR/.ipv6-used" used || return 1
        if ! err=$(ip6tables -I "${FIREWALL_CHAIN}" 1 -s "$ip" "${mark[@]}" 2>&1); then
            log_error "ip6tables 封禁失败 ${ip}: ${err}"
            return 1
        fi
    else
        if ! err=$(iptables -I "${FIREWALL_CHAIN}" 1 -s "$ip" "${mark[@]}" 2>&1); then
            log_error "iptables 封禁失败 ${ip}: ${err}"
            return 1
        fi
    fi
    return 0
}

# 解封 IP（尽力而为：规则不存在不算失败，其他错误记录告警）
fw_unban() {
    local ip="$1" err
    if [[ -n "${RT_OWNER:-}" ]]; then
        fw_remove_managed "$ip"
        return
    fi
    if is_ipv6 "$ip"; then
        if ! command -v ip6tables >/dev/null 2>&1; then
            log_warn "未安装 ip6tables，跳过 IPv6 地址 ${ip} 的解封规则操作"
            return 0
        fi
        if ! err=$(ip6tables -D "${FIREWALL_CHAIN}" -s "$ip" -j DROP 2>&1); then
            log_warn "ip6tables 解封 ${ip} 返回: ${err}"
        fi
    else
        if ! err=$(iptables -D "${FIREWALL_CHAIN}" -s "$ip" -j DROP 2>&1); then
            log_warn "iptables 解封 ${ip} 返回: ${err}"
        fi
    fi
    return 0
}

# 是否已封禁
fw_is_banned() {
    local ip="$1"
    if [[ -n "${RT_OWNER:-}" ]]; then
        local tool=iptables style
        is_ipv6 "$ip" && tool=ip6tables
        command -v "$tool" >/dev/null 2>&1 || return 1
        for style in tagged legacy; do
            if [[ "$style" == tagged ]]; then
                "$tool" -C "$FIREWALL_CHAIN" -s "$ip" -m comment --comment "$RT_OWNER" -j DROP 2>/dev/null && return 0
            else
                "$tool" -C "$FIREWALL_CHAIN" -s "$ip" -j DROP 2>/dev/null && return 0
            fi
        done
        return 1
    fi
    if is_ipv6 "$ip"; then
        command -v ip6tables >/dev/null 2>&1 || return 1
        ip6tables -C "${FIREWALL_CHAIN}" -s "$ip" -j DROP 2>/dev/null && return 0
    else
        iptables -C "${FIREWALL_CHAIN}" -s "$ip" -j DROP 2>/dev/null && return 0
    fi
    return 1
}

# 输出精确归属：chain<TAB>source<TAB>tagged|legacy。
# 只识别本实例标记，或当前配置链内且在 banlist 中的历史无标记纯 DROP。
# IPv6 展开后比较，兼容内核输出压缩形式或 /128。
fw_inventory() (
    local tool="$1" wanted="${2:-}" tmp state="${BANLIST:-$STATE_DIR/banlist.txt}" owner="${RT_OWNER:-}"
    [[ -n "$owner" ]] || {
        [[ ! -r "$STATE_DIR/.instance-id" ]] || IFS= read -r owner < "$STATE_DIR/.instance-id"
        [[ -z "$owner" ]] || owner="swiftban:$owner"
    }
    command -v "$tool" >/dev/null 2>&1 || return 1
    tmp=$(mktemp) || return 1
    trap 'rm -f "$tmp"' EXIT
    LC_ALL=C "$tool" -S > "$tmp" || return 1
    [[ -f "$state" ]] || state=/dev/null
    SWIFTBAN_OWNER="$owner" SWIFTBAN_CHAIN="$FIREWALL_CHAIN" SWIFTBAN_WANTED="$wanted" awk '
    function ipv4(s,a,n,i) {
        n=split(s,a,".")
        if(n!=4) return ""
        for(i=1;i<=4;i++) if(a[i]!~/^[0-9]+$/ || a[i]+0>255) return ""
        return (a[1]+0) "." (a[2]+0) "." (a[3]+0) "." (a[4]+0)
    }
    function hex(s, i,v,d) {
        v=0; s=tolower(s)
        for(i=1;i<=length(s);i++) {
            d=index("0123456789abcdef",substr(s,i,1))-1
            if(d<0) return -1
            v=v*16+d
        }
        return v
    }
    function canon(s, p,a,b,n,m,i,r,v,tail) {
        sub(/\/32$/,"",s); sub(/\/128$/,"",s)
        if(index(s,":")==0) return ipv4(s)
        if(s!~/^[0-9a-fA-F:.]+$/) return ""
        if(index(s,".")) {
            for(i=length(s);i>0 && substr(s,i,1)!=":";i--) {}
            tail=ipv4(substr(s,i+1)); if(tail=="") return ""
            split(tail,a,".")
            s=substr(s,1,i) sprintf("%x:%x",a[1]*256+a[2],a[3]*256+a[4])
        }
        p=index(s,"::")
        if(p) {
            n=split(substr(s,1,p-1),a,":"); m=split(substr(s,p+2),b,":")
            if(substr(s,1,p-1)=="") n=0
            if(substr(s,p+2)=="") m=0
            if(n+m>=8) return ""
        } else {n=split(s,a,":");m=0;if(n!=8)return ""}
        r=""
        for(i=1;i<=n;i++) {v=hex(a[i]); if(a[i]=="" || v<0 || v>65535)return "";r=r sprintf("%04x",v)}
        for(i=0;i<8-n-m;i++) r=r "0000"
        for(i=1;i<=m;i++) {v=hex(b[i]); if(b[i]=="" || v<0 || v>65535)return "";r=r sprintf("%04x",v)}
        return r
    }
    FILENAME==ARGV[1] {
        split($0,a,/\|/); key=canon(a[1]); if(key!="") legacy[key]=1
        next
    }
    $1=="-A" {
        chain=$2; source="";comment="";target=""; module=""; valid=1
        for(i=3;i<=NF;i+=2) {
            if($i=="-s") source=$(i+1)
            else if($i=="-j") target=$(i+1)
            else if($i=="-m") module=$(i+1)
            else if($i=="--comment") {comment=$(i+1);gsub(/^"|"$/,"",comment)}
            else valid=0
        }
        owned=(comment!="" && comment==ENVIRON["SWIFTBAN_OWNER"])
        if(ENVIRON["SWIFTBAN_WANTED"]!="" && canon(source)!=canon(ENVIRON["SWIFTBAN_WANTED"])) next
        if(owned && (!valid || NF!=10 || target!="DROP" || module!="comment" || canon(source)=="")) {
            print "无法识别带本实例标记的规则，拒绝误删" > "/dev/stderr"; failed=1; next
        }
        if(owned) print chain "\t" source "\ttagged"
        else if(valid && NF==6 && target=="DROP" && chain==ENVIRON["SWIFTBAN_CHAIN"] && (canon(source) in legacy))
            print chain "\t" source "\tlegacy"
    }
    END {if(failed)exit 1}' "$state" "$tmp"
)

fw_needs_ipv6() {
    [[ -e "$STATE_DIR/.ipv6-used" ]] && return 0
    [[ -r "${BANLIST:-$STATE_DIR/banlist.txt}" ]] &&
        awk -F '|' '$1 ~ /:/ {found=1} END {exit !found}' "${BANLIST:-$STATE_DIR/banlist.txt}"
}

# 有指定 IP 时只撤销它；否则撤销全部本实例规则。失败不修改 banlist。
fw_remove_managed() (
    local wanted="${1:-}" tool tmp after chain ip style failed=0
    local -a mark=(-j DROP)
    tmp=$(mktemp "$STATE_DIR/.remove.XXXXXX") || return 1
    after=$(mktemp "$STATE_DIR/.verify.XXXXXX") || { rm -f "$tmp"; return 1; }
    trap 'rm -f "$tmp" "$after"' EXIT
    for tool in iptables ip6tables; do
        if [[ -n "$wanted" ]]; then
            if is_ipv6 "$wanted"; then [[ "$tool" == ip6tables ]] || continue
            else [[ "$tool" == iptables ]] || continue; fi
        fi
        if [[ "$tool" == ip6tables ]] && ! command -v ip6tables >/dev/null 2>&1; then
            if fw_needs_ipv6; then log_error "缺少 ip6tables，IPv6 规则是否撤销无法确认"; failed=1; fi
            continue
        fi
        if ! fw_inventory "$tool" "$wanted" > "$tmp"; then
            # 没有已知 IPv6 使用时，内核不支持可选 IPv6 不影响 IPv4 停止。
            if [[ "$tool" == ip6tables ]] && ! fw_needs_ipv6; then continue; fi
            log_error "$tool 规则读取失败，不能确认已撤销"
            failed=1; continue
        fi
        while IFS=$'\t' read -r chain ip style; do
            [[ -n "$chain" ]] || continue
            mark=(-j DROP)
            [[ "$style" != tagged ]] || mark=(-m comment --comment "$RT_OWNER" -j DROP)
            if ! "$tool" -D "$chain" -s "$ip" "${mark[@]}"; then
                log_error "$tool 撤销规则失败: $chain $ip"; failed=1
            fi
        done < "$tmp"
        if ! fw_inventory "$tool" "$wanted" > "$after"; then failed=1; continue; fi
        if [[ -s "$after" ]]; then
            log_error "$tool 仍有本实例管理的规则"; failed=1
        fi
    done
    (( failed == 0 ))
)

fw_managed_count() (
    local tool count v4=0 v6=0 tmp
    [[ -d "$STATE_DIR" ]] || { echo "IPv4=0 IPv6=0"; return 0; }
    tmp=$(mktemp) || return 1
    trap 'rm -f "$tmp"' EXIT
    for tool in iptables ip6tables; do
        if [[ "$tool" == ip6tables ]] && ! command -v ip6tables >/dev/null 2>&1; then
            if fw_needs_ipv6; then v6=未知; fi
            continue
        fi
        if fw_inventory "$tool" > "$tmp" 2>/dev/null; then count=$(wc -l < "$tmp"); else count=未知; fi
        if [[ "$tool" == iptables ]]; then v4="$count"; else v6="$count"; fi
    done
    echo "IPv4=$v4 IPv6=$v6"
)

# 当前封禁数量（用 -S 精确统计规则，避免误计链内其他 DROP）
fw_count() {
    local c4 c6=0
    c4=$(iptables -S "${FIREWALL_CHAIN}" 2>/dev/null | grep -c -- '-j DROP' || true)
    if command -v ip6tables >/dev/null 2>&1; then
        c6=$(ip6tables -S "${FIREWALL_CHAIN}" 2>/dev/null | grep -c -- '-j DROP' || true)
    fi
    echo "${c4}:${c6}"
}

# 列出所有封禁规则
fw_list() {
    local ip
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        echo "$ip"
    done < <(iptables -S "${FIREWALL_CHAIN}" 2>/dev/null | grep -- '-j DROP' | awk '{for(i=1;i<=NF;i++) if($i=="-s") print $(i+1)}' | sort -u)
}
