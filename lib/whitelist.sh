#!/bin/bash
#==============================================================
# SwiftBan - 白名单模块
# 支持: 精确 IP / CIDR 网段 / 文件（动态生效）
#==============================================================

# IPv4 转整数（CIDR 匹配用）
wl_ip2int() {
    local a b c d part
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r a b c d <<< "$1"
    for part in "$a" "$b" "$c" "$d"; do
        [[ "$part" != 0?* ]] && (( 10#$part <= 255 )) || return 1
    done
    echo $(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))
}

# 当前仅支持 IPv4 CIDR，掩码必须是 0–32 的十进制整数。
wl_valid_cidr() {
    local cidr="$1" bits
    [[ "$cidr" == */* ]] || return 1
    bits="${cidr#*/}"
    [[ "$bits" =~ ^(0|[1-9][0-9]?)$ ]] && (( bits <= 32 )) || return 1
    wl_ip2int "${cidr%/*}" >/dev/null
}

# CIDR 匹配（IPv4；IPv6 用精确匹配）
wl_ip_in_cidr() {
    local ip="$1" cidr="$2"
    local net bits ipint netint mask
    wl_valid_cidr "$cidr" || return 1
    net="${cidr%/*}"; bits="${cidr#*/}"
    ipint=$(wl_ip2int "$ip") || return 1
    netint=$(wl_ip2int "$net") || return 1
    mask=$(( 0xFFFFFFFF << (32 - bits) & 0xFFFFFFFF ))
    (( (ipint & mask) == (netint & mask) ))
}

# 供解析、白名单、状态删除和防火墙清点共用的地址规范化函数。
ip_awk() {
    cat <<'AWK'
    function ip_v4(s,a,n,i) {
        n=split(s,a,".")
        if(n!=4)return ""
        for(i=1;i<=4;i++)
            if(a[i]!~/^[0-9]+$/ || length(a[i])>3 || a[i]+0>255 ||
               (length(a[i])>1 && substr(a[i],1,1)=="0"))return ""
        return (a[1]+0) "." (a[2]+0) "." (a[3]+0) "." (a[4]+0)
    }
    function ip_hex(s,i,d,v) {
        if(s=="" || length(s)>4)return -1
        s=tolower(s);v=0
        for(i=1;i<=length(s);i++) {
            d=index("0123456789abcdef",substr(s,i,1))-1
            if(d<0)return -1
            v=v*16+d
        }
        return v
    }
    function ip_canon(s,p,a,b,n,m,i,r,v,tail) {
        if(index(s,":")==0)return ip_v4(s)
        if(s!~/^[0-9a-fA-F:.]+$/)return ""
        if(index(s,".")) {
            for(i=length(s);i>0 && substr(s,i,1)!=":";i--) {}
            tail=ip_v4(substr(s,i+1));if(tail=="")return ""
            split(tail,a,".")
            s=substr(s,1,i) sprintf("%x:%x",a[1]*256+a[2],a[3]*256+a[4])
        }
        p=index(s,"::")
        if(p) {
            n=split(substr(s,1,p-1),a,":");m=split(substr(s,p+2),b,":")
            if(p==1)n=0
            if(p+1==length(s))m=0
            if(n+m>=8)return ""
        } else {n=split(s,a,":");m=0;if(n!=8)return ""}
        r=""
        for(i=1;i<=n;i++) {v=ip_hex(a[i]);if(v<0)return "";r=r sprintf("%04x:",v)}
        for(i=0;i<8-n-m;i++)r=r "0000:"
        for(i=1;i<=m;i++) {v=ip_hex(b[i]);if(v<0)return "";r=r sprintf("%04x:",v)}
        return substr(r,1,length(r)-1)
    }
AWK
}

wl_normalize_ip() {
    SWIFTBAN_IP="$1" LC_ALL=C awk "$(ip_awk)"'
        BEGIN {ip=ip_canon(ENVIRON["SWIFTBAN_IP"]);if(ip=="")exit 1;print ip}'
}

# 白名单检查（脚本内 WHITELIST + 独立文件）
wl_is_whitelisted() {
    local ip="$1" entry key other
    if [[ "$ip" == *:* ]]; then key=$(wl_normalize_ip "$ip") || return 1
    else wl_ip2int "$ip" >/dev/null || return 1; key="$ip"; fi
    # 内置列表与独立文件均按地址含义精确比较。
    local -a entries
    IFS=, read -r -a entries <<< "$WHITELIST"
    for entry in "${entries[@]-}"; do
        [[ -n "$entry" ]] || continue
        if [[ "$entry" == "$ip" ]]; then return 0; fi
        if [[ "$entry" == *:* && "$ip" == *:* ]]; then
            other=$(wl_normalize_ip "$entry") || continue
            [[ "$key" != "$other" ]] || return 0
        fi
    done
    if [[ -n "${WHITELIST_FILE}" && -f "${WHITELIST_FILE}" ]]; then
        while IFS= read -r entry || [[ -n "$entry" ]]; do
            entry="${entry%%#*}"
            entry="${entry// /}"
            [[ -z "$entry" ]] && continue
            if [[ "$entry" == */* ]]; then
                wl_ip_in_cidr "$ip" "$entry" && return 0
            elif [[ "$ip" == "$entry" ]]; then return 0
            elif [[ "$entry" == *:* && "$ip" == *:* ]]; then
                other=$(wl_normalize_ip "$entry") || continue
                [[ "$key" != "$other" ]] || return 0
            fi
        done < "${WHITELIST_FILE}"
    fi
    return 1
}

# 配置检查只读验证，非法条目明确指出来源。
wl_check_config() {
    local entry line=0
    local -a entries
    IFS=, read -r -a entries <<< "$WHITELIST"
    for entry in "${entries[@]-}"; do
        [[ -n "$entry" ]] || continue
        wl_normalize_ip "$entry" >/dev/null || { log_error "内置白名单 IP 无效: $entry"; return 1; }
    done
    if [[ -f "$WHITELIST_FILE" ]]; then
        [[ -r "$WHITELIST_FILE" ]] || return 1
        while IFS= read -r entry || [[ -n "$entry" ]]; do
            line=$((line+1))
            entry="${entry%%#*}"; entry="${entry//[[:space:]]/}"
            [[ -n "$entry" ]] || continue
            if [[ "$entry" == */* ]]; then
                wl_valid_cidr "$entry" || { log_error "白名单 $WHITELIST_FILE 第 $line 行 CIDR 无效"; return 1; }
            else
                wl_normalize_ip "$entry" >/dev/null || { log_error "白名单 $WHITELIST_FILE 第 $line 行 IP 无效"; return 1; }
            fi
        done < "$WHITELIST_FILE"
    fi
    return 0
}

wl_normalize_entry() {
    local entry="$1" ip bits value mask network
    if [[ "$entry" == */* ]]; then
        wl_valid_cidr "$entry" || return 1
        ip="${entry%/*}"; bits="${entry#*/}"
        value=$(wl_ip2int "$ip") || return 1
        if (( bits == 0 )); then network=0
        else mask=$(( (0xFFFFFFFF << (32-bits)) & 0xFFFFFFFF )); network=$(( value & mask )); fi
        printf '%d.%d.%d.%d/%s' "$((network >> 24 & 255))" "$((network >> 16 & 255))" "$((network >> 8 & 255))" "$((network & 255))" "$bits"
    else
        wl_normalize_ip "$entry"
    fi
}

wl_file_commit() {
    local tmp="$1" target="$2" mode
    if [[ -f "$target" ]]; then
        mode=$(stat -c '%a' "$target" 2>/dev/null || stat -f '%Lp' "$target") || return 1
        chmod "$mode" "$tmp" || return 1
    else chmod 600 "$tmp" || return 1; fi
    mv -f "$tmp" "$target"
}

# 添加白名单条目
wl_add() {
    local entry="$1" normalized existing canonical comment tmp mode
    normalized=$(wl_normalize_entry "$entry") || {
        log_error "无效的白名单 IP/CIDR: $entry"; return 1;
    }
    [[ -n "$WHITELIST_FILE" ]] || { log_error "白名单文件未配置"; return 1; }
    [[ -f "$WHITELIST_FILE" ]] || { log_error "白名单文件不存在: $WHITELIST_FILE"; return 1; }
    [[ -r "$WHITELIST_FILE" && -w "$WHITELIST_FILE" ]] || { log_error "白名单文件不可读写: $WHITELIST_FILE"; return 1; }
    while IFS= read -r existing || [[ -n "$existing" ]]; do
        comment="${existing%%#*}"; comment="${comment//[[:space:]]/}"
        [[ -n "$comment" ]] || continue
        canonical=$(wl_normalize_entry "$comment") || continue
        if [[ "$normalized" == "$canonical" ]]; then
            log_info "$normalized 已存在于白名单文件"
            return 0
        fi
    done < "$WHITELIST_FILE"
    tmp=$(mktemp "${WHITELIST_FILE}.XXXXXX") || return 1
    if cat "$WHITELIST_FILE" > "$tmp" && printf '%s\n' "$normalized" >> "$tmp" &&
        wl_file_commit "$tmp" "$WHITELIST_FILE"; then
        log_action "WHITELIST ADD $normalized"
    else
        rm -f "$tmp"
        log_error "更新白名单失败，原文件已保留"
        return 1
    fi
}

# 移除整个地址/CIDR 条目及其注释，保留其他行。
wl_remove() {
    local entry="$1" normalized existing canonical tmp
    normalized=$(wl_normalize_entry "$entry") || { log_error "无效的白名单 IP/CIDR: $entry"; return 1; }
    [[ -n "$WHITELIST_FILE" && -f "$WHITELIST_FILE" ]] || { log_error "白名单文件不存在: $WHITELIST_FILE"; return 1; }
    [[ -r "$WHITELIST_FILE" && -w "$WHITELIST_FILE" ]] || { log_error "白名单文件不可读写: $WHITELIST_FILE"; return 1; }
    tmp=$(mktemp "${WHITELIST_FILE}.XXXXXX") || return 1
    local found=0
    while IFS= read -r existing || [[ -n "$existing" ]]; do
        canonical="${existing%%#*}"; canonical="${canonical//[[:space:]]/}"
        if [[ -n "$canonical" ]]; then
            canonical=$(wl_normalize_entry "$canonical") || canonical=""
            if [[ "$canonical" == "$normalized" ]]; then found=1; continue; fi
        fi
        printf '%s\n' "$existing" >> "$tmp" || { rm -f "$tmp"; return 1; }
    done < "$WHITELIST_FILE"
    (( found )) || { rm -f "$tmp"; log_info "$normalized 不在白名单文件中"; return 0; }
    if ! wl_file_commit "$tmp" "$WHITELIST_FILE"; then rm -f "$tmp"; return 1; fi
    log_action "WHITELIST REMOVE $normalized"
}

# 列出白名单
wl_list() {
    echo "=== 内置白名单 ==="
    echo "${WHITELIST}" | tr ',' '\n' | sed 's/^/  /'
    echo
    echo "=== 白名单文件 (${WHITELIST_FILE}) ==="
    if [[ -f "${WHITELIST_FILE}" ]]; then
        grep -v '^\s*#' "${WHITELIST_FILE}" | grep -v '^\s*$' | sed 's/^/  /'
    else
        echo "  (文件不存在)"
    fi
}
