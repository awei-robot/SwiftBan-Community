#!/bin/bash
#==============================================================
# SwiftBan - 白名单模块
# 支持: 精确 IP / CIDR 网段 / 文件（动态生效）
#==============================================================

# IPv4 转整数（CIDR 匹配用）
wl_ip2int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# CIDR 匹配（IPv4；IPv6 用精确匹配）
wl_ip_in_cidr() {
    local ip="$1" cidr="$2"
    local net bits ipint netint mask
    net="${cidr%/*}"; bits="${cidr#*/}"
    ipint=$(wl_ip2int "$ip") || return 1
    netint=$(wl_ip2int "$net") || return 1
    mask=$(( 0xFFFFFFFF << (32 - bits) & 0xFFFFFFFF ))
    (( (ipint & mask) == (netint & mask) ))
}

# 白名单检查（脚本内 WHITELIST + 独立文件）
wl_is_whitelisted() {
    local ip="$1" entry
    # 1) 脚本内 WHITELIST（精确）
    if [[ ",${WHITELIST}," == *",${ip},"* ]]; then
        return 0
    fi
    # 2) 独立白名单文件（IP / CIDR / 注释）
    if [[ -n "${WHITELIST_FILE}" && -f "${WHITELIST_FILE}" ]]; then
        while IFS= read -r entry || [[ -n "$entry" ]]; do
            entry="${entry%%#*}"
            entry="${entry// /}"
            [[ -z "$entry" ]] && continue
            if [[ "$entry" == */* ]]; then
                wl_ip_in_cidr "$ip" "$entry" && return 0
            else
                [[ "$ip" == "$entry" ]] && return 0
            fi
        done < "${WHITELIST_FILE}"
    fi
    return 1
}

# 添加白名单条目
wl_add() {
    local entry="$1"
    if [[ -z "${WHITELIST_FILE}" || ! -f "${WHITELIST_FILE}" ]]; then
        log_error "白名单文件未配置: ${WHITELIST_FILE}"
        return 1
    fi
    # 去重
    if grep -qxF "$entry" "${WHITELIST_FILE}"; then
        log_warn "$entry 已在白名单中"
        return 0
    fi
    echo "$entry" >> "${WHITELIST_FILE}"
    log_action "WHITELIST ADD $entry"
}

# 移除白名单条目（固定字符串整行匹配，避免 sed 正则注入）
wl_remove() {
    local entry="$1"
    [[ -f "${WHITELIST_FILE}" ]] || return 1
    local tmp
    tmp=$(mktemp)
    awk -v e="$entry" '$0 != e' "${WHITELIST_FILE}" > "$tmp" && mv "$tmp" "${WHITELIST_FILE}"
    log_action "WHITELIST REMOVE $entry"
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
