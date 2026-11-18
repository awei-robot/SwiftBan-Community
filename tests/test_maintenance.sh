#!/bin/bash
# shellcheck disable=SC1090,SC1091,SC2329 # 动态加载模块；替身由产品函数间接调用。
set -uo pipefail
PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_PATH="$PATH"
source "$PROJECT_DIR/bin/swiftban.sh"
export PATH="$TEST_PATH"
SWIFTBAN_CONF="$PROJECT_DIR/config/swiftban.conf"
load_config
load_libs || exit 1
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { local label="$1"; shift; if "$@"; then ok "$label"; else bad "$label"; fi; }
eq() { [[ "$1" == "$2" ]]; }
STATE_DIR="$T/state"; LOG_DIR="$T/logs"
BANLIST="$STATE_DIR/banlist.txt"; BANLOG="$STATE_DIR/ban.log"
WHITELIST_FILE="$STATE_DIR/whitelist.txt"
export NOW=100
mkdir "$STATE_DIR" "$LOG_DIR"
: > "$BANLIST"; : > "$WHITELIST_FILE"

echo "=== IPv6 规范化与状态 ==="
canonical=2001:0db8:0000:0000:0000:0000:0000:0001
for ip in 2001:db8::1 2001:DB8:0:0:0:0:0:1 2001:0db8:0000:0000:0000:0000:0000:0001; do
    check "等价IPv6规范化: $ip" eq "$(wl_normalize_ip "$ip")" "$canonical"
done
check "IPv4嵌入IPv6与十六进制写法等价" eq "$(wl_normalize_ip ::ffff:192.0.2.1)" "$(wl_normalize_ip 0:0:0:0:0:ffff:c000:201)"
for ip in 2001:::1 1:2:3:4:5:6:7::8 :1:2:3:4:5:6:7 1:2:3:4:5:6:7: fe80::1%eth0 2001:db8::/64; do
    if wl_normalize_ip "$ip" >/dev/null; then bad "拒绝非法IP: $ip"; else ok "拒绝非法IP: $ip"; fi
done
WHITELIST="::1,2001:db8::1"
check "展开IPv6命中内置白名单" wl_is_whitelisted "$canonical"
WHITELIST=""
printf '2001:DB8:0:0:0:0:0:1 # trusted\n' > "$WHITELIST_FILE"
check "压缩IPv6命中文件白名单" wl_is_whitelisted 2001:db8::1
: > "$WHITELIST_FILE"
(
    fw_is_banned() { return 1; }
    fw_ban() { :; }
    det_ban 2001:DB8::1 test || exit 1
    grep -q "^$canonical|" "$BANLIST"
)
check "新封禁保存规范化IPv6" eq "$?" 0
printf '2001:db8::1|100|0|a\n2001:DB8:0:0:0:0:0:1|100|0|b\n2001:db8::2|100|0|keep\n' > "$BANLIST"
(
    fw_unban() { printf '%s\n' "$1" > "$T/unban-ip"; }
    cmd_unban 2001:0db8::1 >/dev/null || exit 1
    [[ "$(wc -l < "$BANLIST" | tr -d ' ')" == 1 ]] || exit 1
    grep -q '^2001:db8::2|' "$BANLIST" || exit 1
    [[ "$(cat "$T/unban-ip")" == "$canonical" ]]
)
check "手动解封删除所有等价旧记录且保留其他地址" eq "$?" 0
mkdir "$T/parse"
printf 's\tf\t2001:db8::1 - - [16/Nov/2026:11:59:00 +0000] "GET / HTTP/1.1" 200 0 "-" "Mozilla"\ns\tf\t2001:DB8:0:0:0:0:0:1 - - [16/Nov/2026:11:59:01 +0000] "GET / HTTP/1.1" 200 0 "-" "Mozilla"\n' > "$T/input"
export NOW_EPOCH
NOW_EPOCH=$(TZ=UTC det_awk 'BEGIN {print mktime("2026 11 16 12 00 00")}')
if det_parse "$T/input" "$T/parse/recent.log" "$T/stats" &&
    det_detect_all "$T/parse" && grep -q "^2 $canonical$" "$T/parse/ip_freq.txt"; then
    ok "不同IPv6写法的日志合并统计"
else bad "IPv6日志合并统计"; fi

echo "=== 状态读写故障 ==="
for scenario in retain failed-unban missing-ipv6; do
    (
        if [[ "$scenario" == retain ]]; then printf '198.51.100.1|90|100|keep\n' > "$BANLIST"
        elif [[ "$scenario" == failed-unban ]]; then printf '198.51.100.1|0|1|keep\n' > "$BANLIST"
        else printf '2001:db8::1|0|1|keep\n' > "$BANLIST"; fi
        cp "$BANLIST" "$T/expected"
        fw_unban() { return 1; }
        command() {
            if [[ "$1" == -v && "$2" == ip6tables ]]; then return 1; fi
            builtin command "$@"
        }
        printf() {
            if [[ "$1" == '%s|%s|%s|%s\n' ]]; then return 1; fi
            # shellcheck disable=SC2059 # 原样转发 printf 参数的故障注入替身。
            builtin printf "$@"
        }
        if det_unban_expired >/dev/null; then exit 1; fi
        cmp "$BANLIST" "$T/expected"
    )
    check "写入失败保留原状态: $scenario" eq "$?" 0
done
(
    printf '198.51.100.1|0|1|keep\n' > "$BANLIST"
    cp "$BANLIST" "$T/expected"
    fw_unban() { touch "$T/unexpected-unban"; }
    cat() { if [[ "$1" == "$BANLIST" ]]; then head -c 10 "$1"; return 1; else command cat "$@"; fi; }
    if det_unban_expired >/dev/null; then exit 1; fi
    [[ ! -e "$T/unexpected-unban" ]] && cmp "$BANLIST" "$T/expected"
)
check "部分读取失败不撤销规则、不覆盖原状态" eq "$?" 0
(
    mv "$BANLIST" "$T/saved"
    if det_unban_expired >/dev/null 2>&1; then exit 1; fi
    [[ ! -e "$BANLIST" ]]
)
check "源状态缺失不能生成空banlist" eq "$?" 0
mv "$T/saved" "$BANLIST"

echo "=== 配置检查 ==="
for name in WINDOW LIMIT_444 LIMIT_SCAN LIMIT_EVILPATH LIMIT_PAYLOAD LIMIT_UA LIMIT_AUTH LIMIT_API LIMIT_API_RATE LIMIT_EMPTYUA LIMIT_HIGHFREQ BAN_TTL; do
    (
        for invalid in -1 abc 01 2147483648 999999999999999999999; do
            printf -v "$name" '%s' "$invalid"
            if det_check_config >/dev/null; then exit 1; fi
        done
    )
    check "拒绝非法数值: $name" eq "$?" 0
done
for name in SAFE_PATH GIT_SAFE EVIL_PATH EVIL_PAYLOAD EVIL_UA LOGIN_PATH; do
    (printf -v "$name" '%s' '['; ! det_check_config >/dev/null)
    check "拒绝非法正则: $name" eq "$?" 0
done
(BAN_TTL=0; det_check_config >/dev/null)
check "允许永久TTL" eq "$?" 0
(
    iptables() { return 0; }
    command() { if [[ "$1" == -v && "$2" == ip6tables ]]; then return 1; fi; builtin command "$@"; }
    cmd_configtest >/dev/null || exit 1
    for invalid in log-dir state-dir chain whitelist; do
        (
            case "$invalid" in
                log-dir) LOG_DIR="$T/not-found" ;;
                state-dir) STATE_DIR="$T/not-found" ;;
                chain) iptables() { return 2; } ;;
                whitelist) printf '10.0.0.0/33\n' > "$WHITELIST_FILE" ;;
            esac
            ! cmd_configtest >/dev/null
        ) || exit 1
    done
)
check "配置正常且无可选IPv6时通过，目录、链、白名单异常时失败" eq "$?" 0
 : > "$WHITELIST_FILE"
(
    iptables() { return 0; }
    ip6tables() { [[ "$1" != -L ]]; }
    command() { builtin command "$@"; }
    if ! cmd_configtest > "$T/ipv6-chain-configtest"; then cat "$T/ipv6-chain-configtest"; exit 1; fi
    grep -q 'IPv6 防火墙链: DOCKER-USER ⚠' "$T/ipv6-chain-configtest" || exit 1
    ! grep -q '✗' "$T/ipv6-chain-configtest"
)
check "ip6tables存在但DOCKER-USER缺失时配置检查告警且不失败" eq "$?" 0
: > "$WHITELIST_FILE"

echo "=== CLI cron ==="
(
    # 路径包含空格、单引号、反引号和美元符号，执行时必须原样保留。
    base="$T/space ' quote \$ literal \`tick\`"
    mkdir -p "$base/state" "$base/bin"
    SWIFTBAN_ENTRY="$base/bin/swiftban.sh"
    SWIFTBAN_CONF="$base/custom.conf"; STATE_DIR="$base/state"
    : > "$SWIFTBAN_CONF"
    export RESULT="$base/result"
    cat > "$SWIFTBAN_ENTRY" <<'EOF'
#!/bin/sh
printf '%s\n' "$SWIFTBAN_CONF" > "$RESULT"
EOF
    chmod +x "$SWIFTBAN_ENTRY"
    rt_require_root() { return 0; }
    crontab() {
        if [[ "$1" == -l ]]; then cat "$T/current-cron"
        else cat "$1" > "$T/current-cron"; fi
    }
    printf '# keep\n0 * * * * /usr/local/bin/backup\n* * * * * /usr/local/bin/swiftban run\n' > "$T/current-cron"
    cmd_install_cron >/dev/null || exit 1
    cmd_install_cron >/dev/null || exit 1
    [[ "$(grep -c 'SWIFTBAN_CONF=' "$T/current-cron")" == 1 ]] || exit 1
    grep -q '^0 .*backup$' "$T/current-cron" || exit 1
    grep -q '^\* \* \* \* \* /usr/local/bin/swiftban run$' "$T/current-cron" || exit 1
    line=$(tail -n 1 "$T/current-cron")
    [[ "$(rt_cron_mode "$line")" == 正式 ]] || exit 1
    systemctl() { return 1; }
    rt_show_schedule > "$T/schedule"
    grep -q 'cron 推断模式: 正式' "$T/schedule" || exit 1
    /bin/sh -c "${line#'* * * * * '}" || exit 1
    [[ "$(cat "$RESULT")" -ef "$SWIFTBAN_CONF" ]] || exit 1
    crontab() { if [[ "$1" == -l ]]; then return 0; else return 2; fi; }
    if cmd_install_cron > "$T/cron-error"; then exit 1; fi
    ! grep -q 'cron 已安装' "$T/cron-error" || exit 1
    crontab() { printf 'permission denied\n' >&2; return 1; }
    if cmd_install_cron > "$T/cron-error" 2>&1; then exit 1; fi
    ! grep -q 'cron 已安装' "$T/cron-error" || exit 1
    crontab() { touch "$T/cron-should-not-call"; return 0; }
    SWIFTBAN_CONF="$base/percent%.conf"; : > "$SWIFTBAN_CONF"
    if cmd_install_cron >/dev/null 2>&1; then exit 1; fi
    [[ ! -e "$T/cron-should-not-call" ]]
    SWIFTBAN_CONF="$base/control"$'\n'; : > "$SWIFTBAN_CONF"
    if cmd_install_cron >/dev/null 2>&1; then exit 1; fi
    [[ ! -e "$T/cron-should-not-call" ]]
)
check "CLI保留配置与其他任务、重复安装幂等、安全执行特殊路径并传播失败" eq "$?" 0
(
    WHITELIST=""
    : > "$WHITELIST_FILE"
    printf '119.57.94.54|1|0|test\n198.51.100.2|1|0|keep\n' > "$BANLIST"
    fw_unban() { return 1; }
    if cmd_whitelist add 119.57.94.54 >/dev/null 2>&1; then exit 1; fi
    wl_is_whitelisted 119.57.94.54 || exit 1
    [[ $(wc -l < "$BANLIST") -eq 2 ]] || exit 1
    fw_unban() { return 0; }
    cmd_whitelist add 119.57.94.54 >/dev/null || exit 1
    [[ $(wc -l < "$BANLIST") -eq 1 ]] || exit 1
    grep -q '^198.51.100.2|' "$BANLIST" || exit 1
    cmd_whitelist add 198.51.100.99/24 >/dev/null || exit 1
    [[ ! -s "$BANLIST" ]] || exit 1
)
check "白名单添加撤销已有封禁，失败保留记录，重复添加重试，CIDR覆盖解封" eq "$?" 0
echo "=== 维护回归结果: $PASS 通过, $FAIL 失败 ==="
[[ "$FAIL" == 0 ]]
