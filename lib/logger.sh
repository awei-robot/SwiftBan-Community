#!/bin/bash
#==============================================================
# SwiftBan - 日志模块
#==============================================================

# 日志级别: DEBUG=0 INFO=1 WARN=2 ERROR=3
SWIFTBAN_LOG_LEVEL="${SWIFTBAN_LOG_LEVEL:-1}"

_log() {
    local level="$1" msg="$2"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${ts}] [${level}] ${msg}"
}

log_debug() { (( SWIFTBAN_LOG_LEVEL <= 0 )) && _log "DEBUG" "$1"; }
log_info()  { (( SWIFTBAN_LOG_LEVEL <= 1 )) && _log "INFO"  "$1"; }
log_warn()  { (( SWIFTBAN_LOG_LEVEL <= 2 )) && _log "WARN"  "$1"; }
log_error() { (( SWIFTBAN_LOG_LEVEL <= 3 )) && _log "ERROR" "$1"; }

# 记录到审计日志文件（封禁/解封操作）
audit_log() {
    local msg="$1"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${ts}] ${msg}" >> "${BANLOG}" 2>/dev/null || true
}

# 带审计的操作日志
log_action() {
    local msg="$1"
    log_info "$msg"
    audit_log "$msg"
}
