#!/usr/bin/env bash
# core/logger.sh — Structured logging to file

# Log level priorities
declare -A _LOG_LEVELS=( [DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 )

LOG_FILE=""

log_init() {
    local log_dir="${STACKSENTRY_HOME:-.}/${STACKSENTRY_LOG_DIR:-logs}"
    mkdir -p "$log_dir"
    LOG_FILE="${log_dir}/stacksentry_$(date +%Y%m%d).log"
    export LOG_FILE
}

log_msg() {
    local level="$1" module="$2" message="$3"
    local threshold="${STACKSENTRY_LOG_LEVEL:-INFO}"

    # Filter by log level
    local level_num="${_LOG_LEVELS[$level]:-1}"
    local threshold_num="${_LOG_LEVELS[$threshold]:-1}"
    [[ "$level_num" -lt "$threshold_num" ]] && return 0

    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    local entry="[${ts}] [${level}] [${module}] ${message}"

    # Write to log file if initialized
    if [[ -n "$LOG_FILE" ]]; then
        echo "$entry" >> "$LOG_FILE"
    fi

    # Also print ERROR to stderr
    if [[ "$level" == "ERROR" ]]; then
        echo -e "${RED:-}[ERROR]${RESET:-} ${message}" >&2
    fi
}

log_debug() { log_msg "DEBUG" "$1" "$2"; }
log_info()  { log_msg "INFO"  "$1" "$2"; }
log_warn()  { log_msg "WARN"  "$1" "$2"; }
log_error() { log_msg "ERROR" "$1" "$2"; }
