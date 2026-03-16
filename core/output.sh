#!/usr/bin/env bash
# core/output.sh — ANSI colors, banners, tables, and formatted output

# ── Colors ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED="\033[0;31m"
    YELLOW="\033[0;33m"
    GREEN="\033[0;32m"
    CYAN="\033[0;36m"
    MAGENTA="\033[0;35m"
    BOLD="\033[1m"
    DIM="\033[2m"
    RESET="\033[0m"
else
    RED="" YELLOW="" GREEN="" CYAN="" MAGENTA="" BOLD="" DIM="" RESET=""
fi

# ── Banner ──────────────────────────────────────────────────────────────────
print_banner() {
    local V="${STACKSENTRY_VERSION:-0.1.0}"
    echo ""
    echo -e "${CYAN}${BOLD}     _____ _             _     _____            _              ${RESET}"
    echo -e "${CYAN}${BOLD}    / ____| |           | |   / ____|          | |             ${RESET}"
    echo -e "${CYAN}${BOLD}   | (___ | |_ __ _  ___| | _| (___   ___ _ __| |_ _ __ _   _ ${RESET}"
    echo -e "${CYAN}${BOLD}    \\___ \\| __/ _\` |/ __| |/ /\\___ \\ / _ \\ '_ \\| __| '__| | | |${RESET}"
    echo -e "${CYAN}${BOLD}    ____) | || (_| | (__|   < ____) |  __/ | | | |_| |  | |_| |${RESET}"
    echo -e "${CYAN}${BOLD}   |_____/ \\__\\__,_|\\___|_|\\_\\_____/ \\___|_| |_|\\__|_|   \\__, |${RESET}"
    echo -e "${CYAN}${BOLD}                                                          __/ |${RESET}"
    echo -e "${CYAN}${BOLD}                                                         |___/ ${RESET}"
    echo ""
    echo -e "   ${DIM}╭──────────────────────────────────────────────────────────────╮${RESET}"
    echo -e "   ${DIM}│${RESET}  ${BOLD}v${V}${RESET}  ${DIM}│${RESET}  Cloud Security & Governance CLI  ${DIM}│${RESET}  ${GREEN}Pure Bash${RESET}  ${DIM}│${RESET}"
    echo -e "   ${DIM}╰──────────────────────────────────────────────────────────────╯${RESET}"
    echo ""
    echo -e "   ${DIM}┌─────────┬──────────────┬──────────────┬──────────────────────┐${RESET}"
    echo -e "   ${DIM}│${RESET} ${RED}IAM Lens${RESET} ${DIM}│${RESET} ${YELLOW}Secret Radar${RESET} ${DIM}│${RESET} ${GREEN}Posture Board${RESET}${DIM}│${RESET} ${CYAN}Compliance Mapper${RESET}   ${DIM}│${RESET}"
    echo -e "   ${DIM}│${RESET} ${RED}CostSntl${RESET} ${DIM}│${RESET} ${YELLOW}Infra Snap${RESET}   ${DIM}│${RESET} ${GREEN}Audit Vault${RESET}  ${DIM}│${RESET} ${CYAN}Patch Tracker${RESET}       ${DIM}│${RESET}"
    echo -e "   ${DIM}└─────────┴──────────────┴──────────────┴──────────────────────┘${RESET}"
    echo ""
}

# ── Section Headers ─────────────────────────────────────────────────────────
print_header() {
    local title="$1"
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
    echo -e "${CYAN}${BOLD}━━━ ${title} ━━━${RESET}  ${DIM}${ts}${RESET}"
    if [[ -n "${_AWS_ACCOUNT_ID:-}" ]]; then
        echo -e "${DIM}  Account: ${_AWS_ACCOUNT_ID} | Region: ${AWS_DEFAULT_REGION:-us-east-1}${RESET}"
    fi
    echo ""
}

# ── Status Messages ─────────────────────────────────────────────────────────
print_pass() { echo -e "  ${GREEN}[PASS]${RESET}  $1"; }
print_fail() { echo -e "  ${RED}[FAIL]${RESET}  $1"; }
print_warn() { echo -e "  ${YELLOW}[WARN]${RESET}  $1"; }
print_info() { echo -e "  ${CYAN}[INFO]${RESET}  $1"; }

# ── Finding Printer ─────────────────────────────────────────────────────────
# Prints a single finding with colored severity
print_finding() {
    local severity="$1" module="$2" resource="$3" finding="$4" remediation="$5"
    local color
    color=$(severity_color "$severity" 2>/dev/null || echo "$RED")
    printf "  ${color}%-8s${RESET} %-14s %-40s %s\n" "$severity" "$module" "$resource" "$finding"
    if [[ -n "$remediation" ]]; then
        printf "  ${DIM}%-8s %-14s   ↳ %s${RESET}\n" "" "" "$remediation"
    fi
}

# ── Summary Bar ─────────────────────────────────────────────────────────────
print_summary() {
    local total="$1" critical="$2" high="$3" medium="$4" low="$5"
    echo ""
    echo -e "${BOLD}  Summary: ${total} findings${RESET}  " \
        "${RED}${critical} Critical${RESET} | " \
        "${RED}${high} High${RESET} | " \
        "${YELLOW}${medium} Medium${RESET} | " \
        "${GREEN}${low} Low${RESET}"
    echo ""
}

# ── Table Output (respects STACKSENTRY_OUTPUT_FORMAT) ───────────────────────
# Usage: print_table "HEADER1|HEADER2|..." "${rows_array[@]}"
#   Each row is pipe-delimited: "val1|val2|..."
print_table() {
    local header="$1"
    shift
    local rows=("$@")
    local format="${STACKSENTRY_OUTPUT_FORMAT:-table}"

    case "$format" in
        json)
            _print_table_json "$header" "${rows[@]}"
            ;;
        csv)
            _print_table_csv "$header" "${rows[@]}"
            ;;
        *)
            _print_table_formatted "$header" "${rows[@]}"
            ;;
    esac
}

_print_table_formatted() {
    local header="$1"
    shift
    local rows=("$@")

    # Print header + rows through column for alignment
    {
        echo "$header"
        for row in "${rows[@]}"; do
            echo "$row"
        done
    } | column -t -s '|'
    echo ""
}

_print_table_csv() {
    local header="$1"
    shift
    local rows=("$@")

    # Convert pipe-delimited to CSV with quoting
    echo "$header" | sed 's/|/,/g'
    for row in "${rows[@]}"; do
        # Wrap each field in quotes, escape internal quotes
        local csv_row=""
        IFS='|' read -ra fields <<< "$row"
        for i in "${!fields[@]}"; do
            local field="${fields[$i]}"
            field="${field//\"/\"\"}"
            [[ $i -gt 0 ]] && csv_row+=","
            csv_row+="\"${field}\""
        done
        echo "$csv_row"
    done
}

_print_table_json() {
    local header="$1"
    shift
    local rows=("$@")

    IFS='|' read -ra keys <<< "$header"
    # Lowercase and trim keys
    for i in "${!keys[@]}"; do
        keys[$i]=$(echo "${keys[$i]}" | tr '[:upper:]' '[:lower:]' | tr ' ' '_' | xargs)
    done

    if command -v jq &>/dev/null; then
        # Build JSON via jq
        local json_array="[]"
        for row in "${rows[@]}"; do
            IFS='|' read -ra vals <<< "$row"
            local obj="{}"
            for i in "${!keys[@]}"; do
                obj=$(echo "$obj" | jq --arg k "${keys[$i]}" --arg v "${vals[$i]:-}" '. + {($k): $v}')
            done
            json_array=$(echo "$json_array" | jq --argjson obj "$obj" '. + [$obj]')
        done
        echo "$json_array" | jq .
    else
        # Fallback: manual JSON
        echo "["
        for idx in "${!rows[@]}"; do
            IFS='|' read -ra vals <<< "${rows[$idx]}"
            echo -n "  {"
            for i in "${!keys[@]}"; do
                local val="${vals[$i]:-}"
                val="${val//\\/\\\\}"
                val="${val//\"/\\\"}"
                [[ $i -gt 0 ]] && echo -n ", "
                echo -n "\"${keys[$i]}\": \"${val}\""
            done
            [[ $idx -lt $((${#rows[@]} - 1)) ]] && echo "}," || echo "}"
        done
        echo "]"
    fi
}
