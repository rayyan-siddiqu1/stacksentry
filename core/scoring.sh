#!/usr/bin/env bash
# core/scoring.sh — Finding format, severity scoring, and allowlist

# ── Finding Storage ─────────────────────────────────────────────────────────
# Universal format: SEVERITY|MODULE|RESOURCE|FINDING|REMEDIATION|TIMESTAMP
FINDINGS=()
COUNTER_CRITICAL=0
COUNTER_HIGH=0
COUNTER_MEDIUM=0
COUNTER_LOW=0

init_findings() {
    FINDINGS=()
    COUNTER_CRITICAL=0
    COUNTER_HIGH=0
    COUNTER_MEDIUM=0
    COUNTER_LOW=0
}

add_finding() {
    local severity="$1" module="$2" resource="$3" finding="$4" remediation="${5:-}"
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    # Check allowlist
    if is_allowlisted "$resource"; then
        log_debug "$module" "Skipping allowlisted resource: $resource"
        return 0
    fi

    # Validate severity
    case "$severity" in
        CRITICAL|HIGH|MEDIUM|LOW) ;;
        *) severity="MEDIUM" ;;
    esac

    # Append to findings array
    FINDINGS+=("${severity}|${module}|${resource}|${finding}|${remediation}|${ts}")

    # Increment counter
    case "$severity" in
        CRITICAL) (( COUNTER_CRITICAL++ )) ;;
        HIGH)     (( COUNTER_HIGH++ ))     ;;
        MEDIUM)   (( COUNTER_MEDIUM++ ))   ;;
        LOW)      (( COUNTER_LOW++ ))      ;;
    esac

    # Print finding in real-time (table mode)
    if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
        print_finding "$severity" "$module" "$resource" "$finding" "$remediation"
    fi
}

is_allowlisted() {
    local resource="$1"
    local allowlist="${STACKSENTRY_HOME:-.}/config/allowlist.txt"
    [[ -f "$allowlist" ]] || return 1
    grep -qF "$resource" "$allowlist" 2>/dev/null
}

severity_color() {
    local severity="$1"
    case "$severity" in
        CRITICAL) echo -ne "$RED"    ;;
        HIGH)     echo -ne "$RED"    ;;
        MEDIUM)   echo -ne "$YELLOW" ;;
        LOW)      echo -ne "$GREEN"  ;;
        *)        echo -ne "$RESET"  ;;
    esac
}

score_to_severity() {
    local score="$1"
    if [[ "$score" -ge "${STACKSENTRY_SCORE_CRITICAL:-9}" ]]; then
        echo "CRITICAL"
    elif [[ "$score" -ge "${STACKSENTRY_SCORE_HIGH:-7}" ]]; then
        echo "HIGH"
    elif [[ "$score" -ge "${STACKSENTRY_SCORE_MEDIUM:-4}" ]]; then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

summarize_findings() {
    local total=$(( COUNTER_CRITICAL + COUNTER_HIGH + COUNTER_MEDIUM + COUNTER_LOW ))

    case "${STACKSENTRY_OUTPUT_FORMAT:-table}" in
        json)
            _summarize_json
            ;;
        csv)
            _summarize_csv
            ;;
        *)
            print_summary "$total" "$COUNTER_CRITICAL" "$COUNTER_HIGH" "$COUNTER_MEDIUM" "$COUNTER_LOW"
            ;;
    esac

    # Return exit code based on severity
    if [[ "$COUNTER_CRITICAL" -gt 0 ]]; then return 2; fi
    if [[ "$COUNTER_HIGH" -gt 0 ]]; then return 1; fi
    return 0
}

_summarize_json() {
    local header="SEVERITY|MODULE|RESOURCE|FINDING|REMEDIATION|TIMESTAMP"
    print_table "$header" "${FINDINGS[@]}"
}

_summarize_csv() {
    local header="SEVERITY|MODULE|RESOURCE|FINDING|REMEDIATION|TIMESTAMP"
    print_table "$header" "${FINDINGS[@]}"
}

filter_findings_by_severity() {
    local min_severity="$1"
    local -A severity_rank=( [CRITICAL]=4 [HIGH]=3 [MEDIUM]=2 [LOW]=1 )
    local min_rank="${severity_rank[$min_severity]:-0}"

    for finding in "${FINDINGS[@]}"; do
        local sev
        sev=$(echo "$finding" | cut -d'|' -f1)
        local rank="${severity_rank[$sev]:-0}"
        if [[ "$rank" -ge "$min_rank" ]]; then
            echo "$finding"
        fi
    done
}
