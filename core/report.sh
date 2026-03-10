#!/usr/bin/env bash
# core/report.sh — Save findings to txt/csv/json files

save_report() {
    local module_name="$1"
    local format="${2:-${STACKSENTRY_OUTPUT_FORMAT:-table}}"
    local report_dir="${STACKSENTRY_HOME:-.}/${STACKSENTRY_REPORT_DIR:-reports}"
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"

    mkdir -p "$report_dir"

    local ext
    case "$format" in
        json) ext="json" ;;
        csv)  ext="csv"  ;;
        *)    ext="txt"  ;;
    esac

    local filepath="${report_dir}/${module_name}_${ts}.${ext}"

    case "$ext" in
        json) _save_report_json "$filepath" ;;
        csv)  _save_report_csv  "$filepath" ;;
        txt)  _save_report_txt  "$filepath" ;;
    esac

    log_info "report" "Report saved: $filepath"
    print_info "Report saved to ${filepath}"
}

_save_report_txt() {
    local filepath="$1"
    {
        echo "StackSentry Report"
        echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        [[ -n "${_AWS_ACCOUNT_ID:-}" ]] && echo "Account: ${_AWS_ACCOUNT_ID}"
        echo "Region: ${AWS_DEFAULT_REGION:-us-east-1}"
        echo "================================================"
        echo ""
        printf "%-10s %-14s %-40s %-50s %s\n" "SEVERITY" "MODULE" "RESOURCE" "FINDING" "REMEDIATION"
        printf "%-10s %-14s %-40s %-50s %s\n" "--------" "------" "--------" "-------" "-----------"

        for finding in "${FINDINGS[@]}"; do
            IFS='|' read -r sev mod res desc rem ts <<< "$finding"
            printf "%-10s %-14s %-40s %-50s %s\n" "$sev" "$mod" "$res" "$desc" "$rem"
        done

        echo ""
        local total=$(( COUNTER_CRITICAL + COUNTER_HIGH + COUNTER_MEDIUM + COUNTER_LOW ))
        echo "Summary: ${total} findings — ${COUNTER_CRITICAL} Critical, ${COUNTER_HIGH} High, ${COUNTER_MEDIUM} Medium, ${COUNTER_LOW} Low"
    } > "$filepath"
}

_save_report_csv() {
    local filepath="$1"
    {
        echo "SEVERITY,MODULE,RESOURCE,FINDING,REMEDIATION,TIMESTAMP"
        for finding in "${FINDINGS[@]}"; do
            IFS='|' read -r sev mod res desc rem ts <<< "$finding"
            # Escape double quotes in fields
            sev="${sev//\"/\"\"}"
            mod="${mod//\"/\"\"}"
            res="${res//\"/\"\"}"
            desc="${desc//\"/\"\"}"
            rem="${rem//\"/\"\"}"
            ts="${ts//\"/\"\"}"
            echo "\"${sev}\",\"${mod}\",\"${res}\",\"${desc}\",\"${rem}\",\"${ts}\""
        done
    } > "$filepath"
}

_save_report_json() {
    local filepath="$1"

    if command -v jq &>/dev/null; then
        local json_array="[]"
        for finding in "${FINDINGS[@]}"; do
            IFS='|' read -r sev mod res desc rem ts <<< "$finding"
            json_array=$(echo "$json_array" | jq \
                --arg s "$sev" --arg m "$mod" --arg r "$res" \
                --arg f "$desc" --arg rm "$rem" --arg t "$ts" \
                '. + [{"severity":$s,"module":$m,"resource":$r,"finding":$f,"remediation":$rm,"timestamp":$t}]')
        done
        echo "$json_array" | jq . > "$filepath"
    else
        # Fallback without jq
        {
            echo "["
            for i in "${!FINDINGS[@]}"; do
                IFS='|' read -r sev mod res desc rem ts <<< "${FINDINGS[$i]}"
                # Escape JSON special chars
                desc="${desc//\\/\\\\}"; desc="${desc//\"/\\\"}"
                rem="${rem//\\/\\\\}"; rem="${rem//\"/\\\"}"
                res="${res//\\/\\\\}"; res="${res//\"/\\\"}"
                echo -n "  {\"severity\":\"${sev}\",\"module\":\"${mod}\",\"resource\":\"${res}\",\"finding\":\"${desc}\",\"remediation\":\"${rem}\",\"timestamp\":\"${ts}\"}"
                [[ $i -lt $((${#FINDINGS[@]} - 1)) ]] && echo "," || echo ""
            done
            echo "]"
        } > "$filepath"
    fi
}
