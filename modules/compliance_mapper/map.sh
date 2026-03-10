#!/usr/bin/env bash
# modules/compliance_mapper/map.sh — Map posture results to compliance frameworks

COMPLIANCE_MODULE="compliance_mapper"
FRAMEWORKS_DIR="${STACKSENTRY_HOME}/modules/compliance_mapper/frameworks"

compliance_map() {
    local framework=""

    # Parse flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --framework) framework="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if [[ -z "$framework" ]]; then
        print_fail "Usage: stacksentry compliance map --framework <name>"
        echo ""
        echo "  Available frameworks:"
        for f in "${FRAMEWORKS_DIR}"/*.txt; do
            local fname
            fname=$(basename "$f" .txt)
            echo "    - ${fname}"
        done
        exit 1
    fi

    # Normalize framework name
    framework=$(echo "$framework" | tr '[:upper:]' '[:lower:]' | tr '-' '_')

    local framework_file="${FRAMEWORKS_DIR}/${framework}.txt"
    if [[ ! -f "$framework_file" ]]; then
        print_fail "Unknown framework: ${framework}"
        echo "  Available: $(ls "${FRAMEWORKS_DIR}"/*.txt 2>/dev/null | xargs -I{} basename {} .txt | tr '\n' ', ' | sed 's/,$//')"
        exit 1
    fi

    print_header "Compliance Mapper — ${framework^^} Framework"

    # Find latest posture report
    local report_dir="${STACKSENTRY_HOME}/${STACKSENTRY_REPORT_DIR:-reports}"
    local latest_posture
    latest_posture=$(ls -t "${report_dir}"/posture_*.csv 2>/dev/null | head -1)

    if [[ -z "$latest_posture" ]]; then
        print_warn "No posture scan results found. Running posture scan first..."
        source "${STACKSENTRY_HOME}/modules/posture_board/scan.sh"
        posture_board_scan
        latest_posture=$(ls -t "${report_dir}"/posture_*.csv 2>/dev/null | head -1)

        if [[ -z "$latest_posture" ]]; then
            print_fail "Could not generate posture results"
            exit 1
        fi
    fi

    print_info "Using posture results: ${latest_posture}"
    print_info "Mapping to framework: ${framework^^}"

    # Load posture results into associative array
    declare -A posture_results
    while IFS='|' read -r check_id check_name status severity details remediation; do
        [[ "$check_id" == "CHECK_ID" ]] && continue  # Skip header
        posture_results["$check_id"]="${status}|${severity}|${details}"
    done < "$latest_posture"

    # Load framework mappings and join
    init_findings

    local satisfied=0 failing=0 untested=0 total_controls=0

    # Track unique controls
    declare -A control_status

    echo ""
    if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
        printf "  ${BOLD}%-8s %-10s %-44s %-10s %s${RESET}\n" \
            "CHECK" "CONTROL" "CONTROL NAME" "STATUS" "DETAILS"
        printf "  %-8s %-10s %-44s %-10s %s\n" \
            "-----" "-------" "------------" "------" "-------"
    fi

    local rows=()
    while IFS='|' read -r check_id control_id control_name fw_name; do
        # Skip comments and header
        [[ "$check_id" =~ ^# ]] && continue
        [[ -z "$check_id" ]] && continue

        total_controls=$((total_controls + 1))

        local posture_data="${posture_results[$check_id]:-}"
        local status="UNTESTED"
        local details="No posture data"

        if [[ -n "$posture_data" ]]; then
            IFS='|' read -r p_status p_severity p_details <<< "$posture_data"
            case "$p_status" in
                PASS)
                    status="SATISFIED"
                    details="$p_details"
                    satisfied=$((satisfied + 1))
                    ;;
                FAIL)
                    status="FAILING"
                    details="$p_details"
                    failing=$((failing + 1))
                    add_finding "$p_severity" "$COMPLIANCE_MODULE" "${framework^^}:${control_id}" \
                        "${control_name} — ${p_details}" \
                        "Address check ${check_id} to satisfy ${control_id}"
                    ;;
                SKIP)
                    status="UNTESTED"
                    details="Check was skipped"
                    untested=$((untested + 1))
                    ;;
                *)
                    status="UNTESTED"
                    untested=$((untested + 1))
                    ;;
            esac
        else
            untested=$((untested + 1))
        fi

        # Track per-control (a control may map to multiple checks)
        if [[ -z "${control_status[$control_id]:-}" || "${control_status[$control_id]}" != "FAILING" ]]; then
            control_status["$control_id"]="$status"
        fi

        # Display
        local color
        case "$status" in
            SATISFIED) color="$GREEN" ;;
            FAILING)   color="$RED" ;;
            UNTESTED)  color="$YELLOW" ;;
            *)         color="$RESET" ;;
        esac

        if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
            printf "  %-8s %-10s %-44s ${color}%-10s${RESET} %s\n" \
                "$check_id" "$control_id" "${control_name:0:44}" "$status" "${details:0:60}"
        fi

        rows+=("${check_id}|${control_id}|${control_name}|${status}|${details}")
    done < "$framework_file"

    # Output for non-table formats
    if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" != "table" ]]; then
        local header="CHECK_ID|CONTROL_ID|CONTROL_NAME|STATUS|DETAILS"
        print_table "$header" "${rows[@]}"
    fi

    # Calculate compliance percentage
    local compliance_pct=0
    if [[ "$total_controls" -gt 0 ]]; then
        compliance_pct=$((satisfied * 100 / total_controls))
    fi

    echo ""
    echo -e "${BOLD}  ${framework^^} Compliance Summary${RESET}"
    echo -e "  Compliance Score: ${BOLD}${compliance_pct}%${RESET}"
    echo -e "  ${GREEN}${satisfied} Satisfied${RESET} | ${RED}${failing} Failing${RESET} | ${YELLOW}${untested} Untested${RESET} | Total: ${total_controls}"

    # Visual bar
    if [[ "$compliance_pct" -ge 80 ]]; then
        echo -e "  ${GREEN}■■■■■■■■■■${RESET} On track"
    elif [[ "$compliance_pct" -ge 60 ]]; then
        echo -e "  ${YELLOW}■■■■■■■■${RESET}${DIM}■■${RESET} Gaps exist"
    elif [[ "$compliance_pct" -ge 40 ]]; then
        echo -e "  ${YELLOW}■■■■■■${RESET}${DIM}■■■■${RESET} Significant gaps"
    else
        echo -e "  ${RED}■■■■${RESET}${DIM}■■■■■■${RESET} Non-compliant"
    fi

    # Unique controls summary
    local unique_satisfied=0 unique_failing=0 unique_untested=0
    for cid in "${!control_status[@]}"; do
        case "${control_status[$cid]}" in
            SATISFIED) unique_satisfied=$((unique_satisfied + 1)) ;;
            FAILING)   unique_failing=$((unique_failing + 1)) ;;
            UNTESTED)  unique_untested=$((unique_untested + 1)) ;;
        esac
    done

    echo ""
    echo -e "  Unique Controls: ${unique_satisfied} satisfied, ${unique_failing} failing, ${unique_untested} untested"

    # Save compliance report
    local report_dir="${STACKSENTRY_HOME}/${STACKSENTRY_REPORT_DIR:-reports}"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local compliance_report="${report_dir}/compliance_${framework}_${ts}.csv"
    {
        echo "CHECK_ID,CONTROL_ID,CONTROL_NAME,FRAMEWORK,STATUS,DETAILS"
        for row in "${rows[@]}"; do
            IFS='|' read -r cid ctrlid ctrlname st det <<< "$row"
            echo "\"${cid}\",\"${ctrlid}\",\"${ctrlname}\",\"${framework^^}\",\"${st}\",\"${det}\""
        done
    } > "$compliance_report"

    echo ""
    print_info "Compliance report saved: ${compliance_report}"
    echo ""

    summarize_findings || true
    post_scan_actions "$COMPLIANCE_MODULE"
}
