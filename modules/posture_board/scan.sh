#!/usr/bin/env bash
# modules/posture_board/scan.sh — CIS benchmark posture scan orchestrator

POSTURE_MODULE="posture_board"
CHECKS_DIR="${STACKSENTRY_HOME}/modules/posture_board/checks"

posture_board_scan() {
    aws_init
    init_findings

    print_header "Posture Board — CIS Benchmark Security Scan"

    # Parse flags
    local run_checks="all"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --checks) run_checks="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Source check files
    source "${CHECKS_DIR}/iam_checks.sh"
    source "${CHECKS_DIR}/s3_checks.sh"
    source "${CHECKS_DIR}/logging_checks.sh"
    source "${CHECKS_DIR}/network_checks.sh"

    local all_results=()
    local pass_count=0 fail_count=0 warn_count=0 skip_count=0 total_count=0

    # Run selected checks
    _should_run() {
        [[ "$run_checks" == "all" ]] || [[ "$run_checks" == *"$1"* ]]
    }

    if _should_run "iam"; then
        print_info "Running IAM checks (1.x)..."
        while IFS= read -r line; do
            [[ -n "$line" ]] && all_results+=("$line")
        done < <(run_iam_checks)
    fi

    if _should_run "s3"; then
        print_info "Running S3 checks (2.x)..."
        while IFS= read -r line; do
            [[ -n "$line" ]] && all_results+=("$line")
        done < <(run_s3_checks)
    fi

    if _should_run "logging"; then
        print_info "Running Logging checks (3.x)..."
        while IFS= read -r line; do
            [[ -n "$line" ]] && all_results+=("$line")
        done < <(run_logging_checks)
    fi

    if _should_run "network"; then
        print_info "Running Network checks (4.x)..."
        while IFS= read -r line; do
            [[ -n "$line" ]] && all_results+=("$line")
        done < <(run_network_checks)
    fi

    # Process results
    echo ""
    print_header "Posture Board — Results"

    if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
        printf "  ${BOLD}%-6s %-24s %-6s %-8s %s${RESET}\n" "CHECK" "NAME" "STATUS" "SEVERITY" "DETAILS"
        printf "  %-6s %-24s %-6s %-8s %s\n" "-----" "----" "------" "--------" "-------"
    fi

    for result in "${all_results[@]}"; do
        IFS='|' read -r check_id check_name status severity details remediation <<< "$result"
        total_count=$((total_count + 1))

        case "$status" in
            PASS)
                pass_count=$((pass_count + 1))
                if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
                    printf "  ${GREEN}%-6s${RESET} %-24s ${GREEN}%-6s${RESET} %-8s %s\n" \
                        "$check_id" "$check_name" "$status" "$severity" "$details"
                fi
                ;;
            FAIL)
                fail_count=$((fail_count + 1))
                local color
                case "$severity" in
                    CRITICAL) color="$RED" ;;
                    HIGH)     color="$RED" ;;
                    MEDIUM)   color="$YELLOW" ;;
                    *)        color="$GREEN" ;;
                esac
                if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
                    printf "  ${color}%-6s${RESET} %-24s ${RED}%-6s${RESET} ${color}%-8s${RESET} %s\n" \
                        "$check_id" "$check_name" "$status" "$severity" "$details"
                    if [[ "$remediation" != "N/A" && -n "$remediation" ]]; then
                        printf "  ${DIM}%-6s %-24s        ↳ %s${RESET}\n" "" "" "$remediation"
                    fi
                fi

                # Add to findings for reporting
                add_finding "$severity" "$POSTURE_MODULE" "check:${check_id}" \
                    "${check_name}: ${details}" "$remediation"
                ;;
            WARN)
                warn_count=$((warn_count + 1))
                if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
                    printf "  ${YELLOW}%-6s${RESET} %-24s ${YELLOW}%-6s${RESET} %-8s %s\n" \
                        "$check_id" "$check_name" "$status" "$severity" "$details"
                fi
                ;;
            SKIP)
                skip_count=$((skip_count + 1))
                if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
                    printf "  ${DIM}%-6s %-24s %-6s %-8s %s${RESET}\n" \
                        "$check_id" "$check_name" "$status" "$severity" "$details"
                fi
                ;;
        esac
    done

    # Calculate posture score
    local scoreable=$((total_count - skip_count))
    local score=0
    if [[ "$scoreable" -gt 0 ]]; then
        score=$((pass_count * 100 / scoreable))
    fi

    echo ""
    echo -e "${BOLD}  Posture Score: ${score}%${RESET}  (${pass_count} pass / ${fail_count} fail / ${warn_count} warn / ${skip_count} skip)"

    # Score color indicator
    if [[ "$score" -ge 80 ]]; then
        echo -e "  ${GREEN}■■■■■■■■■■${RESET} Healthy posture"
    elif [[ "$score" -ge 60 ]]; then
        echo -e "  ${YELLOW}■■■■■■■■${RESET}${DIM}■■${RESET} Needs improvement"
    elif [[ "$score" -ge 40 ]]; then
        echo -e "  ${YELLOW}■■■■■■${RESET}${DIM}■■■■${RESET} At risk"
    else
        echo -e "  ${RED}■■■■${RESET}${DIM}■■■■■■${RESET} Critical posture issues"
    fi

    # Compare with last scan if available
    _compare_with_last_scan "$score"

    echo ""

    # Save posture results to CSV for trend tracking
    local report_dir="${STACKSENTRY_HOME}/${STACKSENTRY_REPORT_DIR:-reports}"
    mkdir -p "$report_dir"
    local posture_csv="${report_dir}/posture_$(date +%Y%m%d_%H%M%S).csv"
    {
        echo "CHECK_ID|CHECK_NAME|STATUS|SEVERITY|DETAILS|REMEDIATION"
        for result in "${all_results[@]}"; do
            echo "$result"
        done
    } > "$posture_csv"
    print_info "Posture results saved: ${posture_csv}"

    summarize_findings || true
    post_scan_actions "$POSTURE_MODULE"
}

_compare_with_last_scan() {
    local current_score="$1"
    local report_dir="${STACKSENTRY_HOME}/${STACKSENTRY_REPORT_DIR:-reports}"

    # Find the most recent posture CSV (excluding current)
    local last_report
    last_report=$(ls -t "${report_dir}"/posture_*.csv 2>/dev/null | sed -n '2p')
    [[ -z "$last_report" ]] && return 0

    # Calculate last score
    local last_total last_pass
    last_total=$(tail -n +2 "$last_report" | wc -l | tr -d ' ')
    last_pass=$(tail -n +2 "$last_report" | grep -c '|PASS|' || true)
    local last_skip
    last_skip=$(tail -n +2 "$last_report" | grep -c '|SKIP|' || true)
    local last_scoreable=$((last_total - last_skip))

    [[ "$last_scoreable" -eq 0 ]] && return 0

    local last_score=$((last_pass * 100 / last_scoreable))
    local delta=$((current_score - last_score))

    if [[ "$delta" -gt 0 ]]; then
        echo -e "  ${GREEN}▲ +${delta} from last scan${RESET}"
    elif [[ "$delta" -lt 0 ]]; then
        echo -e "  ${RED}▼ ${delta} from last scan${RESET}"
    else
        echo -e "  ${DIM}→ No change from last scan${RESET}"
    fi
}
