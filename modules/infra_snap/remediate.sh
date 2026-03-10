#!/usr/bin/env bash
# modules/infra_snap/remediate.sh — Generate remediation scripts from findings

infra_snap_remediate() {
    aws_init

    print_header "Infra Snap — Remediation Script Generator"

    # First run a scan to collect findings
    init_findings
    print_info "Running infrastructure scan to detect drift..."

    source "${STACKSENTRY_HOME}/modules/infra_snap/scan.sh"

    # Capture findings by running scan internals
    local snapshot_dir="/tmp/stacksentry_infra_$$"
    mkdir -p "$snapshot_dir"
    _snap_ec2 "$snapshot_dir"
    _snap_security_groups "$snapshot_dir"
    _snap_s3 "$snapshot_dir"
    _snap_vpcs "$snapshot_dir"
    _snap_ebs "$snapshot_dir"
    _snap_rds "$snapshot_dir"
    rm -rf "$snapshot_dir"

    local total=$(( COUNTER_CRITICAL + COUNTER_HIGH + COUNTER_MEDIUM + COUNTER_LOW ))
    if [[ "$total" -eq 0 ]]; then
        print_pass "No drift detected — no remediation needed"
        return 0
    fi

    # Generate remediation script
    local report_dir="${STACKSENTRY_HOME}/${STACKSENTRY_REPORT_DIR:-reports}"
    mkdir -p "$report_dir"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local script_path="${report_dir}/remediation_${ts}.sh"

    {
        echo "#!/usr/bin/env bash"
        echo "# StackSentry Remediation Script"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "# Account: ${_AWS_ACCOUNT_ID:-unknown}"
        echo "# Region: ${AWS_DEFAULT_REGION:-us-east-1}"
        echo "#"
        echo "# REVIEW CAREFULLY BEFORE RUNNING"
        echo "# This script contains destructive operations."
        echo "#"
        echo "set -euo pipefail"
        echo ""
        echo "AWS_PROFILE=\"${AWS_PROFILE:-default}\""
        echo "AWS_REGION=\"${AWS_DEFAULT_REGION:-us-east-1}\""
        echo ""

        local cmd_count=0
        for finding in "${FINDINGS[@]}"; do
            IFS='|' read -r sev mod res desc rem ts_f <<< "$finding"
            [[ -z "$rem" || "$rem" == "N/A" ]] && continue

            # Extract actual aws commands from remediation text
            local aws_cmd_text
            aws_cmd_text=$(echo "$rem" | grep -oE 'aws [a-z0-9-]+ [a-z0-9-]+.*' 2>/dev/null) || continue
            [[ -z "$aws_cmd_text" ]] && continue

            cmd_count=$((cmd_count + 1))
            echo "# [${sev}] ${desc}"
            echo "# Resource: ${res}"
            echo "echo \"[${cmd_count}] Fixing: ${desc}\""
            echo "aws --profile \"\$AWS_PROFILE\" --region \"\$AWS_REGION\" ${aws_cmd_text#aws }"
            echo ""
        done

        if [[ "$cmd_count" -eq 0 ]]; then
            echo "echo 'No automated remediations available. Manual review required.'"
        else
            echo "echo ''"
            echo "echo \"Remediation complete: ${cmd_count} actions executed.\""
        fi
    } > "$script_path"

    chmod +x "$script_path"

    print_info "Remediation script generated: ${script_path}"
    print_warn "Review the script carefully before executing!"
    echo ""
    echo -e "  ${BOLD}To execute:${RESET}"
    echo "    bash ${script_path}"
    echo ""

    summarize_findings || true
}
