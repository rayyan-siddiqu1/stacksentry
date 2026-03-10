#!/usr/bin/env bash
# modules/cost_sentinel/teardown.sh — Generate or execute teardown for wasted resources

COST_MODULE="cost_sentinel"

cost_sentinel_teardown() {
    aws_init
    init_findings

    local dry_run=true
    local confirm=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)  dry_run=true; shift ;;
            --confirm)  confirm=true; dry_run=false; shift ;;
            *) shift ;;
        esac
    done

    print_header "Cost Sentinel — Teardown"

    if [[ "$dry_run" == true ]]; then
        print_info "DRY RUN mode — showing what would be deleted"
        echo ""
    else
        print_warn "CONFIRM mode — generating executable teardown script"
        echo ""
    fi

    # Collect wasteful resources
    local teardown_actions=()

    # Unattached EBS volumes
    print_info "Finding unattached EBS volumes..."
    local volumes
    volumes=$(aws_cmd ec2 describe-volumes \
        --filters "Name=status,Values=available" \
        2>/dev/null | jq -c '.Volumes[]') || true

    if [[ -n "$volumes" ]]; then
        while IFS= read -r vol; do
            [[ -z "$vol" ]] && continue
            local vol_id size vol_type
            vol_id=$(echo "$vol" | jq -r '.VolumeId')
            size=$(echo "$vol" | jq -r '.Size')
            vol_type=$(echo "$vol" | jq -r '.VolumeType')
            teardown_actions+=("EBS|${vol_id}|${size}GB ${vol_type}|aws ec2 delete-volume --volume-id ${vol_id}")
        done <<< "$volumes"
    fi

    # Unassociated EIPs
    print_info "Finding unassociated Elastic IPs..."
    local eips
    eips=$(aws_cmd ec2 describe-addresses 2>/dev/null \
        | jq -c '.Addresses[] | select(.AssociationId == null)') || true

    if [[ -n "$eips" ]]; then
        while IFS= read -r eip; do
            [[ -z "$eip" ]] && continue
            local alloc_id public_ip
            alloc_id=$(echo "$eip" | jq -r '.AllocationId')
            public_ip=$(echo "$eip" | jq -r '.PublicIp')
            teardown_actions+=("EIP|${alloc_id}|${public_ip}|aws ec2 release-address --allocation-id ${alloc_id}")
        done <<< "$eips"
    fi

    # Old orphaned snapshots (>180 days, no AMI)
    print_info "Finding orphaned snapshots..."
    local now_epoch
    now_epoch=$(date +%s)
    local ami_snap_ids
    ami_snap_ids=$(aws_cmd ec2 describe-images --owners self 2>/dev/null \
        | jq -r '.Images[].BlockDeviceMappings[].Ebs.SnapshotId // empty' | sort -u) || ami_snap_ids=""

    local snapshots
    snapshots=$(aws_cmd ec2 describe-snapshots --owner-ids self 2>/dev/null \
        | jq -c '.Snapshots[]') || true

    if [[ -n "$snapshots" ]]; then
        while IFS= read -r snap; do
            [[ -z "$snap" ]] && continue
            local snap_id start_time size
            snap_id=$(echo "$snap" | jq -r '.SnapshotId')
            start_time=$(echo "$snap" | jq -r '.StartTime')
            size=$(echo "$snap" | jq -r '.VolumeSize')

            local snap_epoch
            snap_epoch=$(date -d "$start_time" +%s 2>/dev/null) || continue
            local age_days=$(( (now_epoch - snap_epoch) / 86400 ))

            if [[ "$age_days" -gt 180 ]]; then
                if ! echo "$ami_snap_ids" | grep -qF "$snap_id" 2>/dev/null; then
                    teardown_actions+=("SNAPSHOT|${snap_id}|${size}GB, ${age_days}d old|aws ec2 delete-snapshot --snapshot-id ${snap_id}")
                fi
            fi
        done <<< "$snapshots"
    fi

    # Display teardown plan
    if [[ ${#teardown_actions[@]} -eq 0 ]]; then
        print_pass "No resources identified for teardown"
        return 0
    fi

    echo ""
    printf "  ${BOLD}%-10s %-24s %-24s %s${RESET}\n" "TYPE" "RESOURCE" "DETAILS" "ACTION"
    printf "  %-10s %-24s %-24s %s\n" "----" "--------" "-------" "------"

    for action in "${teardown_actions[@]}"; do
        IFS='|' read -r type resource details cmd <<< "$action"
        printf "  ${YELLOW}%-10s${RESET} %-24s %-24s ${DIM}%s${RESET}\n" "$type" "$resource" "$details" "$cmd"
    done

    echo ""
    echo -e "  ${BOLD}Total: ${#teardown_actions[@]} resources to clean up${RESET}"
    echo ""

    if [[ "$dry_run" == true ]]; then
        print_info "This was a dry run. To generate a teardown script:"
        echo "    stacksentry cost teardown --confirm"
        return 0
    fi

    # Generate teardown script
    local report_dir="${STACKSENTRY_HOME}/${STACKSENTRY_REPORT_DIR:-reports}"
    mkdir -p "$report_dir"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local script_path="${report_dir}/teardown_${ts}.sh"

    {
        echo "#!/usr/bin/env bash"
        echo "# StackSentry Cost Sentinel — Teardown Script"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "# Account: ${_AWS_ACCOUNT_ID:-unknown}"
        echo "# Region: ${AWS_DEFAULT_REGION:-us-east-1}"
        echo "#"
        echo "# WARNING: This script DELETES resources. Review carefully!"
        echo "#"
        echo "set -euo pipefail"
        echo ""
        echo "AWS_PROFILE=\"${AWS_PROFILE:-default}\""
        echo "AWS_REGION=\"${AWS_DEFAULT_REGION:-us-east-1}\""
        echo ""
        echo "echo 'Cost Sentinel Teardown — ${#teardown_actions[@]} actions'"
        echo "echo ''"
        echo ""

        local i=0
        for action in "${teardown_actions[@]}"; do
            IFS='|' read -r type resource details cmd <<< "$action"
            i=$((i + 1))
            echo "# [${i}] ${type}: ${resource} (${details})"
            echo "echo \"[${i}/${#teardown_actions[@]}] Deleting ${type}: ${resource} (${details})\""
            echo "aws --profile \"\$AWS_PROFILE\" --region \"\$AWS_REGION\" ${cmd#aws }" || true
            echo "echo '  Done.'"
            echo ""
        done

        echo "echo ''"
        echo "echo 'Teardown complete: ${#teardown_actions[@]} resources cleaned up.'"
    } > "$script_path"

    chmod +x "$script_path"

    print_info "Teardown script generated: ${script_path}"
    print_warn "Review the script carefully before executing!"
    echo ""
    echo -e "  ${BOLD}To execute:${RESET}"
    echo "    bash ${script_path}"
    echo ""
}
