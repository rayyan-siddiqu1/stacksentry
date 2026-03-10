#!/usr/bin/env bash
# modules/cost_sentinel/scan.sh — Find idle, wasted, and underutilized AWS resources

COST_MODULE="cost_sentinel"

# Hardcoded monthly cost estimates (USD)
declare -A COST_ESTIMATES=(
    [eip]=3.65
    [nat_gw]=32.40
    [ebs_gp2_per_gb]=0.10
    [ebs_gp3_per_gb]=0.08
    [ebs_io1_per_gb]=0.125
    [snapshot_per_gb]=0.05
)

cost_sentinel_scan() {
    aws_init
    init_findings

    print_header "Cost Sentinel — Waste & Idle Resource Detection"

    local total_monthly_waste=0

    print_info "Scanning for idle EC2 instances..."
    _scan_idle_ec2

    print_info "Scanning for unattached EBS volumes..."
    _scan_unattached_ebs

    print_info "Scanning for unassociated Elastic IPs..."
    _scan_unassociated_eips

    print_info "Scanning for stale S3 buckets..."
    _scan_stale_s3

    print_info "Scanning for old snapshots..."
    _scan_old_snapshots

    print_info "Scanning for unused NAT Gateways..."
    _scan_unused_nat_gateways

    echo ""
    if [[ "$TOTAL_ESTIMATED_WASTE" -gt 0 ]] 2>/dev/null; then
        echo -e "  ${BOLD}Estimated Monthly Waste: \$${TOTAL_ESTIMATED_WASTE}${RESET}"
        echo ""
    fi

    summarize_findings || true
    post_scan_actions "$COST_MODULE"
}

TOTAL_ESTIMATED_WASTE=0

# ── Idle EC2 Instances ──────────────────────────────────────────────────────
_scan_idle_ec2() {
    local instances
    instances=$(aws_cmd ec2 describe-instances \
        --filters "Name=instance-state-name,Values=running" \
        2>/dev/null | jq -c '.Reservations[].Instances[]') || {
        log_warn "$COST_MODULE" "Failed to describe EC2 instances"
        return 0
    }

    [[ -z "$instances" ]] && { print_pass "No running EC2 instances"; return 0; }

    local now
    now=$(date -u +%s)
    local fourteen_days_ago
    fourteen_days_ago=$(date -u -d "14 days ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || \
        fourteen_days_ago=$(date -u -v-14d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || return 0

    while IFS= read -r instance; do
        [[ -z "$instance" ]] && continue
        local instance_id instance_type name_tag
        instance_id=$(echo "$instance" | jq -r '.InstanceId')
        instance_type=$(echo "$instance" | jq -r '.InstanceType')
        name_tag=$(echo "$instance" | jq -r '(.Tags // [])[] | select(.Key=="Name") | .Value // empty')

        # Check average CPU over 14 days
        local cpu_avg
        cpu_avg=$(aws_cmd cloudwatch get-metric-statistics \
            --namespace AWS/EC2 \
            --metric-name CPUUtilization \
            --dimensions "Name=InstanceId,Value=${instance_id}" \
            --start-time "$fourteen_days_ago" \
            --end-time "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --period 86400 \
            --statistics Average \
            2>/dev/null | jq '[.Datapoints[].Average] | if length > 0 then add/length else -1 end') || continue

        if [[ "$cpu_avg" != "-1" ]]; then
            local is_idle
            is_idle=$(awk "BEGIN {print ($cpu_avg < 5) ? 1 : 0}")

            if [[ "$is_idle" -eq 1 ]]; then
                local cpu_display
                cpu_display=$(awk "BEGIN {printf \"%.1f\", $cpu_avg}")
                add_finding "MEDIUM" "$COST_MODULE" "ec2:${instance_id}" \
                    "IDLE — ${name_tag:-unnamed} (${instance_type}) avg CPU ${cpu_display}% over 14 days" \
                    "Rightsize or stop: aws ec2 stop-instances --instance-ids ${instance_id}"
            fi
        fi
    done <<< "$instances"
}

# ── Unattached EBS Volumes ──────────────────────────────────────────────────
_scan_unattached_ebs() {
    local volumes
    volumes=$(aws_cmd ec2 describe-volumes \
        --filters "Name=status,Values=available" \
        2>/dev/null | jq -c '.Volumes[]') || {
        log_warn "$COST_MODULE" "Failed to describe EBS volumes"
        return 0
    }

    [[ -z "$volumes" ]] && { print_pass "No unattached EBS volumes"; return 0; }

    while IFS= read -r vol; do
        [[ -z "$vol" ]] && continue
        local vol_id size vol_type
        vol_id=$(echo "$vol" | jq -r '.VolumeId')
        size=$(echo "$vol" | jq -r '.Size')
        vol_type=$(echo "$vol" | jq -r '.VolumeType')

        # Estimate cost
        local cost_per_gb="${COST_ESTIMATES[ebs_${vol_type}_per_gb]:-0.10}"
        local monthly_cost
        monthly_cost=$(awk "BEGIN {printf \"%.2f\", $size * $cost_per_gb}")
        TOTAL_ESTIMATED_WASTE=$((TOTAL_ESTIMATED_WASTE + ${monthly_cost%.*}))

        add_finding "MEDIUM" "$COST_MODULE" "ebs:${vol_id}" \
            "UNATTACHED — ${size}GB ${vol_type} volume (~\$${monthly_cost}/mo)" \
            "Delete: aws ec2 delete-volume --volume-id ${vol_id}"
    done <<< "$volumes"
}

# ── Unassociated Elastic IPs ───────────────────────────────────────────────
_scan_unassociated_eips() {
    local addresses
    addresses=$(aws_cmd ec2 describe-addresses 2>/dev/null) || {
        log_warn "$COST_MODULE" "Failed to describe Elastic IPs"
        return 0
    }

    local unassociated
    unassociated=$(echo "$addresses" | jq -c '.Addresses[] | select(.AssociationId == null)')

    [[ -z "$unassociated" ]] && { print_pass "No unassociated Elastic IPs"; return 0; }

    while IFS= read -r eip; do
        [[ -z "$eip" ]] && continue
        local alloc_id public_ip
        alloc_id=$(echo "$eip" | jq -r '.AllocationId')
        public_ip=$(echo "$eip" | jq -r '.PublicIp')

        TOTAL_ESTIMATED_WASTE=$((TOTAL_ESTIMATED_WASTE + 3))

        add_finding "LOW" "$COST_MODULE" "eip:${alloc_id}" \
            "UNASSOCIATED — ${public_ip} (~\$${COST_ESTIMATES[eip]}/mo)" \
            "Release: aws ec2 release-address --allocation-id ${alloc_id}"
    done <<< "$unassociated"
}

# ── Stale S3 Buckets ───────────────────────────────────────────────────────
_scan_stale_s3() {
    local buckets
    buckets=$(aws_cmd s3api list-buckets 2>/dev/null | jq -r '.Buckets[].Name') || {
        log_warn "$COST_MODULE" "Failed to list S3 buckets"
        return 0
    }

    [[ -z "$buckets" ]] && return 0

    while IFS= read -r bucket; do
        [[ -z "$bucket" ]] && continue

        # Check object count
        local object_count
        object_count=$(aws_cmd cloudwatch get-metric-statistics \
            --namespace AWS/S3 \
            --metric-name NumberOfObjects \
            --dimensions "Name=BucketName,Value=${bucket}" "Name=StorageType,Value=AllStorageTypes" \
            --start-time "$(date -u -d "3 days ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --end-time "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --period 86400 \
            --statistics Average \
            2>/dev/null | jq '[.Datapoints[].Average] | if length > 0 then .[0] else -1 end') || continue

        if [[ "$object_count" == "0" ]]; then
            add_finding "LOW" "$COST_MODULE" "s3:${bucket}" \
                "EMPTY — Bucket has 0 objects" \
                "Delete if unused: aws s3 rb s3://${bucket}"
        fi
    done <<< "$buckets"
}

# ── Old Snapshots ──────────────────────────────────────────────────────────
_scan_old_snapshots() {
    local snapshots
    snapshots=$(aws_cmd ec2 describe-snapshots --owner-ids self 2>/dev/null \
        | jq -c '.Snapshots[]') || {
        log_warn "$COST_MODULE" "Failed to describe snapshots"
        return 0
    }

    [[ -z "$snapshots" ]] && { print_pass "No owned snapshots"; return 0; }

    local now_epoch
    now_epoch=$(date +%s)

    # Get all AMI snapshot IDs for cross-reference
    local ami_snap_ids
    ami_snap_ids=$(aws_cmd ec2 describe-images --owners self 2>/dev/null \
        | jq -r '.Images[].BlockDeviceMappings[].Ebs.SnapshotId // empty' | sort -u) || ami_snap_ids=""

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
            # Check if associated with an AMI
            local has_ami=false
            if echo "$ami_snap_ids" | grep -qF "$snap_id" 2>/dev/null; then
                has_ami=true
            fi

            if [[ "$has_ami" == false ]]; then
                local monthly_cost
                monthly_cost=$(awk "BEGIN {printf \"%.2f\", $size * ${COST_ESTIMATES[snapshot_per_gb]}}")
                TOTAL_ESTIMATED_WASTE=$((TOTAL_ESTIMATED_WASTE + ${monthly_cost%.*}))

                add_finding "LOW" "$COST_MODULE" "snap:${snap_id}" \
                    "OLD — ${age_days} days old, ${size}GB, no AMI (~\$${monthly_cost}/mo)" \
                    "Delete: aws ec2 delete-snapshot --snapshot-id ${snap_id}"
            fi
        fi
    done <<< "$snapshots"
}

# ── Unused NAT Gateways ────────────────────────────────────────────────────
_scan_unused_nat_gateways() {
    local nat_gws
    nat_gws=$(aws_cmd ec2 describe-nat-gateways \
        --filter "Name=state,Values=available" \
        2>/dev/null | jq -c '.NatGateways[]') || {
        log_warn "$COST_MODULE" "Failed to describe NAT Gateways"
        return 0
    }

    [[ -z "$nat_gws" ]] && { print_pass "No NAT Gateways found"; return 0; }

    local seven_days_ago
    seven_days_ago=$(date -u -d "7 days ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || \
        seven_days_ago=$(date -u -v-7d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || return 0

    while IFS= read -r gw; do
        [[ -z "$gw" ]] && continue
        local gw_id
        gw_id=$(echo "$gw" | jq -r '.NatGatewayId')

        # Check bytes out over 7 days
        local bytes_out
        bytes_out=$(aws_cmd cloudwatch get-metric-statistics \
            --namespace AWS/NATGateway \
            --metric-name BytesOutToDestination \
            --dimensions "Name=NatGatewayId,Value=${gw_id}" \
            --start-time "$seven_days_ago" \
            --end-time "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
            --period 604800 \
            --statistics Sum \
            2>/dev/null | jq '[.Datapoints[].Sum] | add // 0') || continue

        if [[ "${bytes_out%.*}" -eq 0 ]] 2>/dev/null; then
            TOTAL_ESTIMATED_WASTE=$((TOTAL_ESTIMATED_WASTE + 32))
            add_finding "MEDIUM" "$COST_MODULE" "nat:${gw_id}" \
                "UNUSED — 0 bytes transferred in 7 days (~\$${COST_ESTIMATES[nat_gw]}/mo)" \
                "Delete: aws ec2 delete-nat-gateway --nat-gateway-id ${gw_id}"
        fi
    done <<< "$nat_gws"
}
