#!/usr/bin/env bash
# modules/patch_tracker/scan.sh — Check EC2 instance patch status via SSM

PATCH_MODULE="patch_tracker"

patch_tracker_scan() {
    aws_init
    init_findings

    print_header "Patch Tracker — EC2 Patch Status"

    print_info "Discovering EC2 instances..."

    local instances
    instances=$(aws_cmd ec2 describe-instances \
        --filters "Name=instance-state-name,Values=running" \
        2>/dev/null | jq -c '.Reservations[].Instances[]') || {
        print_fail "Failed to describe EC2 instances"
        return 1
    }

    [[ -z "$instances" ]] && { print_pass "No running EC2 instances"; return 0; }

    local instance_count=0
    local patched=0 needs_patch=0 unknown=0

    while IFS= read -r instance; do
        [[ -z "$instance" ]] && continue
        instance_count=$((instance_count + 1))

        local instance_id name_tag platform ami_id
        instance_id=$(echo "$instance" | jq -r '.InstanceId')
        name_tag=$(echo "$instance" | jq -r '(.Tags // [])[] | select(.Key=="Name") | .Value // empty')
        platform=$(echo "$instance" | jq -r '.PlatformDetails // "Linux/UNIX"')
        ami_id=$(echo "$instance" | jq -r '.ImageId')

        print_info "Checking ${instance_id} (${name_tag:-unnamed})..."

        # Check AMI age
        _check_ami_age "$instance_id" "$ami_id" "$name_tag"

        # Check SSM patch compliance
        _check_ssm_compliance "$instance_id" "$name_tag"

        # Try to get patch info via SSM
        _check_ssm_patch_status "$instance_id" "$name_tag" "$platform"

    done <<< "$instances"

    echo ""
    print_info "Scanned ${instance_count} instances: ${patched} up-to-date, ${needs_patch} need patching, ${unknown} unknown"

    summarize_findings || true
    post_scan_actions "$PATCH_MODULE"
}

# ── AMI Age Check ──────────────────────────────────────────────────────────
_check_ami_age() {
    local instance_id="$1" ami_id="$2" name_tag="$3"

    local ami_info
    ami_info=$(aws_cmd ec2 describe-images --image-ids "$ami_id" 2>/dev/null) || {
        log_debug "$PATCH_MODULE" "Could not describe AMI ${ami_id}"
        return 0
    }

    local creation_date
    creation_date=$(echo "$ami_info" | jq -r '.Images[0].CreationDate // empty')
    [[ -z "$creation_date" ]] && return 0

    local now_epoch ami_epoch age_days
    now_epoch=$(date +%s)
    ami_epoch=$(date -d "$creation_date" +%s 2>/dev/null) || return 0
    age_days=$(( (now_epoch - ami_epoch) / 86400 ))

    if [[ "$age_days" -gt 365 ]]; then
        add_finding "HIGH" "$PATCH_MODULE" "ec2:${instance_id}" \
            "AMI is ${age_days} days old (${name_tag:-unnamed}, ami: ${ami_id})" \
            "Rebuild instance with a current AMI"
    elif [[ "$age_days" -gt 180 ]]; then
        add_finding "MEDIUM" "$PATCH_MODULE" "ec2:${instance_id}" \
            "AMI is ${age_days} days old (${name_tag:-unnamed}, ami: ${ami_id})" \
            "Consider updating to a newer AMI"
    fi

    # Check if AMI is deprecated
    local deprecated
    deprecated=$(echo "$ami_info" | jq -r '.Images[0].DeprecationTime // empty')
    if [[ -n "$deprecated" ]]; then
        local dep_epoch
        dep_epoch=$(date -d "$deprecated" +%s 2>/dev/null) || return 0
        if [[ "$dep_epoch" -lt "$now_epoch" ]]; then
            add_finding "HIGH" "$PATCH_MODULE" "ec2:${instance_id}" \
                "Running on deprecated AMI (${name_tag:-unnamed})" \
                "Migrate to a supported AMI immediately"
        fi
    fi
}

# ── SSM Patch Compliance ───────────────────────────────────────────────────
_check_ssm_compliance() {
    local instance_id="$1" name_tag="$2"

    local compliance
    compliance=$(aws_cmd ssm list-compliance-items \
        --resource-ids "$instance_id" \
        --resource-types "ManagedInstance" \
        --filters "Key=ComplianceType,Values=Patch,Type=EQUAL" \
        2>/dev/null) || {
        log_debug "$PATCH_MODULE" "SSM compliance not available for ${instance_id}"
        return 0
    }

    local non_compliant
    non_compliant=$(echo "$compliance" | jq '[.ComplianceItems[] | select(.Status=="NON_COMPLIANT")] | length')

    local compliant
    compliant=$(echo "$compliance" | jq '[.ComplianceItems[] | select(.Status=="COMPLIANT")] | length')

    if [[ "${non_compliant:-0}" -gt 0 ]]; then
        needs_patch=$((needs_patch + 1))
        add_finding "HIGH" "$PATCH_MODULE" "ec2:${instance_id}" \
            "SSM: ${non_compliant} non-compliant patches (${name_tag:-unnamed})" \
            "Run patching: aws ssm send-command --instance-ids ${instance_id} --document-name AWS-RunPatchBaseline"
    elif [[ "${compliant:-0}" -gt 0 ]]; then
        patched=$((patched + 1))
    fi
}

# ── SSM Patch Status via Command ───────────────────────────────────────────
_check_ssm_patch_status() {
    local instance_id="$1" name_tag="$2" platform="$3"

    # Check if instance is managed by SSM
    local ssm_info
    ssm_info=$(aws_cmd ssm describe-instance-information \
        --filters "Key=InstanceIds,Values=${instance_id}" \
        2>/dev/null) || {
        unknown=$((unknown + 1))
        add_finding "MEDIUM" "$PATCH_MODULE" "ec2:${instance_id}" \
            "SSM agent not reachable (${name_tag:-unnamed})" \
            "Install/configure SSM agent: https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-install-ssm-agent.html"
        return 0
    }

    local managed_count
    managed_count=$(echo "$ssm_info" | jq '.InstanceInformationList | length')

    if [[ "${managed_count:-0}" -eq 0 ]]; then
        unknown=$((unknown + 1))
        add_finding "MEDIUM" "$PATCH_MODULE" "ec2:${instance_id}" \
            "Instance not managed by SSM (${name_tag:-unnamed})" \
            "Register with SSM for patch management"
        return 0
    fi

    # Get platform details
    local os_name os_version agent_version ping_status
    os_name=$(echo "$ssm_info" | jq -r '.InstanceInformationList[0].PlatformName // "unknown"')
    os_version=$(echo "$ssm_info" | jq -r '.InstanceInformationList[0].PlatformVersion // "unknown"')
    agent_version=$(echo "$ssm_info" | jq -r '.InstanceInformationList[0].AgentVersion // "unknown"')
    ping_status=$(echo "$ssm_info" | jq -r '.InstanceInformationList[0].PingStatus // "unknown"')

    if [[ "$ping_status" != "Online" ]]; then
        unknown=$((unknown + 1))
        add_finding "MEDIUM" "$PATCH_MODULE" "ec2:${instance_id}" \
            "SSM agent offline (${name_tag:-unnamed}, ${os_name} ${os_version})" \
            "Check SSM agent status on the instance"
        return 0
    fi

    # Check for pending patches via compliance summary
    local patch_summary
    patch_summary=$(aws_cmd ssm list-resource-compliance-summaries \
        --filters "Key=ComplianceType,Values=Patch,Type=EQUAL" 2>/dev/null) || return 0

    local instance_summary
    instance_summary=$(echo "$patch_summary" | jq -c \
        --arg id "$instance_id" \
        '.ResourceComplianceSummaryItems[] | select(.ResourceId==$id)' 2>/dev/null)

    if [[ -n "$instance_summary" ]]; then
        local non_compliant_count
        non_compliant_count=$(echo "$instance_summary" | jq -r '.NonCompliantSummary.NonCompliantCount // 0')

        if [[ "$non_compliant_count" -gt 0 ]]; then
            needs_patch=$((needs_patch + 1))
            local critical_count
            critical_count=$(echo "$instance_summary" | jq -r \
                '.NonCompliantSummary.SeveritySummary.CriticalCount // 0')

            local severity="HIGH"
            [[ "$critical_count" -gt 0 ]] && severity="CRITICAL"

            add_finding "$severity" "$PATCH_MODULE" "ec2:${instance_id}" \
                "${non_compliant_count} pending patches (${critical_count} critical) — ${name_tag:-unnamed} (${os_name} ${os_version})" \
                "Patch now: aws ssm send-command --instance-ids ${instance_id} --document-name AWS-RunPatchBaseline --parameters Operation=Install"
        else
            patched=$((patched + 1))
        fi
    fi
}
