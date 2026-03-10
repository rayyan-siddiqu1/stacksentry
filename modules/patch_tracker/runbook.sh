#!/usr/bin/env bash
# modules/patch_tracker/runbook.sh — Generate patch runbook scripts per instance

PATCH_MODULE="patch_tracker"

patch_tracker_runbook() {
    aws_init
    init_findings

    print_header "Patch Tracker — Runbook Generator"

    local target_instance=""
    local all_instances=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --instance) target_instance="$2"; shift 2 ;;
            --all)      all_instances=true; shift ;;
            *) shift ;;
        esac
    done

    local report_dir="${STACKSENTRY_HOME}/${STACKSENTRY_REPORT_DIR:-reports}"
    mkdir -p "$report_dir"

    # Get instances that need patching
    local instances
    if [[ -n "$target_instance" ]]; then
        instances=$(aws_cmd ec2 describe-instances \
            --instance-ids "$target_instance" \
            2>/dev/null | jq -c '.Reservations[].Instances[]') || {
            print_fail "Instance not found: ${target_instance}"
            exit 1
        }
    else
        instances=$(aws_cmd ec2 describe-instances \
            --filters "Name=instance-state-name,Values=running" \
            2>/dev/null | jq -c '.Reservations[].Instances[]') || {
            print_fail "Failed to describe EC2 instances"
            return 1
        }
    fi

    [[ -z "$instances" ]] && { print_pass "No instances to generate runbooks for"; return 0; }

    local runbook_count=0

    while IFS= read -r instance; do
        [[ -z "$instance" ]] && continue

        local instance_id name_tag
        instance_id=$(echo "$instance" | jq -r '.InstanceId')
        name_tag=$(echo "$instance" | jq -r '(.Tags // [])[] | select(.Key=="Name") | .Value // empty')

        # Check if SSM managed
        local ssm_info
        ssm_info=$(aws_cmd ssm describe-instance-information \
            --filters "Key=InstanceIds,Values=${instance_id}" \
            2>/dev/null) || continue

        local managed
        managed=$(echo "$ssm_info" | jq '.InstanceInformationList | length')
        [[ "${managed:-0}" -eq 0 ]] && continue

        local os_name os_version
        os_name=$(echo "$ssm_info" | jq -r '.InstanceInformationList[0].PlatformName // "Linux"')
        os_version=$(echo "$ssm_info" | jq -r '.InstanceInformationList[0].PlatformVersion // "unknown"')
        local platform_type
        platform_type=$(echo "$ssm_info" | jq -r '.InstanceInformationList[0].PlatformType // "Linux"')

        # Generate runbook
        local ts
        ts=$(date +%Y%m%d_%H%M%S)
        local runbook_path="${report_dir}/patch_runbook_${instance_id}_${ts}.sh"

        _generate_runbook "$runbook_path" "$instance_id" "$name_tag" "$os_name" "$os_version" "$platform_type"
        runbook_count=$((runbook_count + 1))

        print_info "Generated: ${runbook_path}"
    done <<< "$instances"

    echo ""
    if [[ "$runbook_count" -gt 0 ]]; then
        print_pass "Generated ${runbook_count} patch runbook(s) in ${report_dir}/"
    else
        print_warn "No SSM-managed instances found for runbook generation"
    fi
}

_generate_runbook() {
    local filepath="$1" instance_id="$2" name_tag="$3" os_name="$4" os_version="$5" platform_type="$6"

    {
        echo "#!/usr/bin/env bash"
        echo "# StackSentry Patch Runbook"
        echo "# Instance: ${instance_id} (${name_tag:-unnamed})"
        echo "# OS: ${os_name} ${os_version}"
        echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "# Account: ${_AWS_ACCOUNT_ID:-unknown}"
        echo "# Region: ${AWS_DEFAULT_REGION:-us-east-1}"
        echo "#"
        echo "# REVIEW BEFORE RUNNING — This will apply patches to the instance."
        echo "#"
        echo "set -euo pipefail"
        echo ""
        echo "INSTANCE_ID=\"${instance_id}\""
        echo "AWS_PROFILE=\"${AWS_PROFILE:-default}\""
        echo "AWS_REGION=\"${AWS_DEFAULT_REGION:-us-east-1}\""
        echo ""
        echo "aws_cmd() {"
        echo "    aws --profile \"\$AWS_PROFILE\" --region \"\$AWS_REGION\" --output json \"\$@\""
        echo "}"
        echo ""
        echo "echo '=========================================='"
        echo "echo 'StackSentry Patch Runbook'"
        echo "echo \"Instance: \${INSTANCE_ID} (${name_tag:-unnamed})\""
        echo "echo \"OS: ${os_name} ${os_version}\""
        echo "echo '=========================================='"
        echo "echo ''"
        echo ""

        # Step 1: Pre-flight checks
        echo "# ── Step 1: Pre-flight Checks ──"
        echo "echo '[1/6] Running pre-flight checks...'"
        echo ""
        echo "# Verify instance is running"
        echo "STATE=\$(aws_cmd ec2 describe-instances --instance-ids \"\$INSTANCE_ID\" \\"
        echo "    | jq -r '.Reservations[0].Instances[0].State.Name')"
        echo "if [[ \"\$STATE\" != \"running\" ]]; then"
        echo "    echo 'ERROR: Instance is not running (state: '\$STATE')'"
        echo "    exit 1"
        echo "fi"
        echo "echo '  Instance is running.'"
        echo ""
        echo "# Verify SSM connectivity"
        echo "PING=\$(aws_cmd ssm describe-instance-information \\"
        echo "    --filters \"Key=InstanceIds,Values=\${INSTANCE_ID}\" \\"
        echo "    | jq -r '.InstanceInformationList[0].PingStatus // \"Offline\"')"
        echo "if [[ \"\$PING\" != \"Online\" ]]; then"
        echo "    echo 'ERROR: SSM agent is not online'"
        echo "    exit 1"
        echo "fi"
        echo "echo '  SSM agent is online.'"
        echo ""

        # Step 2: Create AMI backup
        echo "# ── Step 2: Create Backup AMI ──"
        echo "echo '[2/6] Creating backup AMI...'"
        echo "BACKUP_AMI=\$(aws_cmd ec2 create-image \\"
        echo "    --instance-id \"\$INSTANCE_ID\" \\"
        echo "    --name \"pre-patch-\${INSTANCE_ID}-\$(date +%Y%m%d%H%M%S)\" \\"
        echo "    --no-reboot \\"
        echo "    | jq -r '.ImageId')"
        echo "echo \"  Backup AMI: \$BACKUP_AMI\""
        echo "echo '  Waiting for AMI to become available...'"
        echo "aws_cmd ec2 wait image-available --image-ids \"\$BACKUP_AMI\" 2>/dev/null || true"
        echo "echo '  Backup complete.'"
        echo ""

        # Step 3: Scan for patches
        echo "# ── Step 3: Scan for Available Patches ──"
        echo "echo '[3/6] Scanning for available patches...'"
        echo "SCAN_CMD=\$(aws_cmd ssm send-command \\"
        echo "    --instance-ids \"\$INSTANCE_ID\" \\"
        echo "    --document-name \"AWS-RunPatchBaseline\" \\"
        echo "    --parameters '{\"Operation\":[\"Scan\"]}' \\"
        echo "    | jq -r '.Command.CommandId')"
        echo "echo \"  Scan command: \$SCAN_CMD\""
        echo "echo '  Waiting for scan to complete...'"
        echo "aws_cmd ssm wait command-executed \\"
        echo "    --command-id \"\$SCAN_CMD\" --instance-id \"\$INSTANCE_ID\" 2>/dev/null || sleep 60"
        echo "echo '  Scan complete.'"
        echo ""

        # Step 4: Install patches
        echo "# ── Step 4: Install Patches ──"
        echo "echo '[4/6] Installing patches...'"

        if [[ "$platform_type" == "Windows" ]]; then
            echo "INSTALL_CMD=\$(aws_cmd ssm send-command \\"
            echo "    --instance-ids \"\$INSTANCE_ID\" \\"
            echo "    --document-name \"AWS-RunPatchBaseline\" \\"
            echo "    --parameters '{\"Operation\":[\"Install\"],\"RebootOption\":[\"RebootIfNeeded\"]}' \\"
            echo "    | jq -r '.Command.CommandId')"
        else
            echo "INSTALL_CMD=\$(aws_cmd ssm send-command \\"
            echo "    --instance-ids \"\$INSTANCE_ID\" \\"
            echo "    --document-name \"AWS-RunPatchBaseline\" \\"
            echo "    --parameters '{\"Operation\":[\"Install\"],\"RebootOption\":[\"RebootIfNeeded\"]}' \\"
            echo "    | jq -r '.Command.CommandId')"
        fi

        echo "echo \"  Install command: \$INSTALL_CMD\""
        echo "echo '  Waiting for installation (this may take several minutes)...'"
        echo "aws_cmd ssm wait command-executed \\"
        echo "    --command-id \"\$INSTALL_CMD\" --instance-id \"\$INSTANCE_ID\" 2>/dev/null || sleep 300"
        echo ""

        # Step 5: Get results
        echo "# ── Step 5: Check Results ──"
        echo "echo '[5/6] Checking patch results...'"
        echo "RESULT=\$(aws_cmd ssm get-command-invocation \\"
        echo "    --command-id \"\$INSTALL_CMD\" --instance-id \"\$INSTANCE_ID\" 2>/dev/null)"
        echo "STATUS=\$(echo \"\$RESULT\" | jq -r '.Status // \"Unknown\"')"
        echo "echo \"  Patch status: \$STATUS\""
        echo "echo \"\$RESULT\" | jq -r '.StandardOutputContent // empty' | head -20"
        echo ""

        # Step 6: Verify
        echo "# ── Step 6: Post-Patch Verification ──"
        echo "echo '[6/6] Verifying instance health...'"
        echo "sleep 30"
        echo "FINAL_STATE=\$(aws_cmd ec2 describe-instances --instance-ids \"\$INSTANCE_ID\" \\"
        echo "    | jq -r '.Reservations[0].Instances[0].State.Name')"
        echo "echo \"  Instance state: \$FINAL_STATE\""
        echo ""
        echo "if [[ \"\$FINAL_STATE\" == \"running\" ]]; then"
        echo "    echo ''"
        echo "    echo 'Patching completed successfully!'"
        echo "    echo \"Backup AMI available: \$BACKUP_AMI\""
        echo "else"
        echo "    echo 'WARNING: Instance may be rebooting. Check status manually.'"
        echo "    echo \"Backup AMI for rollback: \$BACKUP_AMI\""
        echo "fi"
    } > "$filepath"

    chmod +x "$filepath"
}
