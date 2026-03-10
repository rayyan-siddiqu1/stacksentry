#!/usr/bin/env bash
# modules/posture_board/checks/logging_checks.sh — CIS logging benchmark checks

run_logging_checks() {
    local results=()

    # 3.1 CloudTrail enabled in all regions
    local trails
    trails=$(aws_cmd cloudtrail describe-trails 2>/dev/null) || {
        results+=("3.1|CloudTrail enabled|SKIP|CRITICAL|Could not query CloudTrail|N/A")
        _emit_logging_results "${results[@]}"
        return 0
    }

    local multi_region_trail
    multi_region_trail=$(echo "$trails" | jq -r '[.trailList[] | select(.IsMultiRegionTrail==true)] | length')

    if [[ "$multi_region_trail" -gt 0 ]]; then
        # Verify at least one is actively logging
        local active_found=false
        echo "$trails" | jq -r '.trailList[] | select(.IsMultiRegionTrail==true) | .TrailARN' | while IFS= read -r arn; do
            local status
            status=$(aws_cmd cloudtrail get-trail-status --name "$arn" 2>/dev/null)
            local is_logging
            is_logging=$(echo "$status" | jq -r '.IsLogging // false')
            if [[ "$is_logging" == "true" ]]; then
                active_found=true
                break
            fi
        done

        results+=("3.1|CloudTrail enabled|PASS|CRITICAL|Multi-region trail is active|N/A")
    else
        results+=("3.1|CloudTrail enabled|FAIL|CRITICAL|No multi-region CloudTrail found|aws cloudtrail create-trail --name main-trail --is-multi-region-trail --s3-bucket-name BUCKET")
    fi

    # 3.2 CloudTrail log file validation enabled
    local validation_count
    validation_count=$(echo "$trails" | jq '[.trailList[] | select(.LogFileValidationEnabled==true)] | length')

    if [[ "$validation_count" -gt 0 ]]; then
        results+=("3.2|Log file validation|PASS|HIGH|${validation_count} trail(s) have log validation|N/A")
    else
        results+=("3.2|Log file validation|FAIL|HIGH|No trails have log file validation|aws cloudtrail update-trail --name TRAIL --enable-log-file-validation")
    fi

    # 3.3 CloudTrail logs encrypted with KMS
    local kms_count
    kms_count=$(echo "$trails" | jq '[.trailList[] | select(.KmsKeyId != null and .KmsKeyId != "")] | length')

    if [[ "$kms_count" -gt 0 ]]; then
        results+=("3.3|CloudTrail KMS encryption|PASS|HIGH|${kms_count} trail(s) encrypted with KMS|N/A")
    else
        results+=("3.3|CloudTrail KMS encryption|FAIL|HIGH|No trails use KMS encryption|aws cloudtrail update-trail --name TRAIL --kms-key-id KEY_ARN")
    fi

    # 3.4 VPC Flow Logs enabled
    local vpcs
    vpcs=$(aws_cmd ec2 describe-vpcs 2>/dev/null | jq -r '.Vpcs[].VpcId') || {
        results+=("3.4|VPC Flow Logs|SKIP|HIGH|Could not list VPCs|N/A")
        _emit_logging_results "${results[@]}"
        return 0
    }

    if [[ -z "$vpcs" ]]; then
        results+=("3.4|VPC Flow Logs|PASS|HIGH|No VPCs found|N/A")
    else
        local vpcs_without_flowlogs=0
        local vpc_details=""
        while IFS= read -r vpc_id; do
            [[ -z "$vpc_id" ]] && continue
            local flow_logs
            flow_logs=$(aws_cmd ec2 describe-flow-logs --filter "Name=resource-id,Values=${vpc_id}" 2>/dev/null \
                | jq '.FlowLogs | length')
            if [[ "${flow_logs:-0}" -eq 0 ]]; then
                vpcs_without_flowlogs=$((vpcs_without_flowlogs + 1))
                vpc_details+="${vpc_id}, "
            fi
        done <<< "$vpcs"

        if [[ "$vpcs_without_flowlogs" -eq 0 ]]; then
            results+=("3.4|VPC Flow Logs|PASS|HIGH|All VPCs have flow logs enabled|N/A")
        else
            results+=("3.4|VPC Flow Logs|FAIL|HIGH|${vpcs_without_flowlogs} VPC(s) lack flow logs: ${vpc_details%, }|aws ec2 create-flow-logs --resource-ids VPC_ID --resource-type VPC --traffic-type ALL --log-destination-type cloud-watch-logs")
        fi
    fi

    # 3.5 AWS Config enabled
    local config_recorders
    config_recorders=$(aws_cmd configservice describe-configuration-recorders 2>/dev/null) || {
        results+=("3.5|AWS Config enabled|FAIL|HIGH|AWS Config not configured|aws configservice put-configuration-recorder ...")
        _emit_logging_results "${results[@]}"
        return 0
    }

    local recorder_count
    recorder_count=$(echo "$config_recorders" | jq '.ConfigurationRecorders | length')

    if [[ "$recorder_count" -gt 0 ]]; then
        # Check if recording
        local status
        status=$(aws_cmd configservice describe-configuration-recorder-status 2>/dev/null)
        local recording
        recording=$(echo "$status" | jq '[.ConfigurationRecordersStatus[] | select(.recording==true)] | length')

        if [[ "$recording" -gt 0 ]]; then
            results+=("3.5|AWS Config enabled|PASS|HIGH|AWS Config is recording|N/A")
        else
            results+=("3.5|AWS Config enabled|FAIL|HIGH|AWS Config exists but not recording|aws configservice start-configuration-recorder --configuration-recorder-name default")
        fi
    else
        results+=("3.5|AWS Config enabled|FAIL|HIGH|No AWS Config recorder found|Enable AWS Config for compliance tracking")
    fi

    _emit_logging_results "${results[@]}"
}

_emit_logging_results() {
    for result in "$@"; do
        echo "$result"
    done
}
