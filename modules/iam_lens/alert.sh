#!/usr/bin/env bash
# modules/iam_lens/alert.sh — CloudTrail IAM event monitoring

# Events considered suspicious
IAM_ALERT_EVENTS=(
    "CreateUser"
    "DeleteUser"
    "AttachUserPolicy"
    "DetachUserPolicy"
    "AttachRolePolicy"
    "CreateAccessKey"
    "CreateLoginProfile"
    "UpdateLoginProfile"
    "PutUserPolicy"
    "PutRolePolicy"
    "CreateRole"
    "DeleteRole"
    "ConsoleLogin"
    "CreatePolicy"
    "CreatePolicyVersion"
)

iam_lens_alert() {
    aws_init
    init_findings

    print_header "IAM Lens — CloudTrail Event Monitor"

    local hours="${1:-24}"
    local start_time
    start_time=$(date -u -d "${hours} hours ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || \
        start_time=$(date -u -v-${hours}H +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || {
        # Fallback
        start_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    }

    print_info "Scanning CloudTrail events from last ${hours} hours..."

    for event_name in "${IAM_ALERT_EVENTS[@]}"; do
        _check_cloudtrail_event "$event_name" "$start_time"
    done

    echo ""
    summarize_findings || true
    post_scan_actions "iam_lens_alert"
}

_check_cloudtrail_event() {
    local event_name="$1" start_time="$2"

    local events
    events=$(aws_cmd cloudtrail lookup-events \
        --lookup-attributes "AttributeKey=EventName,AttributeValue=${event_name}" \
        --start-time "$start_time" \
        --max-results 50 2>/dev/null) || {
        log_debug "iam_lens" "Could not lookup CloudTrail event: ${event_name}"
        return 0
    }

    local count
    count=$(echo "$events" | jq '.Events | length')
    [[ "$count" -eq 0 ]] && return 0

    echo "$events" | jq -c '.Events[]' 2>/dev/null | while IFS= read -r event; do
        local username source_ip event_time resources_text
        username=$(echo "$event" | jq -r '.Username // "unknown"')
        source_ip=$(echo "$event" | jq -r '.CloudTrailEvent' | jq -r '.sourceIPAddress // "unknown"' 2>/dev/null)
        event_time=$(echo "$event" | jq -r '.EventTime // "unknown"')
        resources_text=$(echo "$event" | jq -r '[.Resources[]?.ResourceName // empty] | join(", ")' 2>/dev/null)

        local severity="MEDIUM"
        local detail="${event_name} by ${username} from ${source_ip}"
        [[ -n "$resources_text" ]] && detail+=" (resources: ${resources_text})"

        # Escalate severity based on event type
        case "$event_name" in
            CreateUser|AttachUserPolicy|AttachRolePolicy|PutUserPolicy|PutRolePolicy)
                severity="HIGH"
                ;;
            CreateAccessKey|CreateLoginProfile)
                severity="HIGH"
                ;;
            ConsoleLogin)
                # Check for failed logins or unusual IPs
                local error_code
                error_code=$(echo "$event" | jq -r '.CloudTrailEvent' | jq -r '.errorCode // "none"' 2>/dev/null)
                if [[ "$error_code" != "none" && "$error_code" != "null" ]]; then
                    severity="CRITICAL"
                    detail+=" [FAILED: ${error_code}]"
                else
                    severity="MEDIUM"
                fi
                ;;
        esac

        # Check for off-hours activity (before 06:00 or after 22:00 UTC)
        local hour
        hour=$(echo "$event_time" | grep -oP '\d{2}(?=:\d{2}:\d{2})' | head -1)
        if [[ -n "$hour" ]] && { [[ "$hour" -lt 6 ]] || [[ "$hour" -gt 22 ]]; }; then
            severity="HIGH"
            detail+=" [OFF-HOURS]"
        fi

        add_finding "$severity" "iam_lens" "cloudtrail:${event_name}" \
            "$detail" \
            "Review this activity and verify it was authorized"
    done
}
