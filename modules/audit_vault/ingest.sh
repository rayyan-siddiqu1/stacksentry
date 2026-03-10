#!/usr/bin/env bash
# modules/audit_vault/ingest.sh — Pull and normalize CloudTrail logs from S3

AUDIT_MODULE="audit_vault"
AUDIT_LOG="${STACKSENTRY_HOME}/logs/audit_vault.log"

audit_vault_ingest() {
    aws_init

    local bucket=""
    local prefix=""
    local days=7

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --bucket) bucket="$2"; shift 2 ;;
            --prefix) prefix="$2"; shift 2 ;;
            --days)   days="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if [[ -z "$bucket" ]]; then
        print_fail "Usage: stacksentry logs ingest --bucket <s3-path> [--prefix <path>] [--days <n>]"
        exit 1
    fi

    print_header "Audit Vault — CloudTrail Log Ingestion"
    print_info "Source: s3://${bucket}/${prefix}"
    print_info "Ingesting last ${days} days of logs..."

    local tmp_dir="/tmp/stacksentry_cloudtrail_$$"
    mkdir -p "$tmp_dir"

    # Sync from S3
    print_info "Downloading logs from S3..."
    local s3_path="s3://${bucket}"
    [[ -n "$prefix" ]] && s3_path="${s3_path}/${prefix}"

    aws_cmd s3 sync "$s3_path" "$tmp_dir" \
        --exclude "*" --include "*.json.gz" --include "*.json" \
        --quiet 2>/dev/null || {
        print_fail "Failed to sync from S3. Check bucket name and permissions."
        rm -rf "$tmp_dir"
        exit 1
    }

    local file_count
    file_count=$(find "$tmp_dir" -type f \( -name "*.json.gz" -o -name "*.json" \) | wc -l | tr -d ' ')
    print_info "Downloaded ${file_count} log files"

    if [[ "$file_count" -eq 0 ]]; then
        print_warn "No CloudTrail log files found"
        rm -rf "$tmp_dir"
        return 0
    fi

    # Ensure audit log exists
    mkdir -p "$(dirname "$AUDIT_LOG")"
    touch "$AUDIT_LOG"

    local events_ingested=0
    local now_epoch
    now_epoch=$(date +%s)
    local cutoff_epoch=$((now_epoch - days * 86400))

    # Process each file
    print_info "Parsing and normalizing events..."
    find "$tmp_dir" -type f \( -name "*.json.gz" -o -name "*.json" \) | while IFS= read -r file; do
        local json_content

        if [[ "$file" == *.json.gz ]]; then
            json_content=$(gunzip -c "$file" 2>/dev/null) || continue
        else
            json_content=$(cat "$file") || continue
        fi

        # Extract and normalize events
        echo "$json_content" | jq -c '.Records[]?' 2>/dev/null | while IFS= read -r event; do
            [[ -z "$event" ]] && continue

            local event_time user_identity event_name source_ip region resources
            event_time=$(echo "$event" | jq -r '.eventTime // empty')
            [[ -z "$event_time" ]] && continue

            # Filter by date range
            local event_epoch
            event_epoch=$(date -d "$event_time" +%s 2>/dev/null) || continue
            [[ "$event_epoch" -lt "$cutoff_epoch" ]] && continue

            user_identity=$(echo "$event" | jq -r '
                .userIdentity |
                if .type == "IAMUser" then .userName
                elif .type == "AssumedRole" then (.sessionContext.sessionIssuer.userName // .arn)
                elif .type == "Root" then "root"
                elif .type == "AWSService" then .invokedBy
                else (.arn // .type // "unknown")
                end // "unknown"')

            event_name=$(echo "$event" | jq -r '.eventName // "unknown"')
            source_ip=$(echo "$event" | jq -r '.sourceIPAddress // "unknown"')
            region=$(echo "$event" | jq -r '.awsRegion // "unknown"')

            resources=$(echo "$event" | jq -r '
                [.resources[]?.ARN // empty] | join(",") //
                (.requestParameters | keys[0:2] | join(",")) // "N/A"' 2>/dev/null) || resources="N/A"

            # Normalize to pipe-delimited format
            local normalized="${event_time}|${user_identity}|${event_name}|${resources}|${source_ip}|${region}"

            # Deduplicate: check if this exact line already exists
            if ! grep -qF "$normalized" "$AUDIT_LOG" 2>/dev/null; then
                echo "$normalized" >> "$AUDIT_LOG"
                events_ingested=$((events_ingested + 1))
            fi
        done
    done

    # Cleanup
    rm -rf "$tmp_dir"

    local total_events
    total_events=$(wc -l < "$AUDIT_LOG" | tr -d ' ')

    echo ""
    print_pass "Ingestion complete"
    print_info "New events ingested: ${events_ingested}"
    print_info "Total events in vault: ${total_events}"
    print_info "Audit log: ${AUDIT_LOG}"
}
