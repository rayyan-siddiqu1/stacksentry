#!/usr/bin/env bash
# core/alert.sh — Slack webhook and email alert dispatch

send_alert() {
    local module_name="$1" summary_text="$2"
    local sent=0

    if [[ -n "${STACKSENTRY_SLACK_WEBHOOK:-}" ]]; then
        send_slack "[StackSentry/${module_name}] ${summary_text}" && sent=1
    fi

    if [[ -n "${STACKSENTRY_EMAIL_TO:-}" ]]; then
        send_email "StackSentry Alert: ${module_name}" "$summary_text" && sent=1
    fi

    if [[ "$sent" -eq 0 ]]; then
        log_warn "alert" "No alert channels configured. Set STACKSENTRY_SLACK_WEBHOOK or STACKSENTRY_EMAIL_TO in config."
    fi
}

send_slack() {
    local message="$1"
    local webhook="${STACKSENTRY_SLACK_WEBHOOK:-}"

    if [[ -z "$webhook" ]]; then
        log_debug "alert" "Slack webhook not configured, skipping"
        return 1
    fi

    # Escape JSON special characters
    message="${message//\\/\\\\}"
    message="${message//\"/\\\"}"
    message="${message//$'\n'/\\n}"

    local payload="{\"text\":\"${message}\"}"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "$payload" "$webhook" 2>/dev/null) || {
        log_error "alert" "Slack alert failed: curl error"
        return 1
    }

    if [[ "$http_code" == "200" ]]; then
        log_info "alert" "Slack alert sent successfully"
        return 0
    else
        log_error "alert" "Slack alert failed: HTTP $http_code"
        return 1
    fi
}

send_email() {
    local subject="$1" body="$2"
    local to="${STACKSENTRY_EMAIL_TO:-}"
    local from="${STACKSENTRY_EMAIL_FROM:-stacksentry@localhost}"

    if [[ -z "$to" ]]; then
        log_debug "alert" "Email not configured, skipping"
        return 1
    fi

    if command -v mail &>/dev/null; then
        echo "$body" | mail -s "$subject" -r "$from" "$to" 2>/dev/null && {
            log_info "alert" "Email sent to $to"
            return 0
        }
    elif command -v sendmail &>/dev/null; then
        {
            echo "From: $from"
            echo "To: $to"
            echo "Subject: $subject"
            echo ""
            echo "$body"
        } | sendmail "$to" 2>/dev/null && {
            log_info "alert" "Email sent to $to via sendmail"
            return 0
        }
    fi

    log_warn "alert" "No mail binary found (mail or sendmail). Email alert skipped."
    return 1
}

alert_on_critical() {
    local module_name="$1"
    if [[ "${COUNTER_CRITICAL:-0}" -gt 0 ]]; then
        local total=$(( COUNTER_CRITICAL + COUNTER_HIGH + COUNTER_MEDIUM + COUNTER_LOW ))
        local summary="${COUNTER_CRITICAL} CRITICAL findings detected (${total} total)"
        summary+=$'\n'"Top critical findings:"

        for finding in "${FINDINGS[@]}"; do
            IFS='|' read -r sev mod res desc rem ts <<< "$finding"
            if [[ "$sev" == "CRITICAL" ]]; then
                summary+=$'\n'"  - ${res}: ${desc}"
            fi
        done

        send_alert "$module_name" "$summary"
    fi
}
