#!/usr/bin/env bash
# modules/audit_vault/alert_rules.sh — Configurable alert rules for audit events

# Default alert rules (used when config/alert_rules.conf doesn't exist)
DEFAULT_ALERT_RULES=(
    "DeleteBucket|1|CRITICAL"
    "DeleteDBInstance|1|CRITICAL"
    "TerminateInstances|5|HIGH"
    "StopInstances|10|HIGH"
    "CreateUser|3|HIGH"
    "CreateAccessKey|3|HIGH"
    "AttachUserPolicy|3|HIGH"
    "PutBucketPolicy|2|HIGH"
    "AuthorizeSecurityGroupIngress|5|MEDIUM"
    "ConsoleLogin|20|MEDIUM"
)

check_alert_rules() {
    local data="$1"

    # Load rules from config if available
    local rules_file="${STACKSENTRY_HOME}/config/alert_rules.conf"
    local rules=()

    if [[ -f "$rules_file" ]]; then
        while IFS='|' read -r event threshold severity; do
            [[ "$event" =~ ^# ]] && continue
            [[ -z "$event" ]] && continue
            rules+=("${event}|${threshold}|${severity}")
        done < "$rules_file"
    else
        rules=("${DEFAULT_ALERT_RULES[@]}")
    fi

    for rule in "${rules[@]}"; do
        IFS='|' read -r event_pattern threshold severity <<< "$rule"

        local match_count
        match_count=$(echo "$data" | awk -F'|' -v pat="$event_pattern" '$3 ~ pat' | wc -l | tr -d ' ')

        if [[ "$match_count" -ge "$threshold" ]]; then
            add_finding "$severity" "audit_vault" "alert:${event_pattern}" \
                "${match_count} '${event_pattern}' events detected (threshold: ${threshold})" \
                "Review events: stacksentry logs search --event ${event_pattern}"
        fi
    done
}
