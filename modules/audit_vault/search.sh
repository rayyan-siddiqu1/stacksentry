#!/usr/bin/env bash
# modules/audit_vault/search.sh — Search and analyze ingested CloudTrail logs

AUDIT_MODULE="audit_vault"
AUDIT_LOG="${STACKSENTRY_HOME}/logs/audit_vault.log"

audit_vault_search() {
    local filter_user="" filter_event="" filter_ip="" filter_region=""
    local filter_from="" filter_to=""
    local alert_check=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user)   filter_user="$2"; shift 2 ;;
            --event)  filter_event="$2"; shift 2 ;;
            --ip)     filter_ip="$2"; shift 2 ;;
            --region) filter_region="$2"; shift 2 ;;
            --from)   filter_from="$2"; shift 2 ;;
            --to)     filter_to="$2"; shift 2 ;;
            --alert-check) alert_check=true; shift ;;
            *) shift ;;
        esac
    done

    if [[ ! -f "$AUDIT_LOG" || ! -s "$AUDIT_LOG" ]]; then
        print_fail "Audit vault is empty. Run: stacksentry logs ingest --bucket <name>"
        exit 1
    fi

    if [[ "$alert_check" == true ]]; then
        _run_alert_check
        return $?
    fi

    print_header "Audit Vault — Log Search"

    init_findings

    # Apply filters
    local results
    results=$(cat "$AUDIT_LOG")

    if [[ -n "$filter_user" ]]; then
        results=$(echo "$results" | awk -F'|' -v u="$filter_user" '$2 ~ u')
        print_info "Filter: user matches '${filter_user}'"
    fi

    if [[ -n "$filter_event" ]]; then
        results=$(echo "$results" | awk -F'|' -v e="$filter_event" '$3 ~ e')
        print_info "Filter: event matches '${filter_event}'"
    fi

    if [[ -n "$filter_ip" ]]; then
        results=$(echo "$results" | awk -F'|' -v ip="$filter_ip" '$5 ~ ip')
        print_info "Filter: IP matches '${filter_ip}'"
    fi

    if [[ -n "$filter_region" ]]; then
        results=$(echo "$results" | awk -F'|' -v r="$filter_region" '$6 ~ r')
        print_info "Filter: region matches '${filter_region}'"
    fi

    if [[ -n "$filter_from" ]]; then
        results=$(echo "$results" | awk -F'|' -v from="$filter_from" '$1 >= from')
        print_info "Filter: from ${filter_from}"
    fi

    if [[ -n "$filter_to" ]]; then
        results=$(echo "$results" | awk -F'|' -v to="$filter_to" '$1 <= to')
        print_info "Filter: to ${filter_to}"
    fi

    local count
    count=$(echo "$results" | grep -c '' 2>/dev/null || echo 0)
    [[ -z "$results" ]] && count=0

    echo ""
    print_info "${count} events found"

    if [[ "$count" -eq 0 ]]; then
        return 0
    fi

    # Display results
    if [[ "${STACKSENTRY_OUTPUT_FORMAT:-table}" == "table" ]]; then
        echo ""
        printf "  ${BOLD}%-22s %-20s %-28s %-18s %-14s${RESET}\n" \
            "TIMESTAMP" "USER" "EVENT" "SOURCE_IP" "REGION"
        printf "  %-22s %-20s %-28s %-18s %-14s\n" \
            "---------" "----" "-----" "---------" "------"

        echo "$results" | tail -100 | while IFS='|' read -r ts user event resource ip region; do
            local color="$RESET"

            # Highlight anomalies
            local flags=""

            # Off-hours check
            local hour
            hour=$(echo "$ts" | grep -oP '\d{2}(?=:\d{2}:\d{2})' 2>/dev/null | head -1)
            if [[ -n "$hour" ]] && { [[ "$hour" -lt 6 ]] || [[ "$hour" -gt 22 ]]; }; then
                flags+="[OFF-HOURS] "
                color="$YELLOW"
            fi

            # IAM change events
            case "$event" in
                CreateUser|DeleteUser|AttachUserPolicy|DetachUserPolicy|CreateAccessKey|PutUserPolicy|CreateRole|DeleteRole)
                    flags+="[IAM-CHANGE] "
                    color="$RED"
                    ;;
                ConsoleLogin)
                    flags+="[LOGIN] "
                    ;;
                Delete*|Terminate*|Remove*)
                    flags+="[DESTRUCTIVE] "
                    color="$YELLOW"
                    ;;
            esac

            printf "  ${color}%-22s %-20s %-28s %-18s %-14s${RESET}" \
                "${ts:0:22}" "${user:0:20}" "${event:0:28}" "${ip:0:18}" "${region:0:14}"
            [[ -n "$flags" ]] && printf " ${RED}${flags}${RESET}"
            echo ""
        done

        if [[ "$count" -gt 100 ]]; then
            echo ""
            print_info "Showing last 100 of ${count} events. Use --from/--to to narrow."
        fi
    else
        local header="TIMESTAMP|USER|EVENT|RESOURCE|SOURCE_IP|REGION"
        local rows=()
        while IFS= read -r line; do
            rows+=("$line")
        done <<< "$results"
        print_table "$header" "${rows[@]}"
    fi

    # Anomaly detection
    echo ""
    print_header "Anomaly Detection"
    _detect_anomalies "$results"

    echo ""
    summarize_findings || true
    post_scan_actions "$AUDIT_MODULE"
}

# ── Anomaly Detection ──────────────────────────────────────────────────────
_detect_anomalies() {
    local data="$1"

    # Mass delete events (>10 deletes in 5 min window by same user)
    print_info "Checking for mass delete patterns..."
    local delete_events
    delete_events=$(echo "$data" | awk -F'|' '$3 ~ /^Delete|^Terminate|^Remove/ {print $1"|"$2"|"$3}')

    if [[ -n "$delete_events" ]]; then
        # Group by user and check frequency
        local users_with_deletes
        users_with_deletes=$(echo "$delete_events" | awk -F'|' '{print $2}' | sort | uniq -c | sort -rn)

        while read -r count user; do
            [[ -z "$user" ]] && continue
            if [[ "$count" -gt 10 ]]; then
                add_finding "HIGH" "$AUDIT_MODULE" "user:${user}" \
                    "Mass delete activity: ${count} delete events detected" \
                    "Review user activity: stacksentry logs search --user ${user} --event Delete"
            fi
        done <<< "$users_with_deletes"
    fi

    # Off-hours activity
    print_info "Checking for off-hours activity..."
    local offhours_count
    offhours_count=$(echo "$data" | awk -F'|' '{
        split($1, a, "T")
        split(a[2], b, ":")
        h = int(b[1])
        if (h < 6 || h > 22) count++
    } END {print count+0}')

    if [[ "$offhours_count" -gt 20 ]]; then
        add_finding "MEDIUM" "$AUDIT_MODULE" "audit:off-hours" \
            "${offhours_count} events outside business hours (06:00-22:00 UTC)" \
            "Review off-hours activity for unauthorized access"
    fi

    # IAM changes
    print_info "Checking for IAM modifications..."
    local iam_changes
    iam_changes=$(echo "$data" | awk -F'|' '$3 ~ /^Create(User|Role|Policy)|^Delete(User|Role)|^Attach.*Policy|^Put.*Policy|^CreateAccessKey/ {print $2": "$3}' | head -20)

    if [[ -n "$iam_changes" ]]; then
        local iam_count
        iam_count=$(echo "$iam_changes" | wc -l | tr -d ' ')
        add_finding "MEDIUM" "$AUDIT_MODULE" "audit:iam-changes" \
            "${iam_count} IAM modification events detected" \
            "Review IAM changes for unauthorized modifications"
    fi

    # Unique source IPs per user
    print_info "Checking for unusual source IPs..."
    echo "$data" | awk -F'|' '{print $2"|"$5}' | sort -u | awk -F'|' '{
        users[$1] = users[$1] " " $2
        count[$1]++
    } END {
        for (u in count) {
            if (count[u] > 5) print count[u]"|"u
        }
    }' | sort -rn -t'|' -k1 | head -5 | while IFS='|' read -r ip_count user; do
        [[ -z "$user" ]] && continue
        add_finding "LOW" "$AUDIT_MODULE" "user:${user}" \
            "User accessed from ${ip_count} different IPs" \
            "Verify all source IPs are expected for ${user}"
    done
}

# ── Alert Check (for cron) ─────────────────────────────────────────────────
_run_alert_check() {
    init_findings

    # Check last 15 minutes of events
    local since
    since=$(date -u -d "15 minutes ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || \
        since=$(date -u -v-15M +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || return 0

    local recent
    recent=$(awk -F'|' -v since="$since" '$1 >= since' "$AUDIT_LOG" 2>/dev/null)
    [[ -z "$recent" ]] && return 0

    # Load alert rules
    local rules_file="${STACKSENTRY_HOME}/config/alert_rules.conf"
    if [[ -f "$rules_file" ]]; then
        source "${STACKSENTRY_HOME}/modules/audit_vault/alert_rules.sh"
        check_alert_rules "$recent"
    fi

    # Default checks
    _detect_anomalies "$recent"

    if [[ "$COUNTER_CRITICAL" -gt 0 || "$COUNTER_HIGH" -gt 0 ]]; then
        alert_on_critical "$AUDIT_MODULE"
    fi
}
