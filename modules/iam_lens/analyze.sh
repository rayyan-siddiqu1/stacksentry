#!/usr/bin/env bash
# modules/iam_lens/analyze.sh — Deep IAM least-privilege analysis

iam_lens_analyze() {
    aws_init
    init_findings

    print_header "IAM Lens — Deep Analysis"

    print_info "Analyzing unused roles..."
    analyze_unused_roles

    print_info "Analyzing trust policies..."
    analyze_trust_policies

    print_info "Analyzing service access patterns..."
    analyze_service_last_accessed

    echo ""
    summarize_findings || true
    post_scan_actions "iam_lens_analyze"
}

# ── Unused Roles ────────────────────────────────────────────────────────────
analyze_unused_roles() {
    local roles
    roles=$(aws_cmd iam list-roles 2>/dev/null | jq -c '.Roles[]') || {
        log_warn "iam_lens" "Failed to list roles"
        return 0
    }

    local now_epoch
    now_epoch=$(date +%s)

    while IFS= read -r role_json; do
        [[ -z "$role_json" ]] && continue

        local role_name path last_used_date
        role_name=$(echo "$role_json" | jq -r '.RoleName')
        path=$(echo "$role_json" | jq -r '.Path')

        # Skip AWS service-linked roles
        [[ "$path" == "/aws-service-role/"* ]] && continue

        last_used_date=$(echo "$role_json" | jq -r '.RoleLastUsed.LastUsedDate // "never"')

        if [[ "$last_used_date" == "never" ]]; then
            local create_date
            create_date=$(echo "$role_json" | jq -r '.CreateDate')
            local create_epoch
            create_epoch=$(date -d "$create_date" +%s 2>/dev/null) || continue
            local age_days=$(( (now_epoch - create_epoch) / 86400 ))

            if [[ "$age_days" -gt 90 ]]; then
                add_finding "LOW" "iam_lens" "role:${role_name}" \
                    "Role never used (created ${age_days} days ago)" \
                    "Delete unused role: aws iam delete-role --role-name ${role_name}"
            fi
        else
            local used_epoch
            used_epoch=$(date -d "$last_used_date" +%s 2>/dev/null) || continue
            local days_unused=$(( (now_epoch - used_epoch) / 86400 ))

            if [[ "$days_unused" -gt 90 ]]; then
                add_finding "LOW" "iam_lens" "role:${role_name}" \
                    "Role unused for ${days_unused} days" \
                    "Review and consider deleting: aws iam delete-role --role-name ${role_name}"
            fi
        fi
    done <<< "$roles"
}

# ── Trust Policy Analysis ───────────────────────────────────────────────────
analyze_trust_policies() {
    local roles
    roles=$(aws_cmd iam list-roles 2>/dev/null | jq -r '.Roles[].RoleName') || return 0

    while IFS= read -r role; do
        [[ -z "$role" ]] && continue

        local trust_doc
        trust_doc=$(aws_cmd iam get-role --role-name "$role" 2>/dev/null \
            | jq -r '.Role.AssumeRolePolicyDocument') || continue

        # Check for cross-account access
        local external_accounts
        external_accounts=$(echo "$trust_doc" | jq -r '
            [.Statement[].Principal // {} |
             if type == "object" then (.AWS // empty) else . end |
             if type == "array" then .[] else . end] |
            map(select(. != "*" and test("arn:aws:iam::[0-9]+:"))) |
            unique[]' 2>/dev/null) || continue

        local account_id
        account_id=$(aws_account_id)

        while IFS= read -r principal; do
            [[ -z "$principal" ]] && continue
            # Extract account ID from ARN
            local ext_account
            ext_account=$(echo "$principal" | grep -oP '(?<=arn:aws:iam::)\d{12}' 2>/dev/null) || continue

            if [[ "$ext_account" != "$account_id" ]]; then
                add_finding "MEDIUM" "iam_lens" "role:${role}" \
                    "Cross-account trust: allows access from account ${ext_account}" \
                    "Verify this cross-account trust is intentional and documented"
            fi
        done <<< "$external_accounts"

        # Check for overly broad service principals
        local service_principals
        service_principals=$(echo "$trust_doc" | jq -r '
            [.Statement[].Principal // {} |
             if type == "object" then (.Service // empty) else empty end |
             if type == "array" then .[] else . end] | unique[]' 2>/dev/null) || continue

        # Flag if role has both broad trust AND admin access
        if [[ -n "$service_principals" ]]; then
            local has_admin
            has_admin=$(aws_cmd iam list-attached-role-policies --role-name "$role" 2>/dev/null \
                | jq -r '.AttachedPolicies[] | select(.PolicyArn | contains("AdministratorAccess")) | .PolicyArn') || continue

            if [[ -n "$has_admin" ]]; then
                add_finding "HIGH" "iam_lens" "role:${role}" \
                    "Service role with AdministratorAccess (services: $(echo "$service_principals" | tr '\n' ', '))" \
                    "Apply least-privilege policies instead of AdministratorAccess"
            fi
        fi
    done <<< "$roles"
}

# ── Service Last Accessed ───────────────────────────────────────────────────
analyze_service_last_accessed() {
    local users
    users=$(aws_cmd iam list-users 2>/dev/null | jq -r '.Users[] | "\(.UserName)|\(.Arn)"') || return 0

    [[ -z "$users" ]] && return 0

    while IFS='|' read -r user arn; do
        [[ -z "$arn" ]] && continue

        # Generate report
        local job_id
        job_id=$(aws_cmd iam generate-service-last-accessed-details --arn "$arn" 2>/dev/null \
            | jq -r '.JobId') || continue

        [[ -z "$job_id" || "$job_id" == "null" ]] && continue

        # Poll for completion (max 10 seconds)
        local status="IN_PROGRESS"
        local attempts=0
        while [[ "$status" == "IN_PROGRESS" ]] && [[ $attempts -lt 5 ]]; do
            sleep 2
            local result
            result=$(aws_cmd iam get-service-last-accessed-details --job-id "$job_id" 2>/dev/null) || break
            status=$(echo "$result" | jq -r '.JobStatus')
            attempts=$((attempts + 1))
        done

        [[ "$status" != "COMPLETED" ]] && continue

        local details
        details=$(aws_cmd iam get-service-last-accessed-details --job-id "$job_id" 2>/dev/null) || continue

        # Count services granted vs used
        local total_services used_services
        total_services=$(echo "$details" | jq '.ServicesLastAccessed | length')
        used_services=$(echo "$details" | jq '[.ServicesLastAccessed[] | select(.LastAuthenticated != null)] | length')

        local unused=$((total_services - used_services))
        if [[ "$unused" -gt 5 && "$total_services" -gt 0 ]]; then
            local usage_pct=$((used_services * 100 / total_services))
            add_finding "MEDIUM" "iam_lens" "user:${user}" \
                "Over-provisioned: uses ${used_services}/${total_services} granted services (${usage_pct}%)" \
                "Review and remove unused service permissions for ${user}"
        fi
    done <<< "$users"
}
