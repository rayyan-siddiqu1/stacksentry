#!/usr/bin/env bash
# modules/iam_lens/audit.sh — Full IAM security audit

iam_lens_audit() {
    aws_init
    init_findings

    print_header "IAM Lens — Security Audit"

    print_info "Checking root account security..."
    check_root_mfa
    check_root_access_keys

    print_info "Checking user MFA enrollment..."
    check_user_mfa

    print_info "Checking access key hygiene..."
    check_access_key_age

    print_info "Checking for inactive users..."
    check_inactive_users

    print_info "Checking password policy..."
    check_password_policy

    print_info "Checking for over-privileged policies..."
    check_overprivileged
    check_inline_policies

    echo ""
    summarize_findings || true
    post_scan_actions "iam_lens"
}

# ── Root Account Checks ────────────────────────────────────────────────────
check_root_mfa() {
    local summary
    summary=$(aws_cmd iam get-account-summary 2>/dev/null) || {
        log_warn "iam_lens" "Failed to get account summary, skipping root checks"
        return 0
    }

    local mfa_enabled
    mfa_enabled=$(echo "$summary" | jq -r '.SummaryMap.AccountMFAEnabled // 0')
    if [[ "$mfa_enabled" -eq 0 ]]; then
        add_finding "CRITICAL" "iam_lens" "root-account" \
            "Root account MFA is not enabled" \
            "Enable MFA on the root account: AWS Console > Security Credentials"
    else
        print_pass "Root account MFA is enabled"
    fi
}

check_root_access_keys() {
    local summary
    summary=$(aws_cmd iam get-account-summary 2>/dev/null) || return 0

    local keys_present
    keys_present=$(echo "$summary" | jq -r '.SummaryMap.AccountAccessKeysPresent // 0')
    if [[ "$keys_present" -gt 0 ]]; then
        add_finding "CRITICAL" "iam_lens" "root-account" \
            "Root account has active access keys" \
            "Remove root access keys: aws iam delete-access-key --user-name root"
    else
        print_pass "Root account has no active access keys"
    fi
}

# ── User MFA ────────────────────────────────────────────────────────────────
check_user_mfa() {
    local users
    users=$(aws_cmd iam list-users 2>/dev/null | jq -r '.Users[].UserName') || {
        log_warn "iam_lens" "Failed to list users"
        return 0
    }

    [[ -z "$users" ]] && { print_pass "No IAM users found"; return 0; }

    while IFS= read -r user; do
        local mfa_devices
        mfa_devices=$(aws_cmd iam list-mfa-devices --user-name "$user" 2>/dev/null \
            | jq -r '.MFADevices | length') || continue

        if [[ "$mfa_devices" -eq 0 ]]; then
            # Check if user has console access (password)
            local login_profile
            if aws_cmd iam get-login-profile --user-name "$user" &>/dev/null; then
                add_finding "CRITICAL" "iam_lens" "user:${user}" \
                    "Console user has no MFA device" \
                    "Enable MFA: aws iam enable-mfa-device --user-name ${user}"
            else
                add_finding "MEDIUM" "iam_lens" "user:${user}" \
                    "Programmatic user has no MFA device" \
                    "Consider enabling MFA for all users"
            fi
        fi
    done <<< "$users"
}

# ── Access Key Age ──────────────────────────────────────────────────────────
check_access_key_age() {
    local users
    users=$(aws_cmd iam list-users 2>/dev/null | jq -r '.Users[].UserName') || return 0

    [[ -z "$users" ]] && return 0

    local now_epoch
    now_epoch=$(date +%s)

    while IFS= read -r user; do
        local keys
        keys=$(aws_cmd iam list-access-keys --user-name "$user" 2>/dev/null) || continue

        echo "$keys" | jq -c '.AccessKeyMetadata[]' 2>/dev/null | while IFS= read -r key; do
            local key_id status create_date
            key_id=$(echo "$key" | jq -r '.AccessKeyId')
            status=$(echo "$key" | jq -r '.Status')
            create_date=$(echo "$key" | jq -r '.CreateDate')

            [[ "$status" != "Active" ]] && continue

            # Calculate age in days
            local create_epoch age_days
            create_epoch=$(date -d "$create_date" +%s 2>/dev/null) || \
                create_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${create_date%%+*}" +%s 2>/dev/null) || continue
            age_days=$(( (now_epoch - create_epoch) / 86400 ))

            if [[ "$age_days" -gt 180 ]]; then
                add_finding "CRITICAL" "iam_lens" "user:${user}/key:${key_id}" \
                    "Access key is ${age_days} days old (>180)" \
                    "Rotate key: aws iam create-access-key && aws iam delete-access-key --access-key-id ${key_id}"
            elif [[ "$age_days" -gt 90 ]]; then
                add_finding "HIGH" "iam_lens" "user:${user}/key:${key_id}" \
                    "Access key is ${age_days} days old (>90)" \
                    "Rotate access keys every 90 days"
            fi

            # Check last used
            local last_used
            last_used=$(aws_cmd iam get-access-key-last-used --access-key-id "$key_id" 2>/dev/null \
                | jq -r '.AccessKeyLastUsed.LastUsedDate // "N/A"') || continue

            if [[ "$last_used" == "N/A" ]] && [[ "$age_days" -gt 30 ]]; then
                add_finding "HIGH" "iam_lens" "user:${user}/key:${key_id}" \
                    "Access key never used (${age_days} days old)" \
                    "Delete unused key: aws iam delete-access-key --access-key-id ${key_id} --user-name ${user}"
            fi
        done
    done <<< "$users"
}

# ── Inactive Users ──────────────────────────────────────────────────────────
check_inactive_users() {
    # Generate credential report
    aws_cmd iam generate-credential-report &>/dev/null || true
    sleep 2

    local report
    report=$(aws_cmd iam get-credential-report 2>/dev/null) || {
        log_warn "iam_lens" "Could not get credential report, skipping inactive user check"
        return 0
    }

    local csv_content
    csv_content=$(echo "$report" | jq -r '.Content' | base64 -d 2>/dev/null) || {
        log_warn "iam_lens" "Could not decode credential report"
        return 0
    }

    local now_epoch
    now_epoch=$(date +%s)

    # Skip header line, process each user
    echo "$csv_content" | tail -n +2 | while IFS=',' read -r user _ _ _ password_last_used _ _ _ _ _ access_key_1_active _ access_key_1_last_used _ _ access_key_2_active _ access_key_2_last_used _; do
        [[ "$user" == "<root_account>" ]] && continue

        local last_activity="N/A"
        local last_epoch=0

        # Find most recent activity
        for date_val in "$password_last_used" "$access_key_1_last_used" "$access_key_2_last_used"; do
            if [[ "$date_val" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
                local epoch
                epoch=$(date -d "$date_val" +%s 2>/dev/null) || continue
                if [[ "$epoch" -gt "$last_epoch" ]]; then
                    last_epoch=$epoch
                    last_activity=$date_val
                fi
            fi
        done

        if [[ "$last_epoch" -gt 0 ]]; then
            local days_inactive=$(( (now_epoch - last_epoch) / 86400 ))
            if [[ "$days_inactive" -gt 90 ]]; then
                add_finding "MEDIUM" "iam_lens" "user:${user}" \
                    "User inactive for ${days_inactive} days (last active: ${last_activity})" \
                    "Review and disable: aws iam update-login-profile --user-name ${user} --no-password-reset-required"
            fi
        fi
    done
}

# ── Password Policy ─────────────────────────────────────────────────────────
check_password_policy() {
    local policy
    policy=$(aws_cmd iam get-account-password-policy 2>/dev/null) || {
        add_finding "HIGH" "iam_lens" "password-policy" \
            "No custom password policy configured" \
            "Set password policy: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90"
        return 0
    }

    local min_length require_symbols require_numbers require_upper require_lower max_age
    min_length=$(echo "$policy" | jq -r '.PasswordPolicy.MinimumPasswordLength // 0')
    require_symbols=$(echo "$policy" | jq -r '.PasswordPolicy.RequireSymbols // false')
    require_numbers=$(echo "$policy" | jq -r '.PasswordPolicy.RequireNumbers // false')
    require_upper=$(echo "$policy" | jq -r '.PasswordPolicy.RequireUppercaseCharacters // false')
    require_lower=$(echo "$policy" | jq -r '.PasswordPolicy.RequireLowercaseCharacters // false')
    max_age=$(echo "$policy" | jq -r '.PasswordPolicy.MaxPasswordAge // 0')

    if [[ "$min_length" -lt 14 ]]; then
        add_finding "MEDIUM" "iam_lens" "password-policy" \
            "Minimum password length is ${min_length} (recommended: 14)" \
            "aws iam update-account-password-policy --minimum-password-length 14"
    fi

    if [[ "$require_symbols" != "true" ]]; then
        add_finding "LOW" "iam_lens" "password-policy" \
            "Password policy does not require symbols" \
            "aws iam update-account-password-policy --require-symbols"
    fi

    if [[ "$require_numbers" != "true" ]]; then
        add_finding "LOW" "iam_lens" "password-policy" \
            "Password policy does not require numbers" \
            "aws iam update-account-password-policy --require-numbers"
    fi

    if [[ "$max_age" -eq 0 ]]; then
        add_finding "MEDIUM" "iam_lens" "password-policy" \
            "Password rotation not enforced" \
            "aws iam update-account-password-policy --max-password-age 90"
    fi
}

# ── Over-Privileged Policies ────────────────────────────────────────────────
check_overprivileged() {
    local users
    users=$(aws_cmd iam list-users 2>/dev/null | jq -r '.Users[].UserName') || return 0

    [[ -z "$users" ]] && return 0

    while IFS= read -r user; do
        # Check attached managed policies
        local policies
        policies=$(aws_cmd iam list-attached-user-policies --user-name "$user" 2>/dev/null \
            | jq -r '.AttachedPolicies[].PolicyArn') || continue

        while IFS= read -r policy_arn; do
            [[ -z "$policy_arn" ]] && continue

            if [[ "$policy_arn" == *"AdministratorAccess"* ]]; then
                add_finding "HIGH" "iam_lens" "user:${user}" \
                    "User has AdministratorAccess policy attached" \
                    "Replace with least-privilege policy: aws iam detach-user-policy --user-name ${user} --policy-arn ${policy_arn}"
            fi

            if [[ "$policy_arn" == *"IAMFullAccess"* ]]; then
                add_finding "HIGH" "iam_lens" "user:${user}" \
                    "User has IAMFullAccess policy (can escalate privileges)" \
                    "Restrict IAM permissions to minimum required"
            fi
        done <<< "$policies"

        # Check inline policies for wildcard actions
        local inline_policies
        inline_policies=$(aws_cmd iam list-user-policies --user-name "$user" 2>/dev/null \
            | jq -r '.PolicyNames[]') || continue

        while IFS= read -r policy_name; do
            [[ -z "$policy_name" ]] && continue

            local policy_doc
            policy_doc=$(aws_cmd iam get-user-policy --user-name "$user" --policy-name "$policy_name" 2>/dev/null \
                | jq -r '.PolicyDocument') || continue

            # Check for Action: "*" with Resource: "*"
            local wildcard_count
            wildcard_count=$(echo "$policy_doc" | jq '[.Statement[] | select(.Effect=="Allow" and (.Action=="*" or .Action==["*"]) and (.Resource=="*" or .Resource==["*"]))] | length' 2>/dev/null) || continue

            if [[ "$wildcard_count" -gt 0 ]]; then
                add_finding "CRITICAL" "iam_lens" "user:${user}/policy:${policy_name}" \
                    "Inline policy grants full admin access (Action:*, Resource:*)" \
                    "Replace with least-privilege inline policy"
            fi
        done <<< "$inline_policies"
    done <<< "$users"

    # Check roles for open trust policies
    local roles
    roles=$(aws_cmd iam list-roles 2>/dev/null | jq -r '.Roles[].RoleName') || return 0

    while IFS= read -r role; do
        [[ -z "$role" ]] && continue
        [[ "$role" == aws-service-role/* ]] && continue

        local trust_policy
        trust_policy=$(aws_cmd iam get-role --role-name "$role" 2>/dev/null \
            | jq -r '.Role.AssumeRolePolicyDocument') || continue

        # Check for Principal: "*"
        local open_principal
        open_principal=$(echo "$trust_policy" | jq '[.Statement[] | select(.Principal=="*" or .Principal.AWS=="*")] | length' 2>/dev/null) || continue

        if [[ "$open_principal" -gt 0 ]]; then
            add_finding "CRITICAL" "iam_lens" "role:${role}" \
                "Role trust policy allows any principal (Principal: *)" \
                "Restrict trust policy to specific accounts/services"
        fi

        # Check for AdministratorAccess on role
        local role_policies
        role_policies=$(aws_cmd iam list-attached-role-policies --role-name "$role" 2>/dev/null \
            | jq -r '.AttachedPolicies[].PolicyArn') || continue

        while IFS= read -r rp; do
            [[ -z "$rp" ]] && continue
            if [[ "$rp" == *"AdministratorAccess"* ]]; then
                add_finding "HIGH" "iam_lens" "role:${role}" \
                    "Role has AdministratorAccess attached" \
                    "Apply least-privilege policies to role"
            fi
        done <<< "$role_policies"
    done <<< "$roles"
}

# ── Inline Policies ─────────────────────────────────────────────────────────
check_inline_policies() {
    local summary
    summary=$(aws_cmd iam get-account-summary 2>/dev/null) || return 0

    local user_inline group_inline role_inline
    user_inline=$(echo "$summary" | jq -r '.SummaryMap.UserPolicySizeQuota // 0')
    group_inline=$(echo "$summary" | jq -r '.SummaryMap.GroupPolicySizeQuota // 0')

    # Count actual inline policies
    local users
    users=$(aws_cmd iam list-users 2>/dev/null | jq -r '.Users[].UserName') || return 0

    local inline_count=0
    while IFS= read -r user; do
        local count
        count=$(aws_cmd iam list-user-policies --user-name "$user" 2>/dev/null \
            | jq -r '.PolicyNames | length') || continue
        inline_count=$((inline_count + count))
    done <<< "$users"

    if [[ "$inline_count" -gt 0 ]]; then
        add_finding "MEDIUM" "iam_lens" "iam-config" \
            "${inline_count} inline policies found (use managed policies instead)" \
            "Convert inline policies to managed policies for better governance"
    fi
}
