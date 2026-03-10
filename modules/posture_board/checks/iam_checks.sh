#!/usr/bin/env bash
# modules/posture_board/checks/iam_checks.sh — CIS IAM benchmark checks

run_iam_checks() {
    local results=()

    # 1.1 Root account MFA enabled
    local summary
    summary=$(aws_cmd iam get-account-summary 2>/dev/null) || {
        results+=("1.1|Root account MFA|SKIP|CRITICAL|Could not retrieve account summary|N/A")
        echo "${results[-1]}"
        return 0
    }

    local root_mfa
    root_mfa=$(echo "$summary" | jq -r '.SummaryMap.AccountMFAEnabled // 0')
    if [[ "$root_mfa" -eq 1 ]]; then
        results+=("1.1|Root account MFA|PASS|CRITICAL|Root MFA is enabled|N/A")
    else
        results+=("1.1|Root account MFA|FAIL|CRITICAL|Root account MFA is not enabled|Enable MFA on root: AWS Console > Security Credentials")
    fi

    # 1.2 Root account has no active access keys
    local root_keys
    root_keys=$(echo "$summary" | jq -r '.SummaryMap.AccountAccessKeysPresent // 0')
    if [[ "$root_keys" -eq 0 ]]; then
        results+=("1.2|Root access keys|PASS|CRITICAL|No root access keys found|N/A")
    else
        results+=("1.2|Root access keys|FAIL|CRITICAL|Root account has active access keys|Delete root access keys immediately")
    fi

    # 1.3 Password policy: minimum 14 chars
    local pw_policy
    pw_policy=$(aws_cmd iam get-account-password-policy 2>/dev/null) || {
        results+=("1.3|Password min length|FAIL|MEDIUM|No custom password policy set|aws iam update-account-password-policy --minimum-password-length 14")
        results+=("1.4|Password symbols|FAIL|MEDIUM|No custom password policy set|aws iam update-account-password-policy --require-symbols")
        _emit_results "${results[@]}"
        return 0
    }

    local min_len
    min_len=$(echo "$pw_policy" | jq -r '.PasswordPolicy.MinimumPasswordLength // 0')
    if [[ "$min_len" -ge 14 ]]; then
        results+=("1.3|Password min length|PASS|MEDIUM|Min length is ${min_len}|N/A")
    else
        results+=("1.3|Password min length|FAIL|MEDIUM|Min length is ${min_len} (requires 14)|aws iam update-account-password-policy --minimum-password-length 14")
    fi

    # 1.4 Password policy: requires symbols
    local req_symbols
    req_symbols=$(echo "$pw_policy" | jq -r '.PasswordPolicy.RequireSymbols // false')
    if [[ "$req_symbols" == "true" ]]; then
        results+=("1.4|Password symbols|PASS|MEDIUM|Symbols required|N/A")
    else
        results+=("1.4|Password symbols|FAIL|MEDIUM|Symbols not required|aws iam update-account-password-policy --require-symbols")
    fi

    # 1.5 No inline IAM policies in use
    local users
    users=$(aws_cmd iam list-users 2>/dev/null | jq -r '.Users[].UserName') || {
        results+=("1.5|No inline policies|SKIP|MEDIUM|Could not list users|N/A")
        _emit_results "${results[@]}"
        return 0
    }

    local inline_found=false
    if [[ -n "$users" ]]; then
        while IFS= read -r user; do
            local count
            count=$(aws_cmd iam list-user-policies --user-name "$user" 2>/dev/null \
                | jq '.PolicyNames | length') || continue
            if [[ "$count" -gt 0 ]]; then
                inline_found=true
                break
            fi
        done <<< "$users"
    fi

    if [[ "$inline_found" == false ]]; then
        results+=("1.5|No inline policies|PASS|MEDIUM|No inline policies found|N/A")
    else
        results+=("1.5|No inline policies|FAIL|MEDIUM|Inline policies detected|Convert to managed policies")
    fi

    # 1.6 All IAM users have MFA
    local all_mfa=true
    local no_mfa_users=""
    if [[ -n "$users" ]]; then
        while IFS= read -r user; do
            # Only check users with console access
            if aws_cmd iam get-login-profile --user-name "$user" &>/dev/null; then
                local mfa_count
                mfa_count=$(aws_cmd iam list-mfa-devices --user-name "$user" 2>/dev/null \
                    | jq '.MFADevices | length') || continue
                if [[ "$mfa_count" -eq 0 ]]; then
                    all_mfa=false
                    no_mfa_users+="${user}, "
                fi
            fi
        done <<< "$users"
    fi

    if [[ "$all_mfa" == true ]]; then
        results+=("1.6|All users have MFA|PASS|HIGH|All console users have MFA|N/A")
    else
        results+=("1.6|All users have MFA|FAIL|HIGH|Users without MFA: ${no_mfa_users%, }|Enable MFA for all console users")
    fi

    _emit_results "${results[@]}"
}

_emit_results() {
    for result in "$@"; do
        echo "$result"
    done
}
