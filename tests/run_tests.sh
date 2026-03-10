#!/usr/bin/env bash
# tests/run_tests.sh — Lightweight test harness for StackSentry
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${TESTS_DIR}/.." && pwd)"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BOLD="\033[1m"
RESET="\033[0m"

# ── Test Framework ──────────────────────────────────────────────────────────
assert_equals() {
    local expected="$1" actual="$2" message="${3:-}"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$expected" == "$actual" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}PASS${RESET}  ${message}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}FAIL${RESET}  ${message}"
        echo -e "         expected: '${expected}'"
        echo -e "         actual:   '${actual}'"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" message="${3:-}"
    TESTS_RUN=$((TESTS_RUN + 1))
    if echo "$haystack" | grep -qF "$needle"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}PASS${RESET}  ${message}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}FAIL${RESET}  ${message}"
        echo -e "         '${needle}' not found in output"
    fi
}

assert_exit_code() {
    local expected="$1" actual="$2" message="${3:-}"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$expected" -eq "$actual" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}PASS${RESET}  ${message}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}FAIL${RESET}  ${message}"
        echo -e "         expected exit code: ${expected}, got: ${actual}"
    fi
}

assert_not_empty() {
    local value="$1" message="${2:-}"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -n "$value" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}PASS${RESET}  ${message}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}FAIL${RESET}  ${message}"
        echo -e "         value was empty"
    fi
}

# ── Mock AWS CLI ────────────────────────────────────────────────────────────
# Override aws_cmd to return fixture data instead of calling real AWS
setup_mocks() {
    aws_cmd() {
        local service="$1"
        shift
        local subcommand="$1"
        shift

        case "${service} ${subcommand}" in
            "iam get-account-summary")
                echo '{"SummaryMap":{"AccountMFAEnabled":1,"AccountAccessKeysPresent":0,"Users":3,"Roles":5}}'
                ;;
            "iam list-users")
                echo '{"Users":[{"UserName":"alice","Arn":"arn:aws:iam::123456789012:user/alice","CreateDate":"2025-01-01T00:00:00Z"},{"UserName":"bob","Arn":"arn:aws:iam::123456789012:user/bob","CreateDate":"2024-06-01T00:00:00Z"}]}'
                ;;
            "iam list-mfa-devices")
                local user=""
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        --user-name) user="$2"; shift 2 ;;
                        *) shift ;;
                    esac
                done
                if [[ "$user" == "alice" ]]; then
                    echo '{"MFADevices":[{"SerialNumber":"arn:aws:iam::123456789012:mfa/alice"}]}'
                else
                    echo '{"MFADevices":[]}'
                fi
                ;;
            "iam get-login-profile")
                echo '{"LoginProfile":{"UserName":"test","CreateDate":"2025-01-01"}}'
                ;;
            "iam list-access-keys")
                echo '{"AccessKeyMetadata":[{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","Status":"Active","CreateDate":"2024-01-01T00:00:00Z"}]}'
                ;;
            "iam get-account-password-policy")
                echo '{"PasswordPolicy":{"MinimumPasswordLength":8,"RequireSymbols":false,"RequireNumbers":true,"RequireUppercaseCharacters":true,"RequireLowercaseCharacters":true,"MaxPasswordAge":0}}'
                ;;
            "iam list-attached-user-policies")
                echo '{"AttachedPolicies":[]}'
                ;;
            "iam list-user-policies")
                echo '{"PolicyNames":[]}'
                ;;
            "iam list-roles")
                echo '{"Roles":[]}'
                ;;
            "sts get-caller-identity")
                echo '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/test","UserId":"AIDAEXAMPLE"}'
                ;;
            "s3api list-buckets")
                echo '{"Buckets":[{"Name":"test-bucket","CreationDate":"2025-01-01T00:00:00Z"}]}'
                ;;
            "ec2 describe-instances")
                echo '{"Reservations":[]}'
                ;;
            "ec2 describe-security-groups")
                echo '{"SecurityGroups":[]}'
                ;;
            "ec2 describe-volumes")
                echo '{"Volumes":[]}'
                ;;
            *)
                echo '{}'
                ;;
        esac
    }

    # Mock aws for validation
    aws() {
        case "$1" in
            sts) echo '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/test"}' ;;
            --version) echo "aws-cli/2.0.0 Python/3.8.0" ;;
            *) echo '{}' ;;
        esac
    }
    export -f aws
}

# ── Source Core Libraries ───────────────────────────────────────────────────
source_core() {
    export STACKSENTRY_HOME="$PROJECT_ROOT"
    export STACKSENTRY_VERSION="0.1.0-test"
    export STACKSENTRY_AWS_PROFILE="test"
    export STACKSENTRY_AWS_REGION="us-east-1"
    export STACKSENTRY_OUTPUT_FORMAT="table"
    export STACKSENTRY_LOG_LEVEL="ERROR"
    export STACKSENTRY_LOG_DIR="logs"
    export STACKSENTRY_REPORT_DIR="reports"

    source "${PROJECT_ROOT}/core/output.sh"
    source "${PROJECT_ROOT}/core/logger.sh"
    source "${PROJECT_ROOT}/core/scoring.sh"
    source "${PROJECT_ROOT}/core/aws_session.sh"
    source "${PROJECT_ROOT}/core/report.sh"
    source "${PROJECT_ROOT}/core/alert.sh"

    log_init
    setup_mocks
}

# ── Test Suites ─────────────────────────────────────────────────────────────
run_test_suite() {
    echo ""
    echo -e "${BOLD}StackSentry Test Suite${RESET}"
    echo "========================="

    test_cli_entrypoint
    test_core_output
    test_core_scoring
    test_core_report
    test_secret_radar
    test_iam_lens

    echo ""
    echo "========================="
    echo -e "${BOLD}Results: ${TESTS_RUN} tests${RESET} — " \
        "${GREEN}${TESTS_PASSED} passed${RESET}, " \
        "${RED}${TESTS_FAILED} failed${RESET}"
    echo ""

    [[ "$TESTS_FAILED" -eq 0 ]] && return 0 || return 1
}

# ── CLI Tests ───────────────────────────────────────────────────────────────
test_cli_entrypoint() {
    echo ""
    echo -e "${YELLOW}CLI Entrypoint${RESET}"

    # --version
    local version_output
    version_output=$(bash "${PROJECT_ROOT}/bin/stacksentry" --version 2>&1)
    assert_contains "$version_output" "StackSentry v" "stacksentry --version shows version"

    # --help
    local help_output
    help_output=$(bash "${PROJECT_ROOT}/bin/stacksentry" --help 2>&1)
    assert_contains "$help_output" "Usage:" "--help shows usage"
    assert_contains "$help_output" "iam audit" "--help lists iam audit command"
    assert_contains "$help_output" "secrets scan" "--help lists secrets scan command"
    assert_contains "$help_output" "posture scan" "--help lists posture scan command"

    # Unknown command
    local unknown_output
    unknown_output=$(bash "${PROJECT_ROOT}/bin/stacksentry" bogus 2>&1) || true
    assert_contains "$unknown_output" "Unknown command" "Unknown command shows error"

    # doctor
    local doctor_output
    doctor_output=$(bash "${PROJECT_ROOT}/bin/stacksentry" doctor 2>&1) || true
    assert_contains "$doctor_output" "bash" "doctor checks bash"
    assert_contains "$doctor_output" "dependencies satisfied" "doctor shows summary"
}

# ── Output Tests ────────────────────────────────────────────────────────────
test_core_output() {
    echo ""
    echo -e "${YELLOW}Core: Output${RESET}"
    source_core

    # Banner
    local banner
    banner=$(print_banner 2>&1)
    assert_contains "$banner" "StackSentry" "print_banner contains StackSentry"

    # Status messages
    local pass_msg
    pass_msg=$(print_pass "test message" 2>&1)
    assert_contains "$pass_msg" "PASS" "print_pass shows PASS"
    assert_contains "$pass_msg" "test message" "print_pass shows message"

    local fail_msg
    fail_msg=$(print_fail "error here" 2>&1)
    assert_contains "$fail_msg" "FAIL" "print_fail shows FAIL"

    # Table output (CSV mode)
    STACKSENTRY_OUTPUT_FORMAT="csv"
    local csv_output
    csv_output=$(print_table "NAME|VALUE" "foo|bar" "baz|qux" 2>&1)
    assert_contains "$csv_output" "NAME,VALUE" "CSV output has header"
    assert_contains "$csv_output" '"foo","bar"' "CSV output has data rows"
    STACKSENTRY_OUTPUT_FORMAT="table"
}

# ── Scoring Tests ───────────────────────────────────────────────────────────
test_core_scoring() {
    echo ""
    echo -e "${YELLOW}Core: Scoring${RESET}"
    source_core

    # Init
    init_findings
    assert_equals "0" "${#FINDINGS[@]}" "init_findings resets array"
    assert_equals "0" "$COUNTER_CRITICAL" "init_findings resets CRITICAL counter"

    # Add findings
    add_finding "CRITICAL" "test" "res1" "finding1" "fix1" 2>/dev/null
    assert_equals "1" "${#FINDINGS[@]}" "add_finding adds to array"
    assert_equals "1" "$COUNTER_CRITICAL" "add_finding increments CRITICAL"

    add_finding "HIGH" "test" "res2" "finding2" "fix2" 2>/dev/null
    add_finding "MEDIUM" "test" "res3" "finding3" "fix3" 2>/dev/null
    add_finding "LOW" "test" "res4" "finding4" "fix4" 2>/dev/null
    assert_equals "4" "${#FINDINGS[@]}" "4 findings in array"
    assert_equals "1" "$COUNTER_HIGH" "HIGH counter is 1"
    assert_equals "1" "$COUNTER_MEDIUM" "MEDIUM counter is 1"
    assert_equals "1" "$COUNTER_LOW" "LOW counter is 1"

    # Severity validation
    add_finding "INVALID" "test" "res5" "bad" "" 2>/dev/null
    assert_equals "2" "$COUNTER_MEDIUM" "Invalid severity defaults to MEDIUM"

    # Score to severity
    local sev
    sev=$(score_to_severity 10)
    assert_equals "CRITICAL" "$sev" "score 10 = CRITICAL"
    sev=$(score_to_severity 7)
    assert_equals "HIGH" "$sev" "score 7 = HIGH"
    sev=$(score_to_severity 4)
    assert_equals "MEDIUM" "$sev" "score 4 = MEDIUM"
    sev=$(score_to_severity 1)
    assert_equals "LOW" "$sev" "score 1 = LOW"
}

# ── Report Tests ────────────────────────────────────────────────────────────
test_core_report() {
    echo ""
    echo -e "${YELLOW}Core: Report${RESET}"

    # Run report test in a subshell to avoid state pollution
    local csv_result
    csv_result=$(bash -c "
        source '${PROJECT_ROOT}/core/output.sh'
        source '${PROJECT_ROOT}/core/logger.sh'
        source '${PROJECT_ROOT}/core/scoring.sh'
        source '${PROJECT_ROOT}/core/report.sh'
        export STACKSENTRY_HOME='${PROJECT_ROOT}'
        export STACKSENTRY_LOG_LEVEL='ERROR'
        export STACKSENTRY_REPORT_DIR='reports'
        export STACKSENTRY_OUTPUT_FORMAT='table'
        log_init
        init_findings
        add_finding 'HIGH' 'test' 'resource1' 'test finding' 'test fix' >/dev/null 2>&1
        save_report 'test_module' 'csv' 2>/dev/null
        f=\$(ls -t '${PROJECT_ROOT}/reports'/test_module_*.csv 2>/dev/null | head -1)
        if [[ -n \"\$f\" ]]; then
            echo 'FILE_OK'
            cat \"\$f\"
            rm -f \"\$f\"
        else
            echo 'FILE_MISSING'
        fi
    " 2>/dev/null) || true

    assert_contains "$csv_result" "FILE_OK" "CSV report file created"
    assert_contains "$csv_result" "SEVERITY,MODULE" "CSV has headers"
    assert_contains "$csv_result" "HIGH" "CSV contains finding"
}

# ── Secret Radar Tests ─────────────────────────────────────────────────────
test_secret_radar() {
    echo ""
    echo -e "${YELLOW}Module: Secret Radar${RESET}"
    source_core

    # Patterns file exists
    local patterns="${PROJECT_ROOT}/modules/secret_radar/patterns.txt"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -f "$patterns" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}PASS${RESET}  patterns.txt exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}FAIL${RESET}  patterns.txt missing"
    fi

    # Count patterns (non-comment, non-empty)
    local pattern_count
    pattern_count=$(grep -v '^#' "$patterns" | grep -v '^$' | wc -l | tr -d ' ')
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$pattern_count" -ge 10 ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}PASS${RESET}  ${pattern_count} patterns loaded (>= 10)"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}FAIL${RESET}  Only ${pattern_count} patterns (expected >= 10)"
    fi

    # Test scanning project dir (should find no secrets)
    local scan_output
    scan_output=$(timeout 15 bash "${PROJECT_ROOT}/bin/stacksentry" secrets scan --path "${PROJECT_ROOT}/config" 2>&1) || true
    assert_contains "$scan_output" "Secret Radar" "Secret scan shows module header"

    # Test entropy calculator
    source "${PROJECT_ROOT}/modules/secret_radar/scan.sh"
    local entropy
    entropy=$(_shannon_entropy "aaaa")
    assert_equals "0.00" "$entropy" "Entropy of 'aaaa' is 0.00"

    entropy=$(_shannon_entropy "abcdefgh")
    TESTS_RUN=$((TESTS_RUN + 1))
    local is_high
    is_high=$(awk "BEGIN {print ($entropy > 2.0) ? 1 : 0}")
    if [[ "$is_high" -eq 1 ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}PASS${RESET}  Entropy of 'abcdefgh' = ${entropy} (> 2.0)"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}FAIL${RESET}  Entropy of 'abcdefgh' = ${entropy} (expected > 2.0)"
    fi
}

# ── IAM Lens Tests ──────────────────────────────────────────────────────────
test_iam_lens() {
    echo ""
    echo -e "${YELLOW}Module: IAM Lens${RESET}"

    if ! command -v jq &>/dev/null; then
        echo -e "  ${YELLOW}SKIP${RESET}  IAM Lens tests require jq"
        return 0
    fi

    source_core

    # Source IAM module
    source "${PROJECT_ROOT}/modules/iam_lens/audit.sh"

    # Test with mocked AWS
    init_findings
    check_root_mfa 2>/dev/null
    # Mock returns MFA enabled, so no critical finding
    assert_equals "0" "$COUNTER_CRITICAL" "Root MFA enabled = no CRITICAL finding"

    init_findings
    check_root_access_keys 2>/dev/null
    assert_equals "0" "$COUNTER_CRITICAL" "No root keys = no CRITICAL finding"

    init_findings
    check_password_policy 2>/dev/null
    # Mock returns min length 8 (< 14), so should flag
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$COUNTER_MEDIUM" -gt 0 || "$COUNTER_LOW" -gt 0 ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}PASS${RESET}  Weak password policy flagged"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}FAIL${RESET}  Weak password policy not flagged"
    fi
}

# ── Run ─────────────────────────────────────────────────────────────────────
run_test_suite
