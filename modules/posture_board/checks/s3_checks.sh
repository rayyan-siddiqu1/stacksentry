#!/usr/bin/env bash
# modules/posture_board/checks/s3_checks.sh — CIS S3 benchmark checks

run_s3_checks() {
    local results=()
    local buckets
    buckets=$(aws_cmd s3api list-buckets 2>/dev/null | jq -r '.Buckets[].Name') || {
        results+=("2.1|S3 public ACL|SKIP|CRITICAL|Could not list buckets|N/A")
        _emit_s3_results "${results[@]}"
        return 0
    }

    [[ -z "$buckets" ]] && {
        results+=("2.1|S3 public ACL|PASS|CRITICAL|No S3 buckets found|N/A")
        results+=("2.2|S3 public policy|PASS|CRITICAL|No S3 buckets found|N/A")
        results+=("2.3|S3 encryption|PASS|HIGH|No S3 buckets found|N/A")
        results+=("2.4|S3 versioning|PASS|MEDIUM|No S3 buckets found|N/A")
        results+=("2.5|S3 access logging|PASS|MEDIUM|No S3 buckets found|N/A")
        _emit_s3_results "${results[@]}"
        return 0
    }

    local public_acl_fail=0 public_policy_fail=0 no_encryption=0 no_versioning=0 no_logging=0
    local bucket_count=0
    local fail_details_acl="" fail_details_policy="" fail_details_enc="" fail_details_ver="" fail_details_log=""

    while IFS= read -r bucket; do
        [[ -z "$bucket" ]] && continue
        bucket_count=$((bucket_count + 1))

        # 2.1 Public access block
        local pab
        pab=$(aws_cmd s3api get-public-access-block --bucket "$bucket" 2>/dev/null) || {
            public_acl_fail=$((public_acl_fail + 1))
            fail_details_acl+="${bucket}, "
            continue
        }

        local block_public_acls block_public_policy
        block_public_acls=$(echo "$pab" | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls // false')
        block_public_policy=$(echo "$pab" | jq -r '.PublicAccessBlockConfiguration.BlockPublicPolicy // false')
        local ignore_public restrict_public
        ignore_public=$(echo "$pab" | jq -r '.PublicAccessBlockConfiguration.IgnorePublicAcls // false')
        restrict_public=$(echo "$pab" | jq -r '.PublicAccessBlockConfiguration.RestrictPublicBuckets // false')

        if [[ "$block_public_acls" != "true" || "$ignore_public" != "true" ]]; then
            public_acl_fail=$((public_acl_fail + 1))
            fail_details_acl+="${bucket}, "
        fi

        # 2.2 Public bucket policy
        if [[ "$block_public_policy" != "true" || "$restrict_public" != "true" ]]; then
            public_policy_fail=$((public_policy_fail + 1))
            fail_details_policy+="${bucket}, "
        fi

        # 2.3 Server-side encryption
        local encryption
        encryption=$(aws_cmd s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null) || {
            no_encryption=$((no_encryption + 1))
            fail_details_enc+="${bucket}, "
            # Continue to check versioning and logging even if encryption check fails
        }

        if [[ -z "$encryption" ]] || ! echo "$encryption" | jq -e '.ServerSideEncryptionConfiguration' &>/dev/null; then
            no_encryption=$((no_encryption + 1))
            fail_details_enc+="${bucket}, "
        fi

        # 2.4 Versioning
        local versioning
        versioning=$(aws_cmd s3api get-bucket-versioning --bucket "$bucket" 2>/dev/null)
        local ver_status
        ver_status=$(echo "$versioning" | jq -r '.Status // "Disabled"')
        if [[ "$ver_status" != "Enabled" ]]; then
            no_versioning=$((no_versioning + 1))
            fail_details_ver+="${bucket}, "
        fi

        # 2.5 Access logging
        local logging
        logging=$(aws_cmd s3api get-bucket-logging --bucket "$bucket" 2>/dev/null)
        local log_enabled
        log_enabled=$(echo "$logging" | jq -e '.LoggingEnabled' 2>/dev/null)
        if [[ -z "$log_enabled" ]]; then
            no_logging=$((no_logging + 1))
            fail_details_log+="${bucket}, "
        fi
    done <<< "$buckets"

    # Emit results
    if [[ "$public_acl_fail" -eq 0 ]]; then
        results+=("2.1|S3 public ACL|PASS|CRITICAL|All ${bucket_count} buckets block public ACLs|N/A")
    else
        results+=("2.1|S3 public ACL|FAIL|CRITICAL|${public_acl_fail} bucket(s) allow public ACLs: ${fail_details_acl%, }|aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
    fi

    if [[ "$public_policy_fail" -eq 0 ]]; then
        results+=("2.2|S3 public policy|PASS|CRITICAL|All ${bucket_count} buckets block public policies|N/A")
    else
        results+=("2.2|S3 public policy|FAIL|CRITICAL|${public_policy_fail} bucket(s) allow public policy: ${fail_details_policy%, }|Enable BlockPublicPolicy and RestrictPublicBuckets")
    fi

    if [[ "$no_encryption" -eq 0 ]]; then
        results+=("2.3|S3 encryption|PASS|HIGH|All ${bucket_count} buckets have encryption|N/A")
    else
        results+=("2.3|S3 encryption|FAIL|HIGH|${no_encryption} bucket(s) lack encryption: ${fail_details_enc%, }|aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration ...")
    fi

    if [[ "$no_versioning" -eq 0 ]]; then
        results+=("2.4|S3 versioning|PASS|MEDIUM|All ${bucket_count} buckets have versioning|N/A")
    else
        results+=("2.4|S3 versioning|FAIL|MEDIUM|${no_versioning} bucket(s) lack versioning: ${fail_details_ver%, }|aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled")
    fi

    if [[ "$no_logging" -eq 0 ]]; then
        results+=("2.5|S3 access logging|PASS|MEDIUM|All ${bucket_count} buckets have logging|N/A")
    else
        results+=("2.5|S3 access logging|FAIL|MEDIUM|${no_logging} bucket(s) lack logging: ${fail_details_log%, }|Enable S3 access logging for audit trail")
    fi

    _emit_s3_results "${results[@]}"
}

_emit_s3_results() {
    for result in "$@"; do
        echo "$result"
    done
}
