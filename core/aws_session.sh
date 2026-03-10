#!/usr/bin/env bash
# core/aws_session.sh — AWS profile, region setup, and CLI wrapper

_AWS_ACCOUNT_ID=""

aws_init() {
    # Set profile: CLI flag > config > env > default
    export AWS_PROFILE="${STACKSENTRY_AWS_PROFILE:-${AWS_PROFILE:-default}}"
    export AWS_DEFAULT_REGION="${STACKSENTRY_AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

    log_info "aws_session" "Using profile=$AWS_PROFILE region=$AWS_DEFAULT_REGION"
    aws_validate
}

aws_validate() {
    local identity
    identity=$(aws sts get-caller-identity \
        --profile "$AWS_PROFILE" \
        --region "$AWS_DEFAULT_REGION" \
        --output json \
        --cli-connect-timeout 5 \
        --cli-read-timeout 10 2>&1) || {
        log_error "aws_session" "AWS session validation failed: $identity"
        print_fail "AWS session invalid. Check credentials and profile '$AWS_PROFILE'."
        echo ""
        echo "  Troubleshoot:"
        echo "    aws configure --profile $AWS_PROFILE"
        echo "    aws sts get-caller-identity --profile $AWS_PROFILE"
        exit 1
    }

    _AWS_ACCOUNT_ID=$(echo "$identity" | jq -r '.Account')
    local arn
    arn=$(echo "$identity" | jq -r '.Arn')

    log_info "aws_session" "Authenticated as $arn (account: $_AWS_ACCOUNT_ID)"
    print_info "AWS Account: ${_AWS_ACCOUNT_ID} | Region: ${AWS_DEFAULT_REGION} | Identity: ${arn}"
}

aws_account_id() {
    if [[ -z "$_AWS_ACCOUNT_ID" ]]; then
        _AWS_ACCOUNT_ID=$(aws sts get-caller-identity \
            --profile "${AWS_PROFILE:-default}" \
            --output json 2>/dev/null | jq -r '.Account')
    fi
    echo "$_AWS_ACCOUNT_ID"
}

# Wrapper for all AWS CLI calls — ensures consistent profile/region/output
aws_cmd() {
    log_debug "aws_session" "aws $*"
    aws --profile "$AWS_PROFILE" \
        --region "$AWS_DEFAULT_REGION" \
        --output json \
        "$@"
}
