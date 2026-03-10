#!/usr/bin/env bash
# modules/infra_snap/compare.sh — Compare live state against desired state

infra_compare() {
    local snapshot_dir="$1"
    local desired_state="$2"

    print_info "Parsing desired state configuration..."

    local current_section=""
    local line_num=0

    while IFS= read -r line; do
        line_num=$((line_num + 1))

        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        # Detect section headers (no leading whitespace, ends with colon)
        if [[ "$line" =~ ^[a-z_]+: ]]; then
            current_section=$(echo "$line" | sed 's/:.*//')
            continue
        fi

        # Process entries based on section
        case "$current_section" in
            ec2)
                _compare_ec2_entry "$line" "$snapshot_dir"
                ;;
            security_groups)
                _compare_sg_entry "$line" "$snapshot_dir"
                ;;
            s3)
                _compare_s3_entry "$line" "$snapshot_dir"
                ;;
            vpcs)
                _compare_vpc_entry "$line" "$snapshot_dir"
                ;;
        esac
    done < "$desired_state"

    # Check for EXTRA resources (in live but not in desired)
    _check_extra_resources "$snapshot_dir" "$desired_state"
}

# ── EC2 Comparison ──────────────────────────────────────────────────────────
_compare_ec2_entry() {
    local line="$1" snapshot_dir="$2"

    # Parse key-value from YAML-like line
    local key value
    key=$(echo "$line" | sed 's/^[[:space:]]*//' | cut -d: -f1 | tr -d ' -')
    value=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//')

    # Accumulate into temp vars
    case "$key" in
        id)     _EC2_ID="$value" ;;
        name)   _EC2_NAME="$value" ;;
        type)   _EC2_TYPE="$value" ;;
        state)  _EC2_STATE="$value" ;;
    esac

    # When we have an ID, compare
    if [[ "$key" == "state" && -n "${_EC2_ID:-}" ]]; then
        local live_instance
        live_instance=$(grep "$_EC2_ID" "${snapshot_dir}/ec2.json" 2>/dev/null)

        if [[ -z "$live_instance" ]]; then
            add_finding "HIGH" "infra_snap" "ec2:${_EC2_ID}" \
                "MISSING — Expected instance not found (${_EC2_NAME:-unnamed})" \
                "Investigate missing instance: aws ec2 describe-instances --instance-ids ${_EC2_ID}"
        else
            # Check state
            local live_state
            live_state=$(echo "$live_instance" | jq -r '.State.Name')
            if [[ -n "${_EC2_STATE}" && "$live_state" != "$_EC2_STATE" ]]; then
                add_finding "HIGH" "infra_snap" "ec2:${_EC2_ID}" \
                    "MODIFIED — State is '${live_state}', expected '${_EC2_STATE}'" \
                    "Fix state: aws ec2 start-instances/stop-instances --instance-ids ${_EC2_ID}"
            fi

            # Check instance type
            if [[ -n "${_EC2_TYPE:-}" ]]; then
                local live_type
                live_type=$(echo "$live_instance" | jq -r '.InstanceType')
                if [[ "$live_type" != "$_EC2_TYPE" ]]; then
                    add_finding "MEDIUM" "infra_snap" "ec2:${_EC2_ID}" \
                        "MODIFIED — Type is '${live_type}', expected '${_EC2_TYPE}'" \
                        "Resize: stop instance, modify type, restart"
                fi
            fi
        fi

        # Reset
        _EC2_ID="" _EC2_NAME="" _EC2_TYPE="" _EC2_STATE=""
    fi
}

# ── Security Group Comparison ───────────────────────────────────────────────
_compare_sg_entry() {
    local line="$1" snapshot_dir="$2"
    local key value
    key=$(echo "$line" | sed 's/^[[:space:]]*//' | cut -d: -f1 | tr -d ' -')
    value=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//')

    case "$key" in
        id)   _SG_ID="$value" ;;
        name) _SG_NAME="$value" ;;
    esac

    if [[ "$key" == "name" && -n "${_SG_ID:-}" ]]; then
        local live_sg
        live_sg=$(grep "$_SG_ID" "${snapshot_dir}/sgs.json" 2>/dev/null)

        if [[ -z "$live_sg" ]]; then
            add_finding "CRITICAL" "infra_snap" "sg:${_SG_ID}" \
                "MISSING — Expected security group not found (${_SG_NAME:-unnamed})" \
                "Recreate security group or investigate removal"
        fi

        _SG_ID="" _SG_NAME=""
    fi
}

# ── S3 Comparison ───────────────────────────────────────────────────────────
_compare_s3_entry() {
    local line="$1" snapshot_dir="$2"
    local key value
    key=$(echo "$line" | sed 's/^[[:space:]]*//' | cut -d: -f1 | tr -d ' -')
    value=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//')

    case "$key" in
        name)       _S3_NAME="$value" ;;
        encryption) _S3_ENC="$value" ;;
        versioning) _S3_VER="$value" ;;
        public_access) _S3_PUB="$value" ;;
    esac

    if [[ "$key" == "public_access" && -n "${_S3_NAME:-}" ]]; then
        local live_bucket
        live_bucket=$(grep "\"${_S3_NAME}\"" "${snapshot_dir}/s3.json" 2>/dev/null)

        if [[ -z "$live_bucket" ]]; then
            add_finding "HIGH" "infra_snap" "s3:${_S3_NAME}" \
                "MISSING — Expected S3 bucket not found" \
                "Investigate missing bucket: aws s3api head-bucket --bucket ${_S3_NAME}"
        else
            local live_enc
            live_enc=$(echo "$live_bucket" | jq -r '.encryption')
            if [[ "${_S3_ENC}" == "true" && "$live_enc" == "disabled" ]]; then
                add_finding "HIGH" "infra_snap" "s3:${_S3_NAME}" \
                    "MODIFIED — Encryption expected but disabled" \
                    "Enable encryption on bucket"
            fi
        fi

        _S3_NAME="" _S3_ENC="" _S3_VER="" _S3_PUB=""
    fi
}

# ── VPC Comparison ──────────────────────────────────────────────────────────
_compare_vpc_entry() {
    local line="$1" snapshot_dir="$2"
    local key value
    key=$(echo "$line" | sed 's/^[[:space:]]*//' | cut -d: -f1 | tr -d ' -')
    value=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//')

    case "$key" in
        id)   _VPC_ID="$value" ;;
        cidr) _VPC_CIDR="$value" ;;
        name) _VPC_NAME="$value" ;;
    esac

    if [[ "$key" == "name" && -n "${_VPC_ID:-}" ]]; then
        local live_vpc
        live_vpc=$(grep "$_VPC_ID" "${snapshot_dir}/vpcs.json" 2>/dev/null)

        if [[ -z "$live_vpc" ]]; then
            add_finding "CRITICAL" "infra_snap" "vpc:${_VPC_ID}" \
                "MISSING — Expected VPC not found (${_VPC_NAME:-unnamed})" \
                "Investigate missing VPC"
        fi

        _VPC_ID="" _VPC_CIDR="" _VPC_NAME=""
    fi
}

# ── Extra Resource Detection ───────────────────────────────────────────────
_check_extra_resources() {
    local snapshot_dir="$1" desired_state="$2"

    # Extract desired instance IDs
    local desired_ec2_ids
    desired_ec2_ids=$(grep -E '^\s+id:\s*i-' "$desired_state" 2>/dev/null | awk '{print $2}')

    if [[ -n "$desired_ec2_ids" && -f "${snapshot_dir}/ec2.json" ]]; then
        while IFS= read -r instance; do
            local instance_id
            instance_id=$(echo "$instance" | jq -r '.InstanceId')
            if ! echo "$desired_ec2_ids" | grep -qF "$instance_id"; then
                local name_tag
                name_tag=$(echo "$instance" | jq -r '(.Tags // [])[] | select(.Key=="Name") | .Value // empty')
                add_finding "MEDIUM" "infra_snap" "ec2:${instance_id}" \
                    "EXTRA — Instance not in desired state (${name_tag:-unnamed})" \
                    "Verify this instance is intentional or terminate it"
            fi
        done < "${snapshot_dir}/ec2.json"
    fi
}
