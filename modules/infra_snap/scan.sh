#!/usr/bin/env bash
# modules/infra_snap/scan.sh — Snapshot live AWS infrastructure and detect drift

INFRA_MODULE="infra_snap"

infra_snap_scan() {
    aws_init
    init_findings

    print_header "Infra Snap — Infrastructure Drift Detection"

    print_info "Scanning live infrastructure..."

    # Snapshot all resource types
    local snapshot_dir="/tmp/stacksentry_infra_$$"
    mkdir -p "$snapshot_dir"

    _snap_ec2 "$snapshot_dir"
    _snap_security_groups "$snapshot_dir"
    _snap_s3 "$snapshot_dir"
    _snap_vpcs "$snapshot_dir"
    _snap_ebs "$snapshot_dir"
    _snap_rds "$snapshot_dir"

    # Compare with desired state if available
    local desired_state="${STACKSENTRY_HOME}/config/desired_state.yaml"
    if [[ -f "$desired_state" ]] && grep -qv '^#\|^$' "$desired_state"; then
        print_info "Comparing against desired state..."
        source "${STACKSENTRY_HOME}/modules/infra_snap/compare.sh"
        infra_compare "$snapshot_dir" "$desired_state"
    else
        print_info "No desired state configured — running inventory-only scan"
        _report_inventory "$snapshot_dir"
    fi

    # Cleanup
    rm -rf "$snapshot_dir"

    echo ""
    summarize_findings || true
    post_scan_actions "$INFRA_MODULE"
}

# ── EC2 Snapshot ────────────────────────────────────────────────────────────
_snap_ec2() {
    local dir="$1"
    local instances
    instances=$(aws_cmd ec2 describe-instances \
        --filters "Name=instance-state-name,Values=running,stopped,stopping" 2>/dev/null) || {
        log_warn "$INFRA_MODULE" "Failed to describe EC2 instances"
        return 0
    }

    echo "$instances" | jq -c '.Reservations[].Instances[]' > "${dir}/ec2.json" 2>/dev/null

    local count
    count=$(wc -l < "${dir}/ec2.json" | tr -d ' ')
    print_info "EC2: ${count} instances found"

    # Flag instances without Name tags
    while IFS= read -r instance; do
        local instance_id state instance_type name_tag
        instance_id=$(echo "$instance" | jq -r '.InstanceId')
        state=$(echo "$instance" | jq -r '.State.Name')
        instance_type=$(echo "$instance" | jq -r '.InstanceType')
        name_tag=$(echo "$instance" | jq -r '(.Tags // [])[] | select(.Key=="Name") | .Value // empty')

        if [[ -z "$name_tag" ]]; then
            add_finding "LOW" "$INFRA_MODULE" "ec2:${instance_id}" \
                "EC2 instance has no Name tag (type: ${instance_type}, state: ${state})" \
                "Add Name tag: aws ec2 create-tags --resources ${instance_id} --tags Key=Name,Value=NAME"
        fi

        # Flag stopped instances
        if [[ "$state" == "stopped" ]]; then
            add_finding "MEDIUM" "$INFRA_MODULE" "ec2:${instance_id}" \
                "EC2 instance is stopped (${name_tag:-unnamed}, type: ${instance_type})" \
                "Terminate if unused: aws ec2 terminate-instances --instance-ids ${instance_id}"
        fi
    done < "${dir}/ec2.json"
}

# ── Security Groups Snapshot ────────────────────────────────────────────────
_snap_security_groups() {
    local dir="$1"
    local sgs
    sgs=$(aws_cmd ec2 describe-security-groups 2>/dev/null) || {
        log_warn "$INFRA_MODULE" "Failed to describe security groups"
        return 0
    }

    echo "$sgs" | jq -c '.SecurityGroups[]' > "${dir}/sgs.json" 2>/dev/null

    local count
    count=$(wc -l < "${dir}/sgs.json" | tr -d ' ')
    print_info "Security Groups: ${count} found"

    # Flag overly permissive rules
    while IFS= read -r sg; do
        local sg_id sg_name
        sg_id=$(echo "$sg" | jq -r '.GroupId')
        sg_name=$(echo "$sg" | jq -r '.GroupName')

        # Check for 0.0.0.0/0 ingress on sensitive ports
        local open_ports
        open_ports=$(echo "$sg" | jq -r '
            [.IpPermissions[] |
             select(.IpRanges[]?.CidrIp == "0.0.0.0/0") |
             if .FromPort == .ToPort then "\(.FromPort)"
             elif .IpProtocol == "-1" then "ALL"
             else "\(.FromPort)-\(.ToPort)" end] | unique[]' 2>/dev/null)

        if [[ -n "$open_ports" ]]; then
            while IFS= read -r port; do
                [[ -z "$port" ]] && continue
                local severity="HIGH"
                case "$port" in
                    22|3389|ALL) severity="CRITICAL" ;;
                    3306|5432|1433|27017|6379) severity="CRITICAL" ;;
                esac
                add_finding "$severity" "$INFRA_MODULE" "sg:${sg_id}(${sg_name})" \
                    "Port ${port} open to 0.0.0.0/0" \
                    "Restrict ingress: aws ec2 revoke-security-group-ingress --group-id ${sg_id}"
            done <<< "$open_ports"
        fi
    done < "${dir}/sgs.json"
}

# ── S3 Snapshot ─────────────────────────────────────────────────────────────
_snap_s3() {
    local dir="$1"
    local buckets
    buckets=$(aws_cmd s3api list-buckets 2>/dev/null | jq -r '.Buckets[].Name') || {
        log_warn "$INFRA_MODULE" "Failed to list S3 buckets"
        return 0
    }

    local count=0
    echo -n "" > "${dir}/s3.json"

    while IFS= read -r bucket; do
        [[ -z "$bucket" ]] && continue
        count=$((count + 1))

        local encryption="unknown" versioning="unknown" public_access="unknown"

        # Check encryption
        if aws_cmd s3api get-bucket-encryption --bucket "$bucket" &>/dev/null; then
            encryption="enabled"
        else
            encryption="disabled"
            add_finding "HIGH" "$INFRA_MODULE" "s3:${bucket}" \
                "Bucket has no server-side encryption" \
                "Enable encryption: aws s3api put-bucket-encryption --bucket ${bucket} --server-side-encryption-configuration ..."
        fi

        # Check public access block
        local pab
        pab=$(aws_cmd s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
        if [[ -n "$pab" ]]; then
            local all_blocked
            all_blocked=$(echo "$pab" | jq '.PublicAccessBlockConfiguration | .BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets')
            if [[ "$all_blocked" != "true" ]]; then
                public_access="partially_open"
                add_finding "CRITICAL" "$INFRA_MODULE" "s3:${bucket}" \
                    "Bucket does not fully block public access" \
                    "Block public access: aws s3api put-public-access-block --bucket ${bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            else
                public_access="blocked"
            fi
        else
            public_access="no_config"
            add_finding "CRITICAL" "$INFRA_MODULE" "s3:${bucket}" \
                "Bucket has no public access block configuration" \
                "Enable public access block for this bucket"
        fi

        echo "{\"name\":\"${bucket}\",\"encryption\":\"${encryption}\",\"public_access\":\"${public_access}\"}" >> "${dir}/s3.json"
    done <<< "$buckets"

    print_info "S3: ${count} buckets found"
}

# ── VPC Snapshot ────────────────────────────────────────────────────────────
_snap_vpcs() {
    local dir="$1"
    local vpcs
    vpcs=$(aws_cmd ec2 describe-vpcs 2>/dev/null) || {
        log_warn "$INFRA_MODULE" "Failed to describe VPCs"
        return 0
    }

    echo "$vpcs" | jq -c '.Vpcs[]' > "${dir}/vpcs.json" 2>/dev/null

    local count
    count=$(wc -l < "${dir}/vpcs.json" | tr -d ' ')
    print_info "VPCs: ${count} found"

    # Flag default VPC usage
    while IFS= read -r vpc; do
        local vpc_id is_default
        vpc_id=$(echo "$vpc" | jq -r '.VpcId')
        is_default=$(echo "$vpc" | jq -r '.IsDefault')

        if [[ "$is_default" == "true" ]]; then
            add_finding "MEDIUM" "$INFRA_MODULE" "vpc:${vpc_id}" \
                "Default VPC is present (consider removing)" \
                "Migrate resources and delete default VPC"
        fi
    done < "${dir}/vpcs.json"
}

# ── EBS Snapshot ────────────────────────────────────────────────────────────
_snap_ebs() {
    local dir="$1"
    local volumes
    volumes=$(aws_cmd ec2 describe-volumes 2>/dev/null) || {
        log_warn "$INFRA_MODULE" "Failed to describe EBS volumes"
        return 0
    }

    echo "$volumes" | jq -c '.Volumes[]' > "${dir}/ebs.json" 2>/dev/null

    local count
    count=$(wc -l < "${dir}/ebs.json" | tr -d ' ')
    print_info "EBS: ${count} volumes found"

    while IFS= read -r vol; do
        local vol_id state encrypted
        vol_id=$(echo "$vol" | jq -r '.VolumeId')
        state=$(echo "$vol" | jq -r '.State')
        encrypted=$(echo "$vol" | jq -r '.Encrypted')

        if [[ "$state" == "available" ]]; then
            add_finding "MEDIUM" "$INFRA_MODULE" "ebs:${vol_id}" \
                "Unattached EBS volume (wasting cost)" \
                "Delete if unused: aws ec2 delete-volume --volume-id ${vol_id}"
        fi

        if [[ "$encrypted" != "true" ]]; then
            add_finding "HIGH" "$INFRA_MODULE" "ebs:${vol_id}" \
                "EBS volume is not encrypted" \
                "Create encrypted snapshot and restore: cannot encrypt existing volume in-place"
        fi
    done < "${dir}/ebs.json"
}

# ── RDS Snapshot ────────────────────────────────────────────────────────────
_snap_rds() {
    local dir="$1"
    local instances
    instances=$(aws_cmd rds describe-db-instances 2>/dev/null) || {
        log_warn "$INFRA_MODULE" "Failed to describe RDS instances"
        return 0
    }

    echo "$instances" | jq -c '.DBInstances[]' > "${dir}/rds.json" 2>/dev/null

    local count
    count=$(wc -l < "${dir}/rds.json" | tr -d ' ')
    print_info "RDS: ${count} instances found"

    while IFS= read -r db; do
        [[ -z "$db" ]] && continue
        local db_id publicly_accessible encrypted multi_az
        db_id=$(echo "$db" | jq -r '.DBInstanceIdentifier')
        publicly_accessible=$(echo "$db" | jq -r '.PubliclyAccessible')
        encrypted=$(echo "$db" | jq -r '.StorageEncrypted')
        multi_az=$(echo "$db" | jq -r '.MultiAZ')

        if [[ "$publicly_accessible" == "true" ]]; then
            add_finding "CRITICAL" "$INFRA_MODULE" "rds:${db_id}" \
                "RDS instance is publicly accessible" \
                "Disable public access: aws rds modify-db-instance --db-instance-identifier ${db_id} --no-publicly-accessible"
        fi

        if [[ "$encrypted" != "true" ]]; then
            add_finding "HIGH" "$INFRA_MODULE" "rds:${db_id}" \
                "RDS storage is not encrypted" \
                "Enable encryption (requires snapshot restore)"
        fi
    done < "${dir}/rds.json"
}

# ── Inventory Report (when no desired state) ───────────────────────────────
_report_inventory() {
    local dir="$1"
    echo ""
    print_header "Infrastructure Inventory"

    local header="RESOURCE_TYPE|COUNT|DETAILS"
    local rows=()

    for resource_file in ec2 sgs s3 vpcs ebs rds; do
        local file="${dir}/${resource_file}.json"
        if [[ -f "$file" ]]; then
            local count
            count=$(wc -l < "$file" | tr -d ' ')
            rows+=("${resource_file}|${count}|See findings above for issues")
        fi
    done

    print_table "$header" "${rows[@]}"
}
