#!/usr/bin/env bash
# modules/posture_board/checks/network_checks.sh — CIS network benchmark checks

run_network_checks() {
    local results=()

    # Get all security groups
    local sgs
    sgs=$(aws_cmd ec2 describe-security-groups 2>/dev/null) || {
        results+=("4.1|SSH open to world|SKIP|CRITICAL|Could not list security groups|N/A")
        _emit_network_results "${results[@]}"
        return 0
    }

    # 4.1 No security groups allow 0.0.0.0/0 on port 22
    local ssh_open
    ssh_open=$(echo "$sgs" | jq -r '
        [.SecurityGroups[] |
         select(.IpPermissions[]? |
            select((.FromPort // -1) <= 22 and (.ToPort // -1) >= 22) |
            select(.IpRanges[]?.CidrIp == "0.0.0.0/0" or .Ipv6Ranges[]?.CidrIpv6 == "::/0")
         ) | .GroupId + " (" + .GroupName + ")"] | unique[]')

    if [[ -z "$ssh_open" ]]; then
        results+=("4.1|SSH open to world|PASS|CRITICAL|No security groups allow SSH from 0.0.0.0/0|N/A")
    else
        local sg_list=""
        while IFS= read -r sg; do
            [[ -n "$sg" ]] && sg_list+="${sg}, "
        done <<< "$ssh_open"
        results+=("4.1|SSH open to world|FAIL|CRITICAL|SSH (port 22) open to world: ${sg_list%, }|Restrict SSH to specific IPs: aws ec2 revoke-security-group-ingress")
    fi

    # 4.2 No security groups allow 0.0.0.0/0 on port 3389
    local rdp_open
    rdp_open=$(echo "$sgs" | jq -r '
        [.SecurityGroups[] |
         select(.IpPermissions[]? |
            select((.FromPort // -1) <= 3389 and (.ToPort // -1) >= 3389) |
            select(.IpRanges[]?.CidrIp == "0.0.0.0/0" or .Ipv6Ranges[]?.CidrIpv6 == "::/0")
         ) | .GroupId + " (" + .GroupName + ")"] | unique[]')

    if [[ -z "$rdp_open" ]]; then
        results+=("4.2|RDP open to world|PASS|CRITICAL|No security groups allow RDP from 0.0.0.0/0|N/A")
    else
        local sg_list=""
        while IFS= read -r sg; do
            [[ -n "$sg" ]] && sg_list+="${sg}, "
        done <<< "$rdp_open"
        results+=("4.2|RDP open to world|FAIL|CRITICAL|RDP (port 3389) open to world: ${sg_list%, }|Restrict RDP to specific IPs or use VPN")
    fi

    # 4.3 Default VPC has no internet gateway attached
    local default_vpc
    default_vpc=$(aws_cmd ec2 describe-vpcs --filters "Name=is-default,Values=true" 2>/dev/null \
        | jq -r '.Vpcs[0].VpcId // empty')

    if [[ -z "$default_vpc" ]]; then
        results+=("4.3|Default VPC IGW|PASS|MEDIUM|No default VPC found|N/A")
    else
        local igws
        igws=$(aws_cmd ec2 describe-internet-gateways \
            --filters "Name=attachment.vpc-id,Values=${default_vpc}" 2>/dev/null \
            | jq '.InternetGateways | length')

        if [[ "${igws:-0}" -eq 0 ]]; then
            results+=("4.3|Default VPC IGW|PASS|MEDIUM|Default VPC has no internet gateway|N/A")
        else
            results+=("4.3|Default VPC IGW|FAIL|MEDIUM|Default VPC (${default_vpc}) has an internet gateway|Detach or delete the IGW from default VPC")
        fi
    fi

    # 4.4 No EC2 instances in default VPC
    if [[ -n "$default_vpc" ]]; then
        local instances_in_default
        instances_in_default=$(aws_cmd ec2 describe-instances \
            --filters "Name=vpc-id,Values=${default_vpc}" "Name=instance-state-name,Values=running,stopped" \
            2>/dev/null | jq '.Reservations[].Instances | length' | awk '{s+=$1} END {print s+0}')

        if [[ "${instances_in_default:-0}" -eq 0 ]]; then
            results+=("4.4|EC2 in default VPC|PASS|MEDIUM|No EC2 instances in default VPC|N/A")
        else
            results+=("4.4|EC2 in default VPC|FAIL|MEDIUM|${instances_in_default} instance(s) running in default VPC|Migrate instances to a custom VPC with proper network segmentation")
        fi
    else
        results+=("4.4|EC2 in default VPC|PASS|MEDIUM|No default VPC exists|N/A")
    fi

    _emit_network_results "${results[@]}"
}

_emit_network_results() {
    for result in "$@"; do
        echo "$result"
    done
}
