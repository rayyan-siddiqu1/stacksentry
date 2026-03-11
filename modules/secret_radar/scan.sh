#!/usr/bin/env bash
# modules/secret_radar/scan.sh — Scan files and repos for exposed secrets

SECRET_RADAR_MODULE="secret_radar"
SCAN_FILE_TYPES="*.env,*.conf,*.yaml,*.yml,*.json,*.sh,*.py,*.js,*.ts,*.tf,*.rb,*.php,*.java,*.go,*.cfg,*.ini,*.properties,*.toml"
SCAN_EXCLUDE_DIRS=".git,node_modules,vendor,__pycache__,.venv,venv,.terraform,dist,build"
MAX_FILE_SIZE_KB=1024

secret_radar_scan() {
    init_findings

    local scan_path=""
    local scan_repo=""
    local scan_git_history=false
    local scan_entropy=true
    local tmp_clone_dir=""

    # Parse module-specific flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --path)   scan_path="$2"; shift 2 ;;
            --repo)   scan_repo="$2"; shift 2 ;;
            --git-history) scan_git_history=true; shift ;;
            --no-entropy)  scan_entropy=false; shift ;;
            *)        shift ;;
        esac
    done

    # Validate input
    if [[ -z "$scan_path" && -z "$scan_repo" ]]; then
        print_fail "Usage: stacksentry secrets scan --path <dir> or --repo <url>"
        exit 1
    fi

    # Clone repo if needed
    if [[ -n "$scan_repo" ]]; then
        tmp_clone_dir="/tmp/stacksentry_scan_$(date +%s)"
        print_info "Cloning repository: ${scan_repo}"
        git clone --depth 1 "$scan_repo" "$tmp_clone_dir" 2>/dev/null || {
            print_fail "Failed to clone repository: ${scan_repo}"
            exit 1
        }
        scan_path="$tmp_clone_dir"
        scan_git_history=true
        log_info "$SECRET_RADAR_MODULE" "Cloned to $tmp_clone_dir"
    fi

    if [[ ! -d "$scan_path" ]]; then
        print_fail "Directory not found: ${scan_path}"
        exit 1
    fi

    print_header "Secret Radar — Scanning for Exposed Secrets"
    print_info "Target: ${scan_path}"

    # Load patterns
    local patterns_file="${STACKSENTRY_HOME}/modules/secret_radar/patterns.txt"
    if [[ ! -f "$patterns_file" ]]; then
        print_fail "Patterns file not found: ${patterns_file}"
        exit 1
    fi

    # Build grep-compatible patterns file (strip comments and blanks)
    local active_patterns
    active_patterns=$(grep -v '^#' "$patterns_file" | grep -v '^$')

    local patterns_tmp="/tmp/stacksentry_patterns_$$"
    echo "$active_patterns" > "$patterns_tmp"
    local pattern_count
    pattern_count=$(echo "$active_patterns" | wc -l | tr -d ' ')
    print_info "Loaded ${pattern_count} detection patterns"

    # Scan filesystem
    print_info "Scanning files..."
    _scan_files "$scan_path" "$patterns_tmp"

    # Loose .env file scan
    print_info "Scanning for loose .env files..."
    _scan_env_files "$scan_path"

    # Entropy scan
    if [[ "$scan_entropy" == true ]]; then
        print_info "Running entropy analysis..."
        _scan_entropy "$scan_path"
    fi

    # Git history scan
    if [[ "$scan_git_history" == true ]] && [[ -d "${scan_path}/.git" ]]; then
        print_info "Scanning git history..."
        _scan_git_history "$scan_path" "$patterns_tmp"
    fi

    # Cleanup
    rm -f "$patterns_tmp"
    if [[ -n "$tmp_clone_dir" && -d "$tmp_clone_dir" ]]; then
        rm -rf "$tmp_clone_dir"
        log_info "$SECRET_RADAR_MODULE" "Cleaned up temp clone dir"
    fi

    echo ""
    summarize_findings || true
    post_scan_actions "$SECRET_RADAR_MODULE"
}

# ── File Scanner ────────────────────────────────────────────────────────────
_scan_files() {
    local target="$1" patterns_file="$2"
    local allowlist="${STACKSENTRY_HOME}/config/allowlist.txt"

    # Build include pattern for grep
    local include_args=""
    IFS=',' read -ra types <<< "$SCAN_FILE_TYPES"
    for t in "${types[@]}"; do
        include_args+="--include=${t} "
    done

    # Build exclude dirs
    local exclude_args=""
    IFS=',' read -ra excludes <<< "$SCAN_EXCLUDE_DIRS"
    for d in "${excludes[@]}"; do
        exclude_args+="--exclude-dir=${d} "
    done

    # Run grep with patterns
    local matches
    matches=$(eval grep -rn $include_args $exclude_args -f "$patterns_file" "$target" 2>/dev/null) || true

    [[ -z "$matches" ]] && { print_pass "No secrets found in file scan"; return 0; }

    while IFS= read -r match; do
        local filepath line_num content
        filepath=$(echo "$match" | cut -d':' -f1)
        line_num=$(echo "$match" | cut -d':' -f2)
        content=$(echo "$match" | cut -d':' -f3-)

        # Skip files larger than threshold
        local file_size_kb
        file_size_kb=$(du -k "$filepath" 2>/dev/null | cut -f1)
        [[ "${file_size_kb:-0}" -gt "$MAX_FILE_SIZE_KB" ]] && continue

        # Determine pattern type and severity
        local pattern_type severity
        _classify_finding "$content" pattern_type severity

        # Mask the secret value
        local masked
        masked=$(_mask_secret "$content")

        # Truncate to 80 chars for display
        [[ ${#masked} -gt 80 ]] && masked="${masked:0:77}..."

        add_finding "$severity" "$SECRET_RADAR_MODULE" "${filepath}:${line_num}" \
            "${pattern_type}: ${masked}" \
            "Remove or rotate the exposed secret and add to .gitignore"
    done <<< "$matches"
}

# ── Loose .env File Scanner ─────────────────────────────────────────────────
_scan_env_files() {
    local target="$1"

    # Find all .env files (including .env.local, .env.production, etc.)
    local env_files
    env_files=$(find "$target" -type f -name ".env*" \
        ! -path "*/.git/*" ! -path "*/node_modules/*" ! -path "*/vendor/*" \
        ! -path "*/__pycache__/*" ! -path "*/.venv/*" ! -path "*/venv/*" \
        ! -name ".env.example" ! -name ".env.sample" ! -name ".env.template" \
        2>/dev/null) || true

    [[ -z "$env_files" ]] && { print_pass "No loose .env files found"; return 0; }

    while IFS= read -r envfile; do
        local basename
        basename=$(basename "$envfile")
        local relpath="${envfile#"$target"/}"

        # Check if .env is in .gitignore
        local in_gitignore=false
        if [[ -d "${target}/.git" ]]; then
            (cd "$target" && git check-ignore -q "$envfile" 2>/dev/null) && in_gitignore=true
        fi

        # Flag the file itself as a finding
        if [[ "$in_gitignore" == false ]]; then
            add_finding "HIGH" "$SECRET_RADAR_MODULE" "$relpath" \
                "Loose .env file not in .gitignore: ${basename}" \
                "Add ${basename} to .gitignore and remove from version control"
        fi

        # Scan contents for sensitive variables
        local sensitive_lines
        sensitive_lines=$(grep -nE \
            '^\s*(PASSWORD|SECRET|TOKEN|API_KEY|API_SECRET|ACCESS_KEY|PRIVATE_KEY|DB_PASSWORD|DATABASE_PASSWORD|DATABASE_URL|DB_URI|DB_URL|CREDENTIAL|AUTH_TOKEN|MONGO_PASSWORD|REDIS_PASSWORD|PG_PASSWORD|MYSQL_PASSWORD)\s*=' \
            "$envfile" 2>/dev/null) || true

        if [[ -n "$sensitive_lines" ]]; then
            while IFS= read -r line; do
                local line_num content varname
                line_num=$(echo "$line" | cut -d':' -f1)
                content=$(echo "$line" | cut -d':' -f2-)
                varname=$(echo "$content" | cut -d'=' -f1 | tr -d ' ')

                local masked
                masked=$(_mask_secret "$content")
                [[ ${#masked} -gt 80 ]] && masked="${masked:0:77}..."

                local sev="HIGH"
                # DB creds and private keys in .env are critical
                [[ "$varname" =~ (DB_PASSWORD|DATABASE_PASSWORD|DATABASE_URL|DB_URI|PRIVATE_KEY|MONGO_PASSWORD|REDIS_PASSWORD|PG_PASSWORD|MYSQL_PASSWORD) ]] && sev="CRITICAL"

                add_finding "$sev" "$SECRET_RADAR_MODULE" "${relpath}:${line_num}" \
                    "Sensitive var in .env: ${masked}" \
                    "Move to a secrets manager (AWS SSM, Vault, etc.) and remove from file"
            done <<< "$sensitive_lines"
        fi
    done <<< "$env_files"
}

# ── Git History Scanner ─────────────────────────────────────────────────────
_scan_git_history() {
    local target="$1" patterns_file="$2"

    # Only scan last 100 commits to avoid timeout
    local matches
    matches=$(cd "$target" && git log --all -p -100 --diff-filter=A 2>/dev/null \
        | grep -n -f "$patterns_file" 2>/dev/null | head -50) || true

    [[ -z "$matches" ]] && { print_pass "No secrets found in git history"; return 0; }

    local history_count=0
    while IFS= read -r match; do
        local content
        content=$(echo "$match" | cut -d':' -f2-)

        local pattern_type severity
        _classify_finding "$content" pattern_type severity

        local masked
        masked=$(_mask_secret "$content")
        [[ ${#masked} -gt 80 ]] && masked="${masked:0:77}..."

        add_finding "$severity" "$SECRET_RADAR_MODULE" "git-history" \
            "[HISTORY] ${pattern_type}: ${masked}" \
            "Rotate the secret and consider using git-filter-branch or BFG to purge history"

        history_count=$((history_count + 1))
        [[ $history_count -ge 20 ]] && break
    done <<< "$matches"
}

# ── Entropy Scanner ─────────────────────────────────────────────────────────
_scan_entropy() {
    local target="$1"
    local threshold="4.5"

    # Find key=value assignments and check entropy of value
    local kv_matches
    kv_matches=$(grep -rn --include="*.env" --include="*.conf" --include="*.yaml" \
        --include="*.yml" --include="*.properties" --include="*.cfg" --include="*.toml" \
        --exclude-dir=".git" --exclude-dir="node_modules" --exclude-dir="vendor" \
        -E '(password|secret|token|key|api_key|apikey|access_key|auth|db_pass|db_password|database_password|mysql_password|pg_password|pgpassword|mongo_password|redis_password|dsn|database_url|db_uri)\s*[=:]\s*\S+' \
        "$target" 2>/dev/null) || true

    [[ -z "$kv_matches" ]] && return 0

    while IFS= read -r match; do
        local filepath line_num content
        filepath=$(echo "$match" | cut -d':' -f1)
        line_num=$(echo "$match" | cut -d':' -f2)
        content=$(echo "$match" | cut -d':' -f3-)

        # Extract the value part
        local value
        value=$(echo "$content" | sed -E "s/.*[=:]\s*[\"']?([^\"' ]+).*/\1/")

        # Skip short values and obvious placeholders
        [[ ${#value} -lt 8 ]] && continue
        [[ "$value" =~ ^(changeme|placeholder|example|your_|TODO|FIXME|xxx) ]] && continue

        # Calculate Shannon entropy
        local entropy
        entropy=$(_shannon_entropy "$value")

        # Compare with threshold using awk (no bc needed)
        local is_high
        is_high=$(awk "BEGIN {print ($entropy > $threshold) ? 1 : 0}")

        if [[ "$is_high" -eq 1 ]]; then
            local masked
            masked=$(_mask_secret "$content")
            [[ ${#masked} -gt 80 ]] && masked="${masked:0:77}..."

            add_finding "MEDIUM" "$SECRET_RADAR_MODULE" "${filepath}:${line_num}" \
                "High entropy (${entropy}): ${masked}" \
                "Verify this is not a real secret; move to env var or vault"
        fi
    done <<< "$kv_matches"
}

# ── Shannon Entropy Calculator (pure awk) ──────────────────────────────────
_shannon_entropy() {
    local input="$1"
    echo "$input" | awk '{
        n = length($0)
        if (n == 0) { print 0; exit }
        delete count
        for (i = 1; i <= n; i++) {
            c = substr($0, i, 1)
            count[c]++
        }
        entropy = 0
        for (c in count) {
            p = count[c] / n
            if (p > 0) entropy -= p * (log(p) / log(2))
        }
        printf "%.2f", entropy
    }'
}

# ── Classify Finding ────────────────────────────────────────────────────────
_classify_finding() {
    local content="$1"
    local -n _type=$2
    local -n _sev=$3

    if [[ "$content" =~ AKIA[0-9A-Z]{16} ]]; then
        _type="AWS Access Key"; _sev="CRITICAL"
    elif [[ "$content" =~ AIza[0-9A-Za-z_-]{35} ]]; then
        _type="GCP API Key"; _sev="CRITICAL"
    elif [[ "$content" =~ mysql://[^:]+:[^@]+@ ]] || [[ "$content" =~ postgres(ql)?://[^:]+:[^@]+@ ]] || \
         [[ "$content" =~ mongodb(\+srv)?://[^:]+:[^@]+@ ]]; then
        _type="Database Connection String"; _sev="CRITICAL"
    elif [[ "$content" =~ (DB|DATABASE)_PASSWORD[[:space:]]*[=:] ]]; then
        _type="Database Password"; _sev="CRITICAL"
    elif [[ "$content" =~ (DB_URI|DATABASE_URL|DB_URL|DATABASE_URI)[[:space:]]*[=:].*://[^:]+:[^@]+@ ]]; then
        _type="Database URI with Credentials"; _sev="CRITICAL"
    elif [[ "$content" =~ redis://:[^@]+@ ]]; then
        _type="Redis Connection String"; _sev="HIGH"
    elif [[ "$content" =~ jdbc:[a-z]+://.*password= ]]; then
        _type="JDBC Connection String"; _sev="HIGH"
    elif [[ "$content" =~ (db_pass|dbpassword|db_password|mysql_password|pg_password|pgpassword|mongo_password|redis_password)[[:space:]]*[=:] ]]; then
        _type="Hardcoded DB Password"; _sev="HIGH"
    elif [[ "$content" =~ Server=.*Password= ]]; then
        _type="MSSQL Connection String"; _sev="CRITICAL"
    elif [[ "$content" =~ sk_live_ ]]; then
        _type="Stripe Live Key"; _sev="HIGH"
    elif [[ "$content" =~ -----BEGIN.*PRIVATE\ KEY----- ]]; then
        _type="Private Key"; _sev="HIGH"
    elif [[ "$content" =~ ghp_[0-9a-zA-Z]{36} ]]; then
        _type="GitHub PAT"; _sev="MEDIUM"
    elif [[ "$content" =~ xox[baprs]- ]]; then
        _type="Slack Token"; _sev="MEDIUM"
    elif [[ "$content" =~ password[[:space:]]*= ]]; then
        _type="Hardcoded Password"; _sev="LOW"
    elif [[ "$content" =~ secret[[:space:]]*= ]]; then
        _type="Hardcoded Secret"; _sev="LOW"
    elif [[ "$content" =~ token[[:space:]]*= ]]; then
        _type="Hardcoded Token"; _sev="LOW"
    elif [[ "$content" =~ api_key[[:space:]]*= ]]; then
        _type="Hardcoded API Key"; _sev="LOW"
    else
        _type="Potential Secret"; _sev="LOW"
    fi
}

# ── Mask Secret Value ───────────────────────────────────────────────────────
_mask_secret() {
    local input="$1"
    # Find and mask strings that look like secrets (8+ chars after = or :)
    echo "$input" | sed -E 's/([=:]\s*["\x27]?)([A-Za-z0-9/+=_-]{4})[A-Za-z0-9/+=_-]{4,}([A-Za-z0-9/+=_-]{4})/\1\2****\3/g'
}
