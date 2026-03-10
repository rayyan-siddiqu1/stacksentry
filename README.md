# StackSentry

A pure-bash DevOps security and cloud governance CLI platform. No Python, no Node, no frontend frameworks — everything runs in the terminal using bash scripts, AWS CLI, and standard Unix tools.

## Quick Start

```bash
# Clone and set up
git clone <repo-url> && cd stacksentry
chmod +x bin/stacksentry

# Check dependencies
./bin/stacksentry doctor

# Run an IAM security audit
./bin/stacksentry iam audit

# Scan a directory for exposed secrets
./bin/stacksentry secrets scan --path /your/project

# Run CIS benchmark checks
./bin/stacksentry posture scan
```

## Requirements

| Tool | Version | Required |
|------|---------|----------|
| bash | 4.0+ | Yes |
| aws cli | v2 | Yes |
| jq | any | Yes |
| curl | any | Yes |
| git | any | Yes |
| bc | any | Yes |
| column | any | Yes |
| awk / sed / grep | any | Yes |
| mail / sendmail | any | No (for email alerts) |

Run `stacksentry doctor` to verify all dependencies.

## Installation

```bash
# Option 1: Symlink to PATH
ln -s $(pwd)/bin/stacksentry /usr/local/bin/stacksentry

# Option 2: Add to PATH
export PATH="$PATH:/path/to/stacksentry/bin"
```

## Usage

```
stacksentry <module> <command> [flags]
```

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--profile <name>` | AWS CLI profile | `default` |
| `--region <region>` | AWS region | `us-east-1` |
| `--output <format>` | `table`, `json`, or `csv` | `table` |
| `--severity <level>` | Filter: `critical`, `high`, `medium`, `low` | all |
| `--save` | Save report to `reports/` directory | off |
| `--alert` | Trigger Slack/email alerts on findings | off |
| `--verbose` | Enable debug logging | off |

## Modules

### IAM Lens — IAM Security Audit

```bash
# Full IAM audit: MFA, access keys, password policy, privileges
stacksentry iam audit

# Deep analysis: unused roles, trust policies, service access patterns
stacksentry iam analyze

# Monitor CloudTrail for suspicious IAM events (last 24h)
stacksentry iam alert
```

**What it checks:**
- Root account MFA and access keys
- User MFA enrollment (console vs programmatic)
- Access key age and rotation (>90 days flagged)
- Inactive users (>90 days)
- Password policy strength (length, complexity, rotation)
- Over-privileged policies (`Action:*`, `AdministratorAccess`)
- Inline policies (recommends managed policies)
- Open trust policies (`Principal: *`)
- Cross-account role trust
- Unused roles and over-provisioned service access

### Secret Radar — Secret Detection

```bash
# Scan a local directory
stacksentry secrets scan --path /your/project

# Scan a Git repository (clones to /tmp, cleans up after)
stacksentry secrets scan --repo https://github.com/org/repo

# Include git history scan
stacksentry secrets scan --path . --git-history

# Skip entropy analysis
stacksentry secrets scan --path . --no-entropy
```

**Detection patterns (20 built-in):**
- AWS Access Keys and Secret Keys
- GCP API Keys
- Stripe Live/Test Keys
- Slack Tokens
- GitHub PATs, OAuth, and App Tokens
- RSA / EC / Generic Private Keys
- Hardcoded passwords, secrets, tokens, API keys
- Azure Storage Account Keys
- SendGrid, Twilio, Mailgun keys

**Features:**
- Shannon entropy analysis for high-randomness values
- Git history scanning (last 100 commits)
- Secret masking in output (first 4 + last 4 chars shown)
- Allowlist support (`config/allowlist.txt`)
- Skips binary files and directories like `.git`, `node_modules`, `vendor`

### Posture Board — CIS Benchmark Checks

```bash
# Run all 20 CIS checks
stacksentry posture scan

# Run specific check categories
stacksentry posture scan --checks iam,s3
stacksentry posture scan --checks network
```

**20 checks across 4 categories:**

| ID | Category | Check |
|----|----------|-------|
| 1.1 | IAM | Root account MFA enabled |
| 1.2 | IAM | Root account has no active access keys |
| 1.3 | IAM | Password policy minimum 14 characters |
| 1.4 | IAM | Password policy requires symbols |
| 1.5 | IAM | No inline IAM policies in use |
| 1.6 | IAM | All console users have MFA |
| 2.1 | S3 | No buckets with public ACL |
| 2.2 | S3 | No buckets with public bucket policy |
| 2.3 | S3 | Buckets have server-side encryption |
| 2.4 | S3 | Buckets have versioning enabled |
| 2.5 | S3 | S3 access logging enabled |
| 3.1 | Logging | CloudTrail enabled in all regions |
| 3.2 | Logging | CloudTrail log file validation |
| 3.3 | Logging | CloudTrail logs encrypted with KMS |
| 3.4 | Logging | VPC Flow Logs enabled |
| 3.5 | Logging | AWS Config enabled |
| 4.1 | Network | No security groups allow SSH from 0.0.0.0/0 |
| 4.2 | Network | No security groups allow RDP from 0.0.0.0/0 |
| 4.3 | Network | Default VPC has no internet gateway |
| 4.4 | Network | No EC2 instances in default VPC |

**Features:**
- Posture score: `(PASS / total) * 100%`
- Score delta vs previous scan (trend tracking)
- Results saved to `reports/posture_TIMESTAMP.csv`

## Output Formats

### Table (default)
Color-coded terminal output with severity indicators:
- **Red** — Critical / High
- **Yellow** — Medium
- **Green** — Pass / Low

### JSON (`--output json`)
```json
[
  {
    "severity": "CRITICAL",
    "module": "iam_lens",
    "resource": "user:john",
    "finding": "Console user has no MFA device",
    "remediation": "Enable MFA: aws iam enable-mfa-device --user-name john",
    "timestamp": "2026-03-10T14:30:00Z"
  }
]
```

### CSV (`--output csv`)
```
SEVERITY,MODULE,RESOURCE,FINDING,REMEDIATION,TIMESTAMP
"CRITICAL","iam_lens","user:john","Console user has no MFA device","Enable MFA...","2026-03-10T14:30:00Z"
```

## Configuration

### `config/stacksentry.conf`

```bash
STACKSENTRY_AWS_PROFILE="default"
STACKSENTRY_AWS_REGION="us-east-1"
STACKSENTRY_OUTPUT_FORMAT="table"
STACKSENTRY_LOG_LEVEL="INFO"

# Slack alerts
STACKSENTRY_SLACK_WEBHOOK="https://hooks.slack.com/services/..."

# Email alerts
STACKSENTRY_EMAIL_TO="security@example.com"
```

### `config/allowlist.txt`

Suppress known false positives by adding resource identifiers (one per line):

```
arn:aws:iam::123456789012:user/ci-bot
sg-0abc1234def56789a
my-public-docs-bucket
```

## Project Structure

```
stacksentry/
├── bin/stacksentry              # CLI entrypoint
├── core/
│   ├── output.sh                # Colors, banners, tables
│   ├── logger.sh                # Structured file logging
│   ├── scoring.sh               # Finding format & severity
│   ├── aws_session.sh           # AWS profile/region setup
│   ├── report.sh                # Save to txt/csv/json
│   └── alert.sh                 # Slack & email dispatch
├── modules/
│   ├── iam_lens/                # IAM security audit
│   ├── secret_radar/            # Secret detection
│   ├── posture_board/           # CIS benchmark checks
│   ├── infra_snap/              # Infrastructure drift (planned)
│   ├── compliance_mapper/       # Compliance mapping (planned)
│   ├── cost_sentinel/           # Cost optimization (planned)
│   ├── audit_vault/             # CloudTrail analysis (planned)
│   └── patch_tracker/           # Patch management (planned)
├── config/
│   ├── stacksentry.conf         # Global configuration
│   └── allowlist.txt            # False positive suppression
├── reports/                     # Generated reports
└── logs/                        # Scan logs
```

## Roadmap

- [ ] **Infra Snap** — Detect infrastructure drift against desired state
- [ ] **Compliance Mapper** — Map findings to SOC2, HIPAA, PCI-DSS controls
- [ ] **Cost Sentinel** — Find idle EC2, unattached EBS, unused EIPs
- [ ] **Audit Vault** — CloudTrail log ingestion, search, anomaly detection
- [ ] **Patch Tracker** — EC2 patch status via SSM, CVE cross-reference
- [ ] Test suite with mocked AWS responses
- [ ] Automated install script

## License

MIT
