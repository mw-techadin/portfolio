# Projects Overview

A reference guide for every script and tool in this portfolio, including purpose, usage, and dependencies.

**Python compatibility:** All scripts require Python 3.7 or later.

---

## scripts/

### `log_parser_authlog.py`
**Purpose:** Scans `/var/log/auth.log` for failed SSH authentication events and detects brute-force patterns.

**Features:**
- Parses sshd failed/accepted events with regex
- Counts failures per source IP
- Flags IPs exceeding a configurable threshold
- Outputs a daily summary report
- Exits non-zero when brute-force IPs are found (CI-friendly)

**Usage:**
```bash
python3 scripts/log_parser_authlog.py
python3 scripts/log_parser_authlog.py --log /var/log/auth.log --threshold 5
```

**Dependencies:** Python standard library only

---

### `s3_public_checker.py`
**Purpose:** Audits all AWS S3 buckets for public exposure vectors.

**Checks performed:**
- `PublicAccessBlock` — all four flags must be enabled
- Bucket ACL — no grants to `AllUsers` or `AuthenticatedUsers` URIs
- Bucket policy — no statements with `Principal: "*"`

**Usage:**
```bash
AWS_PROFILE=myprofile python3 scripts/s3_public_checker.py
python3 scripts/s3_public_checker.py --region us-east-1 --output json
```

**Dependencies:** `pip install boto3`

---

### `vuln_csv_parser.py`
**Purpose:** Parses vulnerability scanner CSV exports (Nessus, Qualys, or generic format), deduplicates findings, and outputs a triage-ready severity summary.

**Features:**
- Auto-detects column names (case-insensitive)
- Deduplicates by (name, severity, port), merging affected hosts
- Groups by: Critical → High → Medium → Low → Info
- Supports text and JSON output formats

**Usage:**
```bash
python3 scripts/vuln_csv_parser.py --input scan_results.csv
python3 scripts/vuln_csv_parser.py --input scan_results.csv --output report.txt
python3 scripts/vuln_csv_parser.py --input scan_results.csv --format json
```

**Dependencies:** Python standard library only

---

### `linux_audit.sh`
**Purpose:** Audits local user accounts, sudo privileges, and login history on a Linux host.

**Checks performed:**
- Users with interactive login shells (compares against a whitelist)
- sudoers file and sudoers.d drop-ins
- Members of `sudo` and `wheel` groups
- Last 10 logins via `last`
- Currently logged-in users via `who`

**Usage:**
```bash
./scripts/linux_audit.sh
./scripts/linux_audit.sh --whitelist "alice,bob,deploy"
./scripts/linux_audit.sh --output /var/log/audit.txt --email security@example.com
```

**Dependencies:** `bash`, `lastlog`, `last`, `who`, `getent` (standard Linux tools)

---

## detections/

### `brute_force_detect.json`
**Purpose:** Detection rule definitions in a structured JSON schema for SSH brute-force and enumeration patterns.

**Rules included:**
| ID | Name | MITRE |
|----|------|-------|
| BFD-001 | SSH Brute Force - Threshold Exceeded | T1110.001 |
| BFD-002 | SSH Distributed Brute Force - Multiple IPs | T1110.003 |
| BFD-003 | SSH Invalid User Enumeration | T1087.001 |

Each rule includes: detection logic, aggregation parameters, severity, MITRE ATT&CK mapping, false-positive notes, and response actions.

---

### `failed_logins_summary.py`
**Purpose:** Aggregates failed SSH login events into a daily triage summary. Can ingest either auth.log directly or a JSON events file.

**Features:**
- Top N attacking IPs
- Top N targeted usernames
- IPs targeting 3+ distinct usernames (enumeration flag)
- Optional JSON summary output for SIEM ingestion

**Usage:**
```bash
python3 detections/failed_logins_summary.py --log /var/log/auth.log
python3 detections/failed_logins_summary.py --log /var/log/auth.log --top 20
python3 detections/failed_logins_summary.py --json /tmp/events.json --output-json summary.json
```

---

## devsecops/

### `.github/workflows/secrets_scan.yml`
**Purpose:** GitHub Action that runs `gitleaks` on every PR and push to main, failing the build if secrets are detected.

**Features:**
- On PRs: scans only the commits introduced by the PR; on push: scans the head commit
- Posts a PR comment listing violations
- Uploads a `gitleaks-report.json` artifact on failure
- Optionally sends a Slack alert (via `slackapi/slack-github-action@v2`) when secrets land on main

**Required secrets:**
- `SLACK_WEBHOOK_URL` (optional, for Slack notifications)

---

### `tfsec_scan.sh`
**Purpose:** Bash wrapper around `tfsec` for scanning Terraform configurations in CI or local workflows.

**Features:**
- Configurable minimum severity (LOW / MEDIUM / HIGH / CRITICAL)
- Supports default, JSON, SARIF, and CSV output formats
- Respects `.tfsec/config.yml` if present
- `--no-fail` flag for informational-only runs

**Usage:**
```bash
./devsecops/tfsec_scan.sh
./devsecops/tfsec_scan.sh --dir infrastructure/ --severity HIGH
./devsecops/tfsec_scan.sh --dir infra/ --format json --output report.json
```

---

### `checkov_report_parser.py`
**Purpose:** Parses `checkov` JSON output into a human-readable or Markdown summary for IaC security reviews.

**Features:**
- Handles single-runner and multi-runner checkov output
- Correctly maps check name and description from checkov's nested output structure
- Filters by minimum severity
- Groups findings by CRITICAL → HIGH → MEDIUM → LOW
- Markdown output for GitHub PR comments or Confluence pages

**Usage:**
```bash
checkov -d ./infrastructure --output json > checkov_report.json
python3 devsecops/checkov_report_parser.py --input checkov_report.json
python3 devsecops/checkov_report_parser.py --input checkov_report.json --severity HIGH --format markdown
```

---

## integrations/

### `shodan_scan_to_jira.py`
**Purpose:** Queries Shodan for open ports/services on a domain or CIDR range and auto-creates Jira tickets for unexpected exposure.

**Features:**
- Supports domain names, single IPs, and CIDR ranges
- Configurable allowed-ports list (default: 80, 443)
- `--dry-run` mode for testing without creating tickets
- Generates Jira issue descriptions in plain text (compatible with Jira Cloud REST API v2 and v3)

**Required env vars:**
```
SHODAN_API_KEY, JIRA_URL, JIRA_USER, JIRA_API_TOKEN, JIRA_PROJECT_KEY
```

**Usage:**
```bash
python3 integrations/shodan_scan_to_jira.py --target example.com
python3 integrations/shodan_scan_to_jira.py --target 203.0.113.0/24 --allowed-ports 22,80,443
python3 integrations/shodan_scan_to_jira.py --target example.com --dry-run
```

---

### `slack_notifier.py`
**Purpose:** Reusable Slack webhook helper for sending colour-coded security alerts from any automation script using Slack Block Kit.

**Severities and colours:**
| Severity | Colour |
|----------|--------|
| CRITICAL | Red |
| HIGH | Orange |
| MEDIUM | Yellow |
| LOW | Green |
| INFO | Blue |

**Usage as a library:**
```python
from integrations.slack_notifier import SlackNotifier

notifier = SlackNotifier()
notifier.send_alert(
    title="S3 Public Bucket Detected",
    message="Bucket 'my-bucket' has public ACL enabled.",
    severity="HIGH",
    fields={"Bucket": "my-bucket", "Account": "123456789"},
)
```

**Usage as a CLI:**
```bash
python3 integrations/slack_notifier.py \
  --title "Scan Complete" \
  --message "3 HIGH findings in Terraform config" \
  --severity HIGH \
  --field "Environment=production" \
  --field "Repo=infra"
```
