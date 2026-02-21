# Remediation Automation

How the scripts in this portfolio automate security detection and response, and how to integrate them into a continuous security workflow.

---

## Philosophy

> Detection without response is just logging.

Every tool in this portfolio is designed with a pipeline model:

```
Detect → Enrich → Alert → Track → Remediate → Verify
```

Each step produces a structured output that feeds the next. Scripts exit with standard codes so they compose naturally in CI/CD, cron jobs, and SOAR platforms.

---

## Exit Codes

All Python scripts and bash tools follow this convention:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Clean — no findings above threshold |
| `1` | Non-critical error (file not found, config issue) |
| `2` | Security findings detected — action required |

This makes them safe to use in `&&` chains, GitHub Actions `if: failure()` conditions, and cron alerting.

---

## Automation Workflows

### 1. Daily SSH Brute-Force Digest

Run nightly via cron, post summary to Slack:

```bash
#!/usr/bin/env bash
# /etc/cron.d/ssh-audit  — runs at 07:00 daily
0 7 * * * root \
  python3 /opt/portfolio/scripts/log_parser_authlog.py \
    --log /var/log/auth.log \
  | python3 /opt/portfolio/integrations/slack_notifier.py \
    --title "Daily SSH Brute Force Report" \
    --severity INFO \
    --message "$(cat)"
```

Or in two steps, capturing exit code for escalation:

```bash
python3 scripts/log_parser_authlog.py --log /var/log/auth.log > /tmp/ssh_report.txt
EXIT=$?

python3 integrations/slack_notifier.py \
  --title "SSH Audit" \
  --message "$(cat /tmp/ssh_report.txt)" \
  --severity "$([ $EXIT -eq 2 ] && echo HIGH || echo INFO)"
```

---

### 2. S3 Public Bucket Alert → Jira Ticket

Detect exposed buckets and file a ticket automatically:

```bash
#!/usr/bin/env bash
set -euo pipefail

REPORT=$(python3 scripts/s3_public_checker.py --output json)
RISKY=$(echo "$REPORT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
risky = [b['bucket'] for b in data if b['at_risk']]
print('\n'.join(risky))
")

if [[ -n "$RISKY" ]]; then
  while IFS= read -r bucket; do
    python3 integrations/slack_notifier.py \
      --title "S3 Public Bucket Detected" \
      --message "Bucket '$bucket' has public access enabled." \
      --severity HIGH \
      --field "Bucket=$bucket"
  done <<< "$RISKY"
fi
```

---

### 3. GitHub Actions — Full DevSecOps Pipeline

Combine secrets scanning with IaC scanning in one workflow:

```yaml
name: Security Gates

on: [pull_request]

jobs:
  secrets:
    uses: ./.github/workflows/secrets_scan.yml

  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run checkov
        run: |
          pip install checkov
          checkov -d . --output json > checkov_report.json || true

      - name: Parse checkov report
        run: |
          python3 devsecops/checkov_report_parser.py \
            --input checkov_report.json \
            --severity HIGH \
            --format markdown >> $GITHUB_STEP_SUMMARY

      - name: Run tfsec
        run: ./devsecops/tfsec_scan.sh --dir . --severity HIGH
```

---

### 4. Shodan → Jira on Schedule

Run weekly to detect new external exposure:

```yaml
name: External Exposure Scan

on:
  schedule:
    - cron: '0 9 * * 1'   # Monday 09:00 UTC
  workflow_dispatch:

jobs:
  shodan-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install shodan requests
      - name: Scan for open ports
        env:
          SHODAN_API_KEY:   ${{ secrets.SHODAN_API_KEY }}
          JIRA_URL:         ${{ secrets.JIRA_URL }}
          JIRA_USER:        ${{ secrets.JIRA_USER }}
          JIRA_API_TOKEN:   ${{ secrets.JIRA_API_TOKEN }}
          JIRA_PROJECT_KEY: SEC
        run: |
          python3 integrations/shodan_scan_to_jira.py \
            --target ${{ vars.TARGET_DOMAIN }} \
            --allowed-ports 80,443
```

---

### 5. Linux Audit in a Deployment Pipeline

Validate host posture after a deployment:

```yaml
# Ansible task example
- name: Run linux user audit
  script: scripts/linux_audit.sh --whitelist "deploy,ubuntu,ec2-user"
  register: audit_result
  failed_when: audit_result.rc == 1

- name: Alert on unexpected users
  when: audit_result.rc == 1
  uri:
    url: "{{ slack_webhook_url }}"
    method: POST
    body_format: json
    body:
      text: "User audit failed on {{ inventory_hostname }}. Review attached output."
```

---

## Composing a SOAR-lite Pipeline

A simple Python-based SOAR mock using the tools in this repo:

```python
#!/usr/bin/env python3
"""
soar_mock.py — Minimal security orchestration example.
Chains: log_parser → slack_notifier → (optionally) jira ticket
"""
import subprocess
import sys
from integrations.slack_notifier import SlackNotifier

NOTIFIER = SlackNotifier()

def run_check(cmd: list[str], name: str, severity: str = "HIGH") -> int:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode >= 2:
        NOTIFIER.send_alert(
            title=f"Security Finding: {name}",
            message=result.stdout[-1000:] or result.stderr[-500:],
            severity=severity,
        )
    return result.returncode

checks = [
    (["python3", "scripts/log_parser_authlog.py"], "SSH Brute Force Scan", "HIGH"),
    (["python3", "scripts/s3_public_checker.py"],  "S3 Public Bucket Audit", "CRITICAL"),
    (["bash", "scripts/linux_audit.sh"],             "Linux User Audit", "HIGH"),
]

any_failed = False
for cmd, name, sev in checks:
    rc = run_check(cmd, name, sev)
    if rc >= 2:
        any_failed = True
        print(f"[!] {name}: FINDINGS DETECTED")
    else:
        print(f"[OK] {name}")

sys.exit(1 if any_failed else 0)
```

---

## Remediation Checklist

When a finding is raised, use this checklist:

### SSH Brute Force
- [ ] Confirm source IP is not a legitimate user/system
- [ ] Block IP at firewall or with `ufw deny from <ip>`
- [ ] Add IP to fail2ban (if deployed)
- [ ] Check if any successful login followed the failures
- [ ] Review audit log for lateral movement post-compromise

### S3 Public Bucket
- [ ] Identify the bucket owner and business purpose
- [ ] Enable all `PublicAccessBlock` settings
- [ ] Review and restrict bucket ACL to specific principals
- [ ] Audit bucket policy for `Principal: "*"` statements
- [ ] Enable S3 access logging and CloudTrail data events
- [ ] Check if sensitive data was exposed — initiate incident response if needed

### Unexpected Users (Linux Audit)
- [ ] Identify when and how the account was created
- [ ] Check shell history and login sessions for the account
- [ ] Lock or delete the account if not authorised
- [ ] Rotate credentials for any shared accounts
- [ ] Review sudoers for privilege escalation paths

### Secret in Git (gitleaks)
- [ ] Do NOT merge the PR
- [ ] Rotate the exposed credential immediately
- [ ] Remove the secret from all commits (git filter-repo or BFG)
- [ ] Audit access logs for the exposed credential
- [ ] Add the secret pattern to `.gitleaksignore` baseline if a false positive
