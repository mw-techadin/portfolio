# 🛡️ Security Engineering Portfolio

A collection of hands-on security engineering projects demonstrating scripting, automation, detection, and DevSecOps skills.

---

## 📁 Directory Structure
```
security-engineering-portfolio/
├── README.md
├── scripts/
│   ├── log_parser_authlog.py
│   ├── s3_public_checker.py
│   ├── vuln_csv_parser.py
│   └── linux_audit.sh
├── detections/
│   ├── brute_force_detect.json
│   └── failed_logins_summary.py
├── devsecops/
│   ├── .github/
│   │   └── workflows/
│   │       └── secrets_scan.yml
│   ├── tfsec_scan.sh
│   └── checkov_report_parser.py
├── exploitation/
│   ├── CVE-YYYY-NNNN_poc.py
│   └── reverse_shell_generator.py
├── integrations/
│   ├── shodan_scan_to_jira.py
│   └── slack_notifier.py
└── docs/
    ├── PROJECTS.md
    ├── LOG_PARSING.md
    └── REMEDIATION_AUTOMATION.md
```

---

## ✅ Highlighted Projects

### 1. **Linux Audit Script** (`scripts/linux_audit.sh`)
- Bash script that audits local user accounts, sudo usage, and last login times.
- Sends alert if unexpected users are found.

### 2. **Auth Log Parser** (`scripts/log_parser_authlog.py`)
- Python script that scans `/var/log/auth.log` for failed SSH attempts.
- Outputs daily summaries and raises flags on brute force indicators.

### 3. **S3 Public Bucket Checker** (`scripts/s3_public_checker.py`)
- Uses `boto3` to audit all S3 buckets.
- Flags any that have `PublicAccessBlock` disabled or ACLs with public grants.

### 4. **Shodan to Jira** (`integrations/shodan_scan_to_jira.py`)
- Polls Shodan for open ports on your domain.
- Auto-creates tickets in Jira with actionable context.

### 5. **GitHub Secrets Scanner** (`devsecops/.github/workflows/secrets_scan.yml`)
- GitHub Action integrating `gitleaks` to scan for secrets in PRs.
- Fails builds and alerts developers.

---

## 🚧 Future Project Ideas
- [ ] Build a CLI wrapper for `nuclei`
- [ ] Use `falco` to monitor container activity and trigger alerts
- [ ] Integrate `checkov` with Slack for Terraform scanning alerts
- [ ] Python-based SOAR mock tool (parse scan → send to Slack/Jira)

---

## 📚 Docs and Usage
- `PROJECTS.md`: Overview and purpose of each script/tool
- `LOG_PARSING.md`: Guide on custom detection patterns
- `REMEDIATION_AUTOMATION.md`: How the scripts automate basic remediations

---

## 💬 Contact / Connect
Feel free to fork, star, or reach out with suggestions. Built by a security engineer focused on automation, detection, and modern SecOps.
