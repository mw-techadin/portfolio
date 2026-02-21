# Log Parsing & Detection Patterns

A guide to the detection logic used in `scripts/log_parser_authlog.py`, `detections/failed_logins_summary.py`, and the `detections/brute_force_detect.json` rule schema.

---

## Log Sources

### `/var/log/auth.log` (Debian/Ubuntu)
The primary log source for SSH authentication events. Equivalent path on RHEL/CentOS/Fedora is `/var/log/secure`.

**Key event patterns:**

| Pattern | Meaning |
|---------|---------|
| `Failed password for <user> from <ip>` | Password auth failure |
| `Failed publickey for <user> from <ip>` | Key-based auth failure |
| `Invalid user <user> from <ip>` | Attempt against non-existent user |
| `Accepted password for <user> from <ip>` | Successful password login |
| `Accepted publickey for <user> from <ip>` | Successful key-based login |
| `Connection closed by <ip> [preauth]` | Connection dropped before auth completed |
| `Did not receive identification string from <ip>` | Scanner or probe — no SSH client |

---

## Regex Patterns Used

### Failed authentication events
```python
r"(\w{3}\s+\d{1,2}\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
r"Failed\s+\w+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\d.]+)"
```
**Captures:** `(timestamp, username, source_ip)`

This pattern handles both standard and "invalid user" variants in a single match, avoiding duplicate entries.

### Successful authentication events
```python
r"(\w{3}\s+\d{1,2}\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
r"Accepted\s+\w+\s+for\s+(\S+)\s+from\s+([\d.]+)"
```
**Captures:** `(timestamp, username, source_ip)`

---

## Detection Logic

### Rule 1: Threshold-based brute force (BFD-001)

The simplest and most reliable signal. If a single IP generates ≥ N failed attempts within a window, flag it.

```
for each source_ip:
    if count(failed_attempts, window=5min) >= THRESHOLD:
        ALERT: brute_force
```

**Tuning guidance:**
- Default threshold: **10 failures / 5 minutes**
- For high-value systems (jump hosts, bastion servers): lower to **5 / 5min**
- For shared NAT environments: raise to **25 / 5min** to reduce false positives
- Always pair with GeoIP enrichment to contextualise alerts

### Rule 2: Password spraying (BFD-002)

Low-and-slow attacks avoid per-IP thresholds by distributing attempts across many IPs. Detect by looking at the usernames being targeted:

```
for each target_username:
    if distinct_count(source_ip, window=60min) >= 5:
        ALERT: password_spray
```

**Key insight:** Spray attacks try one password per account to avoid lockouts, so the username hit count stays low per IP but the unique-IP count targeting a single account grows.

### Rule 3: User enumeration (BFD-003)

Attackers often probe for valid usernames before attempting passwords. Detect by counting distinct usernames tried from a single IP:

```
for each source_ip:
    if distinct_count(target_username, window=10min) >= 5:
        where event contains "Invalid user"
        ALERT: user_enumeration
```

---

## Detection Rule Schema

The `brute_force_detect.json` file follows a structured schema:

```json
{
  "id":          "BFD-001",
  "name":        "Human-readable rule name",
  "description": "What this rule detects and why",
  "category":    "credential_access | reconnaissance | ...",
  "mitre_attack": {
    "tactic":        "Credential Access",
    "technique":     "T1110",
    "sub_technique": "T1110.001"
  },
  "log_source": {
    "type": "syslog",
    "path": "/var/log/auth.log"
  },
  "detection": {
    "filter": { "process": "sshd", "event_pattern": "..." },
    "aggregation": {
      "group_by":   ["source_ip"],
      "count_field": "event_id",
      "threshold":   10,
      "window_minutes": 5
    }
  },
  "severity":              "HIGH",
  "response":              { "actions": ["alert", "block_ip"] },
  "false_positive_notes":  "Describe known FP scenarios here",
  "tags":                  ["ssh", "brute-force"]
}
```

This schema is designed to be parsed by a SIEM ingestion script or translated into platform-native rule formats (Splunk SPL, Elastic EQL, Sigma, etc.).

---

## Sigma Rule Translation

The BFD-001 rule in Sigma format for SIEM portability:

```yaml
title: SSH Brute Force - Threshold Exceeded
id: bfd-001-sigma
status: stable
description: Detects SSH brute force by counting failed authentication per source IP
references:
  - https://attack.mitre.org/techniques/T1110/001/
author: Security Engineering
date: 2025/01/01
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  product: linux
  service: auth
detection:
  selection:
    process: sshd
  keywords:
    - 'Failed password for'
    - 'Failed publickey for'
  condition: selection and keywords | count() by source_ip > 10
  timeframe: 5m
falsepositives:
  - Legitimate users behind shared NAT
level: high
```

---

## Operational Tips

1. **Log rotation:** Ensure logrotate preserves compressed copies for ≥ 90 days. Run the parser against both the current log and rotated `.gz` files.

2. **Time zone normalisation:** auth.log uses local time with no explicit timezone. Standardise to UTC when aggregating across hosts.

3. **IPv6:** Extend regex to capture IPv6 addresses (`[\da-fA-F:]+`) if your environment uses dual-stack SSH.

4. **Log shipping:** For distributed environments, ship auth.log to a centralised syslog server or SIEM (e.g., Graylog, Elastic, Splunk) and run these patterns as SIEM queries rather than local scripts.

5. **Allowlisting:** Maintain a list of known-good IPs (monitoring systems, CI runners, VPN egress IPs) to suppress false positives automatically.
