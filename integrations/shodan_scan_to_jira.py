#!/usr/bin/env python3
"""
shodan_scan_to_jira.py
----------------------
Polls Shodan for open ports/services on a target domain or IP range,
then auto-creates Jira tickets for unexpected exposure.

Requirements:
    pip install shodan requests

Environment variables (or .env file):
    SHODAN_API_KEY    — Shodan API key
    JIRA_URL          — e.g. https://yourorg.atlassian.net
    JIRA_USER         — Atlassian account email
    JIRA_API_TOKEN    — Jira API token
    JIRA_PROJECT_KEY  — e.g. SEC

Usage:
    python3 shodan_scan_to_jira.py --target example.com
    python3 shodan_scan_to_jira.py --target 203.0.113.0/24 --allowed-ports 80,443
    python3 shodan_scan_to_jira.py --target example.com --dry-run
"""

from __future__ import annotations

import os
import sys
import json
import argparse
from datetime import datetime

try:
    import shodan
except ImportError:
    print("[ERROR] 'shodan' package not installed. Run: pip install shodan", file=sys.stderr)
    sys.exit(1)

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("[ERROR] 'requests' package not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


# ── Configuration from environment ────────────────────────────────────────────
SHODAN_API_KEY   = os.environ.get("SHODAN_API_KEY", "")
JIRA_URL         = os.environ.get("JIRA_URL", "").rstrip("/")
JIRA_USER        = os.environ.get("JIRA_USER", "")
JIRA_API_TOKEN   = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SEC")

# Ports that are always acceptable (skip Jira creation for these)
DEFAULT_ALLOWED_PORTS = {80, 443}


def validate_env() -> None:
    missing = []
    for var in ["SHODAN_API_KEY", "JIRA_URL", "JIRA_USER", "JIRA_API_TOKEN"]:
        if not os.environ.get(var):
            missing.append(var)
    if missing:
        print(f"[ERROR] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def shodan_lookup(target: str) -> list[dict]:
    """Query Shodan for a domain or IP and return a list of host/port findings."""
    api      = shodan.Shodan(SHODAN_API_KEY)
    findings = []

    try:
        if "/" in target:
            # CIDR range — use search
            results = api.search(f"net:{target}")
            for match in results.get("matches", []):
                findings.append({
                    "ip":        match.get("ip_str", ""),
                    "port":      match.get("port"),
                    "transport": match.get("transport", "tcp"),
                    "product":   match.get("product", ""),
                    "banner":    (match.get("data", "") or "")[:200],
                    "country":   match.get("location", {}).get("country_name", ""),
                    "org":       match.get("org", ""),
                    "hostnames": match.get("hostnames", []),
                })
        else:
            # Domain or single IP — resolve and look up
            host = api.host(target)
            for item in host.get("data", []):
                findings.append({
                    "ip":        host.get("ip_str", target),
                    "port":      item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product":   item.get("product", ""),
                    "banner":    (item.get("data", "") or "")[:200],
                    "country":   host.get("country_name", ""),
                    "org":       host.get("org", ""),
                    "hostnames": host.get("hostnames", []),
                })

    except shodan.APIError as e:
        print(f"[ERROR] Shodan API error: {e}", file=sys.stderr)
        sys.exit(1)

    return findings


def filter_unexpected(findings: list[dict], allowed_ports: set[int]) -> list[dict]:
    return [f for f in findings if f["port"] not in allowed_ports]


def create_jira_ticket(finding: dict, target: str, dry_run: bool) -> dict | None:
    """Create a Jira issue for an unexpected open port finding."""
    summary = (
        f"[Shodan] Unexpected open port {finding['port']}/{finding['transport']} "
        f"on {finding['ip']} ({target})"
    )
    hostnames = ', '.join(finding.get('hostnames', [])) or 'N/A'
    banner    = finding.get('banner', 'N/A')
    description = (
        f"Finding source: Shodan automated scan\n"
        f"Scan date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        f"Target:    {target}\n"
        f"IP:        {finding['ip']}\n"
        f"Port:      {finding['port']}/{finding['transport']}\n"
        f"Product:   {finding.get('product') or 'N/A'}\n"
        f"Country:   {finding.get('country') or 'N/A'}\n"
        f"Org:       {finding.get('org') or 'N/A'}\n"
        f"Hostnames: {hostnames}\n\n"
        f"Banner (first 200 chars):\n{banner}\n\n"
        f"Action required:\n"
        f"1. Confirm whether this port should be exposed.\n"
        f"2. If unexpected, identify the service and owner.\n"
        f"3. Firewall or restrict access, or close the service.\n"
        f"4. Update the allowed-ports list if this is intentional.\n"
    )

    payload = {
        "fields": {
            "project":     {"key": JIRA_PROJECT_KEY},
            "summary":     summary,
            "description": description,
            "issuetype":   {"name": "Bug"},
            "priority":    {"name": "High"},
            "labels":      ["shodan", "external-exposure", "automated"],
        }
    }

    if dry_run:
        print(f"  [DRY RUN] Would create ticket: {summary}")
        return None

    resp = requests.post(
        f"{JIRA_URL}/rest/api/2/issue",
        json=payload,
        auth=HTTPBasicAuth(JIRA_USER, JIRA_API_TOKEN),
        headers={"Content-Type": "application/json"},
        timeout=15,
    )

    if resp.status_code == 201:
        issue = resp.json()
        return {"key": issue["key"], "url": f"{JIRA_URL}/browse/{issue['key']}"}
    else:
        print(f"  [ERROR] Failed to create ticket: {resp.status_code} {resp.text}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(description="Poll Shodan and file Jira tickets for open ports")
    parser.add_argument("--target",        required=True, help="Domain, IP, or CIDR range to scan")
    parser.add_argument("--allowed-ports", default="80,443",
                        help="Comma-separated list of allowed ports (default: 80,443)")
    parser.add_argument("--dry-run",       action="store_true",
                        help="Print what tickets would be created without creating them")
    args = parser.parse_args()

    if not args.dry_run:
        validate_env()

    allowed = {int(p.strip()) for p in args.allowed_ports.split(",") if p.strip().isdigit()}

    print(f"[*] Querying Shodan for: {args.target}")
    findings = shodan_lookup(args.target)
    print(f"[*] Total findings: {len(findings)}")

    unexpected = filter_unexpected(findings, allowed)
    print(f"[*] Unexpected ports (not in {sorted(allowed)}): {len(unexpected)}")

    if not unexpected:
        print("[OK] No unexpected ports found.")
        sys.exit(0)

    print()
    created = []
    for finding in unexpected:
        print(f"  → {finding['ip']}:{finding['port']}/{finding['transport']} "
              f"({finding.get('product') or 'unknown'})")
        ticket = create_jira_ticket(finding, args.target, args.dry_run)
        if ticket:
            print(f"    Jira: {ticket['url']}")
            created.append(ticket)

    print()
    if not args.dry_run:
        print(f"[OK] Created {len(created)} Jira ticket(s).")
    else:
        print(f"[DRY RUN] Would have created {len(unexpected)} Jira ticket(s).")

    sys.exit(1 if unexpected else 0)


if __name__ == "__main__":
    main()
