#!/usr/bin/env python3
"""
log_parser_authlog.py
---------------------
Scans /var/log/auth.log for failed SSH authentication attempts.
Outputs a daily summary and raises a brute-force flag when an IP
exceeds the configured threshold.

Usage:
    python3 log_parser_authlog.py [--log /path/to/auth.log] [--threshold 10]
"""

import re
import sys
import argparse
from collections import defaultdict
from datetime import datetime, date


# ── Configuration ────────────────────────────────────────────────────────────
DEFAULT_LOG_PATH = "/var/log/auth.log"
DEFAULT_THRESHOLD = 10          # failed attempts before flagging an IP
BRUTE_FORCE_WINDOW_MINUTES = 5  # time window for rapid-burst detection

# Regex patterns
FAILED_PATTERN = re.compile(
    r"(\w{3}\s+\d{1,2}\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed\s+\w+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\d.]+)"
)
ACCEPTED_PATTERN = re.compile(
    r"(\w{3}\s+\d{1,2}\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted\s+\w+\s+for\s+(\S+)\s+from\s+([\d.]+)"
)


def parse_log(log_path: str) -> dict:
    """Parse auth.log and return structured findings."""
    failed_by_ip: dict[str, list] = defaultdict(list)
    successful_logins: list[dict] = []

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = FAILED_PATTERN.search(line)
                if m:
                    timestamp, user, ip = m.groups()
                    failed_by_ip[ip].append({
                        "timestamp": timestamp,
                        "user": user,
                    })
                    continue

                m = ACCEPTED_PATTERN.search(line)
                if m:
                    timestamp, user, ip = m.groups()
                    successful_logins.append({
                        "timestamp": timestamp,
                        "user": user,
                        "ip": ip,
                    })

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {log_path}", file=sys.stderr)
        sys.exit(1)

    return {
        "failed_by_ip": dict(failed_by_ip),
        "successful_logins": successful_logins,
    }


def analyze(findings: dict, threshold: int) -> dict:
    """Identify brute-force candidates and build summary."""
    flagged_ips = {}
    failed_by_ip = findings["failed_by_ip"]

    for ip, attempts in failed_by_ip.items():
        count = len(attempts)
        if count >= threshold:
            usernames_tried = list({a["user"] for a in attempts})
            flagged_ips[ip] = {
                "count": count,
                "usernames_tried": usernames_tried,
                "first_seen": attempts[0]["timestamp"] if attempts else "N/A",
                "last_seen": attempts[-1]["timestamp"] if attempts else "N/A",
            }

    total_failed = sum(len(v) for v in failed_by_ip.values())

    return {
        "total_failed_attempts": total_failed,
        "unique_ips": len(failed_by_ip),
        "flagged_ips": flagged_ips,
        "successful_logins": findings["successful_logins"],
    }


def print_report(report: dict, threshold: int) -> None:
    """Pretty-print the summary report."""
    today = date.today().strftime("%Y-%m-%d")
    divider = "=" * 60

    print(divider)
    print(f"  SSH Auth Log Report  |  {today}")
    print(divider)
    print(f"  Total failed attempts : {report['total_failed_attempts']}")
    print(f"  Unique source IPs     : {report['unique_ips']}")
    print(f"  Brute-force threshold : {threshold} attempts")
    print()

    if report["flagged_ips"]:
        print(f"  [!] BRUTE-FORCE CANDIDATES ({len(report['flagged_ips'])} IPs flagged)")
        print("-" * 60)
        for ip, info in sorted(report["flagged_ips"].items(),
                                key=lambda x: x[1]["count"], reverse=True):
            print(f"  IP      : {ip}")
            print(f"  Count   : {info['count']} failed attempts")
            print(f"  Users   : {', '.join(info['usernames_tried'][:5])}")
            print(f"  Window  : {info['first_seen']}  →  {info['last_seen']}")
            print()
    else:
        print("  [OK] No brute-force activity detected above threshold.")
        print()

    if report["successful_logins"]:
        print(f"  [INFO] Successful logins: {len(report['successful_logins'])}")
        for login in report["successful_logins"][-5:]:
            print(f"    {login['timestamp']}  user={login['user']}  from={login['ip']}")
    else:
        print("  [INFO] No successful logins recorded in this log.")

    print(divider)


def main():
    parser = argparse.ArgumentParser(
        description="Parse auth.log for SSH brute-force indicators"
    )
    parser.add_argument("--log",       default=DEFAULT_LOG_PATH, help="Path to auth.log")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help="Failed attempt count before flagging an IP")
    args = parser.parse_args()

    findings = parse_log(args.log)
    report   = analyze(findings, args.threshold)
    print_report(report, args.threshold)

    # Exit with non-zero status if brute-force IPs found (useful in pipelines)
    if report["flagged_ips"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
