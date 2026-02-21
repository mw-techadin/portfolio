#!/usr/bin/env python3
"""
failed_logins_summary.py
------------------------
Aggregates failed SSH login data produced by log_parser_authlog.py
(or any structured source) and generates a summary suitable for
daily security reports or SIEM ingestion.

Can read from:
  - A live auth.log file directly (--log)
  - A JSON file output by log_parser_authlog.py (--json)

Usage:
    python3 failed_logins_summary.py --log /var/log/auth.log
    python3 failed_logins_summary.py --json /tmp/failed_logins.json
    python3 failed_logins_summary.py --log /var/log/auth.log --top 20
"""

import re
import sys
import json
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path


FAILED_PATTERN = re.compile(
    r"(\w{3}\s+\d{1,2}\s[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed\s+\w+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\d.]+)"
)


def parse_auth_log(log_path: str) -> list[dict]:
    events = []
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = FAILED_PATTERN.search(line)
                if m:
                    ts, user, ip = m.groups()
                    events.append({"timestamp": ts, "user": user, "ip": ip})
    except (FileNotFoundError, PermissionError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    return events


def load_json(json_path: str) -> list[dict]:
    try:
        data = json.loads(Path(json_path).read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        # If nested under a key
        for key in ("events", "failed", "attempts"):
            if key in data:
                return data[key]
        raise ValueError("Cannot locate event list in JSON structure")
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


def summarise(events: list[dict], top_n: int) -> dict:
    ip_counts       = Counter(e["ip"] for e in events)
    user_counts     = Counter(e["user"] for e in events)
    ip_users        = defaultdict(set)
    user_ips        = defaultdict(set)

    for e in events:
        ip_users[e["ip"]].add(e["user"])
        user_ips[e["user"]].add(e["ip"])

    return {
        "total_events":      len(events),
        "unique_ips":        len(ip_counts),
        "unique_users":      len(user_counts),
        "top_ips":           ip_counts.most_common(top_n),
        "top_targeted_users": user_counts.most_common(top_n),
        "multi_user_ips":    {
            ip: sorted(users)
            for ip, users in ip_users.items()
            if len(users) >= 3
        },
    }


def print_summary(summary: dict, top_n: int) -> None:
    divider = "=" * 60
    print(divider)
    print(f"  Failed SSH Logins — Daily Summary")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(divider)
    print(f"  Total failed events : {summary['total_events']}")
    print(f"  Unique source IPs   : {summary['unique_ips']}")
    print(f"  Unique usernames    : {summary['unique_users']}")
    print()

    print(f"  Top {top_n} attacking IPs:")
    print(f"  {'IP':<20} {'Count':>6}")
    print(f"  {'─'*20}  {'─'*6}")
    for ip, count in summary["top_ips"]:
        print(f"  {ip:<20} {count:>6}")
    print()

    print(f"  Top {top_n} targeted usernames:")
    print(f"  {'Username':<20} {'Count':>6}")
    print(f"  {'─'*20}  {'─'*6}")
    for user, count in summary["top_targeted_users"]:
        print(f"  {user:<20} {count:>6}")
    print()

    if summary["multi_user_ips"]:
        print(f"  IPs targeting 3+ distinct usernames (enumeration risk):")
        for ip, users in sorted(summary["multi_user_ips"].items()):
            print(f"  {ip}  →  {', '.join(users[:8])}")
        print()

    print(divider)


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate failed SSH login events into a summary"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--log",  help="Path to auth.log file")
    source.add_argument("--json", help="Path to JSON events file")
    parser.add_argument("--top",  type=int, default=10, help="Number of top entries to show")
    parser.add_argument("--output-json", help="Write JSON summary to file")
    args = parser.parse_args()

    events = parse_auth_log(args.log) if args.log else load_json(args.json)

    if not events:
        print("[INFO] No failed login events found.")
        sys.exit(0)

    summary = summarise(events, args.top)
    print_summary(summary, args.top)

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"[OK] JSON summary written to: {args.output_json}")


if __name__ == "__main__":
    main()
