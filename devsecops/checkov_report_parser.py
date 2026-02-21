#!/usr/bin/env python3
"""
checkov_report_parser.py
------------------------
Parses checkov JSON output and produces a concise summary table
for Infrastructure-as-Code security findings.

Generate checkov JSON:
    checkov -d ./infrastructure --output json > checkov_report.json
    checkov -f main.tf --output json > checkov_report.json

Usage:
    python3 checkov_report_parser.py --input checkov_report.json
    python3 checkov_report_parser.py --input checkov_report.json --severity HIGH
    python3 checkov_report_parser.py --input checkov_report.json --format markdown
"""

import json
import sys
import argparse
from pathlib import Path
from collections import Counter


SEVERITY_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def load_report(path: str) -> dict:
    try:
        text = Path(path).read_text(encoding="utf-8")
        data = json.loads(text)
        return data
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)


def extract_failed_checks(data: dict) -> list[dict]:
    """Extract failed checks from checkov output (supports single and multi-runner format)."""
    failed = []

    def _extract(results: dict) -> None:
        for check in results.get("failed_checks", []):
            severity = (check.get("severity") or "UNKNOWN").upper()
            failed.append({
                "check_id":   check.get("check_id", ""),
                "name":       check.get("check", {}).get("name", check.get("name", check.get("check_id", ""))),
                "description": check.get("description", check.get("short_description", "")),
                "severity":   severity,
                "resource":   check.get("resource", ""),
                "file":       check.get("repo_file_path", check.get("file_path", "")),
                "lines":      check.get("file_line_range", []),
                "guideline":  check.get("guideline", ""),
            })

    if "results" in data:
        _extract(data["results"])
    elif isinstance(data, list):
        for runner_result in data:
            if "results" in runner_result:
                _extract(runner_result["results"])
    else:
        _extract(data)

    return failed


def filter_by_severity(checks: list[dict], min_severity: str) -> list[dict]:
    min_level = SEVERITY_LEVELS.get(min_severity.upper(), 0)
    return [c for c in checks if SEVERITY_LEVELS.get(c["severity"], 0) >= min_level]


def print_text_summary(checks: list[dict], passed_count: int) -> None:
    divider = "=" * 65
    sev_counts = Counter(c["severity"] for c in checks)

    print(divider)
    print("  Checkov IaC Security Report")
    print(divider)
    print(f"  Passed checks  : {passed_count}")
    print(f"  Failed checks  : {len(checks)}")
    print()
    print("  Failed by severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = sev_counts.get(sev, 0)
        if count:
            bar = "█" * min(count, 20)
            print(f"    {sev:<10} {count:>4}  {bar}")
    print()

    # Group by severity, sort within group by check_id
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        group = sorted(
            [c for c in checks if c["severity"] == sev],
            key=lambda x: x["check_id"]
        )
        if not group:
            continue
        print(f"  {'─'*63}")
        print(f"  [{sev}]  ({len(group)} checks)")
        print(f"  {'─'*63}")
        for chk in group:
            lines_str = (
                f"  lines {chk['lines'][0]}-{chk['lines'][1]}"
                if len(chk.get("lines", [])) == 2
                else ""
            )
            print(f"  {chk['check_id']}")
            print(f"    Resource : {chk['resource']}")
            print(f"    File     : {chk['file']}{lines_str}")
            if chk.get("guideline"):
                print(f"    Guide    : {chk['guideline'][:80]}")
            print()

    print(divider)


def print_markdown_summary(checks: list[dict], passed_count: int) -> None:
    sev_counts = Counter(c["severity"] for c in checks)
    lines = [
        "# Checkov IaC Security Report",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Passed | {passed_count} |",
        f"| Failed | {len(checks)} |",
        "",
        "## Failed by Severity",
        "",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts.get(sev, 0)
        lines.append(f"- **{sev}**: {count}")
    lines.append("")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        group = [c for c in checks if c["severity"] == sev]
        if not group:
            continue
        lines.append(f"## {sev} Findings ({len(group)})")
        lines.append("")
        lines.append("| Check ID | Resource | File |")
        lines.append("|----------|----------|------|")
        for chk in group:
            lines.append(f"| `{chk['check_id']}` | `{chk['resource']}` | `{chk['file']}` |")
        lines.append("")

    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Parse checkov JSON scan output")
    parser.add_argument("--input",    required=True, help="Path to checkov JSON output file")
    parser.add_argument("--severity", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity to include (default: LOW)")
    parser.add_argument("--format",   choices=["text", "markdown"], default="text",
                        help="Output format")
    args = parser.parse_args()

    data   = load_report(args.input)
    checks = extract_failed_checks(data)
    checks = filter_by_severity(checks, args.severity)

    passed_count = (
        len(data.get("results", {}).get("passed_checks", []))
        if "results" in data else 0
    )

    if args.format == "markdown":
        print_markdown_summary(checks, passed_count)
    else:
        print_text_summary(checks, passed_count)

    critical_high = sum(
        1 for c in checks if c["severity"] in ("CRITICAL", "HIGH")
    )
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()
