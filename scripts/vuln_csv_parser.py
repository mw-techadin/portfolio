#!/usr/bin/env python3
"""
vuln_csv_parser.py
------------------
Parses a vulnerability scanner CSV export (Nessus / Qualys / generic format),
deduplicates findings, groups by severity, and outputs a triage-ready summary.

Expected CSV columns (case-insensitive):
    Plugin ID, CVE, Risk, Host, Protocol, Port, Name, Description, Solution

Usage:
    python3 vuln_csv_parser.py --input scan_results.csv
    python3 vuln_csv_parser.py --input scan_results.csv --output report.txt
    python3 vuln_csv_parser.py --input scan_results.csv --format json
"""

import csv
import sys
import json
import argparse
from collections import defaultdict
from pathlib import Path


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "None"]

SEVERITY_MAP = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
    "none":     "None",
    "informational": "Info",
}


def normalise_header(raw: str) -> str:
    return raw.strip().lower().replace(" ", "_")


def parse_csv(path: str) -> list[dict]:
    findings = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            headers = {normalise_header(h): h for h in reader.fieldnames or []}

            for row in reader:
                norm = {normalise_header(k): v.strip() for k, v in row.items()}

                severity_raw = (
                    norm.get("risk")
                    or norm.get("severity")
                    or norm.get("criticality")
                    or "None"
                )
                severity = SEVERITY_MAP.get(severity_raw.lower(), severity_raw.title())

                findings.append({
                    "plugin_id":   norm.get("plugin_id") or norm.get("id") or "",
                    "cve":         norm.get("cve") or "",
                    "severity":    severity,
                    "host":        norm.get("host") or norm.get("ip") or "",
                    "port":        norm.get("port") or "",
                    "protocol":    norm.get("protocol") or "",
                    "name":        norm.get("name") or norm.get("vulnerability_name") or "",
                    "description": norm.get("description") or "",
                    "solution":    norm.get("solution") or norm.get("recommendation") or "",
                })
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    return findings


def deduplicate(findings: list[dict]) -> list[dict]:
    """Deduplicate by (name, severity, port) key, collecting affected hosts."""
    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (f["name"], f["severity"], f["port"])
        if key in seen:
            if f["host"] and f["host"] not in seen[key]["hosts"]:
                seen[key]["hosts"].append(f["host"])
        else:
            entry        = dict(f)
            entry["hosts"] = [f["host"]] if f["host"] else []
            seen[key]    = entry
    return list(seen.values())


def group_by_severity(findings: list[dict]) -> dict[str, list]:
    groups: dict[str, list] = defaultdict(list)
    for f in findings:
        groups[f["severity"]].append(f)
    return groups


def print_text_report(groups: dict, total_raw: int, output_path: str | None) -> None:
    lines = []
    divider = "=" * 65
    total_deduped = sum(len(v) for v in groups.values())

    lines.append(divider)
    lines.append("  Vulnerability Scan Summary Report")
    lines.append(divider)
    lines.append(f"  Raw findings    : {total_raw}")
    lines.append(f"  Deduplicated    : {total_deduped}")
    lines.append("")

    counts = {sev: len(groups.get(sev, [])) for sev in SEVERITY_ORDER}
    lines.append("  Severity Breakdown:")
    for sev in SEVERITY_ORDER:
        count = counts[sev]
        bar   = "█" * min(count, 30)
        lines.append(f"    {sev:<10} {count:>4}  {bar}")
    lines.append("")

    for sev in SEVERITY_ORDER:
        items = groups.get(sev, [])
        if not items:
            continue
        lines.append(f"  {'─'*55}")
        lines.append(f"  [{sev.upper()}]  ({len(items)} findings)")
        lines.append(f"  {'─'*55}")
        for item in items:
            hosts_str = ", ".join(item["hosts"][:5])
            if len(item["hosts"]) > 5:
                hosts_str += f"  +{len(item['hosts']) - 5} more"
            lines.append(f"  Name     : {item['name']}")
            if item.get("cve"):
                lines.append(f"  CVE      : {item['cve']}")
            if item.get("port"):
                lines.append(f"  Port     : {item['port']}/{item.get('protocol', 'tcp')}")
            lines.append(f"  Hosts    : {hosts_str or 'N/A'}")
            if item.get("solution"):
                sol = item["solution"][:120] + ("…" if len(item["solution"]) > 120 else "")
                lines.append(f"  Solution : {sol}")
            lines.append("")

    lines.append(divider)
    output = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
        print(f"[OK] Report written to: {output_path}")
    else:
        print(output)


def main():
    parser = argparse.ArgumentParser(description="Parse vulnerability scanner CSV exports")
    parser.add_argument("--input",  required=True, help="Path to CSV file")
    parser.add_argument("--output", default=None,  help="Write report to file (optional)")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format")
    args = parser.parse_args()

    raw_findings  = parse_csv(args.input)
    deduped       = deduplicate(raw_findings)
    groups        = group_by_severity(deduped)

    if args.format == "json":
        out = {sev: groups.get(sev, []) for sev in SEVERITY_ORDER}
        text = json.dumps(out, indent=2)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"[OK] JSON report written to: {args.output}")
        else:
            print(text)
    else:
        print_text_report(groups, len(raw_findings), args.output)

    critical_count = len(groups.get("Critical", []))
    high_count     = len(groups.get("High", []))
    sys.exit(1 if (critical_count + high_count) > 0 else 0)


if __name__ == "__main__":
    main()
