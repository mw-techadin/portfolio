#!/usr/bin/env python3
"""
ai_alert_triage.py
------------------
LLM-assisted SIEM alert triage using the Claude API.

Accepts a raw alert payload (JSON) and returns a structured analyst
narrative: severity assessment, likely cause, recommended actions,
and indicators of compromise.

The model acts as a first-pass analyst — review and validate its output
before acting on it.

Usage:
    python3 ai_alert_triage.py --file alert.json
    echo '{"event": "..."}' | python3 ai_alert_triage.py
    python3 ai_alert_triage.py --file alert.json --output report.md

Requires:
    pip install anthropic
    export ANTHROPIC_API_KEY="sk-ant-..."
"""

import anthropic
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path


MODEL = "claude-opus-4-6"

TRIAGE_PROMPT = """\
You are a tier-1 SOC analyst assistant. A security alert has been received.

Analyze the alert below and return a structured triage report with exactly
these sections:

SUMMARY
  One sentence describing what happened.

SEVERITY
  One of: Critical / High / Medium / Low — with a one-line rationale.

LIKELY CAUSE
  Top 1–2 hypotheses (benign or malicious), briefly explained.

RECOMMENDED ACTIONS
  Numbered list of immediate next steps for the analyst.

IOCs
  Any indicators of compromise present in the alert (IPs, hashes,
  usernames, file paths, domains). If none, write "None identified."

Be direct and practical. Avoid boilerplate. If the data is insufficient
to assess a field, say so explicitly rather than guessing.

--- ALERT ---
{alert}"""


def triage(alert_data: dict) -> str:
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    message = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": TRIAGE_PROMPT.format(
                    alert=json.dumps(alert_data, indent=2)
                ),
            }
        ],
    )
    return message.content[0].text


def print_report(result: str, source: str) -> None:
    divider = "=" * 60
    print(divider)
    print("  AI-Assisted Alert Triage Report")
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Source    : {source}")
    print(f"  Model     : {MODEL}")
    print(divider)
    print()
    print(result)
    print()
    print(divider)
    print("  [!] LLM output — analyst review required before acting.")
    print(divider)


def main():
    parser = argparse.ArgumentParser(
        description="LLM-assisted SIEM alert triage via Claude API"
    )
    parser.add_argument("--file", "-f", help="Path to alert JSON file (default: stdin)")
    parser.add_argument("--output", "-o", help="Write Markdown report to this file")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[ERROR] ANTHROPIC_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    source_label = args.file or "stdin"

    try:
        if args.file:
            raw = Path(args.file).read_text(encoding="utf-8")
        else:
            if sys.stdin.isatty():
                print("[INFO] Paste alert JSON, then press Ctrl-D:", file=sys.stderr)
            raw = sys.stdin.read()
        alert_data = json.loads(raw)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    print("[*] Sending alert to Claude for triage...", file=sys.stderr)
    result = triage(alert_data)
    print_report(result, source_label)

    if args.output:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md = (
            f"# Alert Triage Report\n\n"
            f"**Generated:** {ts}  \n"
            f"**Source:** {source_label}  \n"
            f"**Model:** {MODEL}\n\n"
            f"---\n\n"
            f"{result}\n\n"
            f"---\n\n"
            f"> LLM output — analyst review required before acting.\n"
        )
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"[OK] Report written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
