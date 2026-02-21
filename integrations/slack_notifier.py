#!/usr/bin/env python3
"""
slack_notifier.py
-----------------
Reusable Slack webhook alert helper for security automation pipelines.
Sends structured notifications to a Slack channel via Incoming Webhooks.

Requirements:
    pip install requests

Environment variables:
    SLACK_WEBHOOK_URL — Slack Incoming Webhook URL

Usage as a module:
    from integrations.slack_notifier import SlackNotifier

    notifier = SlackNotifier()
    notifier.send_alert(
        title="S3 Public Bucket Detected",
        message="Bucket 'my-bucket' has public ACL enabled.",
        severity="HIGH",
        fields={"Bucket": "my-bucket", "Account": "123456789"},
    )

Usage as a CLI:
    python3 slack_notifier.py --title "Test Alert" --message "Hello from security pipeline" --severity HIGH
    SLACK_WEBHOOK_URL=https://hooks.slack.com/... python3 slack_notifier.py --title "Test" --message "msg"
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH":     "#FF6600",
    "MEDIUM":   "#FFB800",
    "LOW":      "#36A64F",
    "INFO":     "#2196F3",
}

SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH":     ":warning:",
    "MEDIUM":   ":large_yellow_circle:",
    "LOW":      ":information_source:",
    "INFO":     ":bell:",
}


class SlackNotifier:
    """Send security alerts to Slack via Incoming Webhooks."""

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
        if not self.webhook_url:
            raise ValueError(
                "Slack webhook URL is required. Set SLACK_WEBHOOK_URL env var "
                "or pass webhook_url to SlackNotifier()."
            )

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "INFO",
        fields: dict | None = None,
        source: str = "Security Automation",
        link: str | None = None,
    ) -> bool:
        """
        Send a formatted security alert to Slack.

        Returns True on success, False on failure.
        """
        severity  = severity.upper()
        color     = SEVERITY_COLORS.get(severity, "#808080")
        emoji     = SEVERITY_EMOJI.get(severity, ":bell:")
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        attachment: dict = {
            "color":    color,
            "fallback": f"[{severity}] {title}: {message}",
            "title":    f"{emoji} [{severity}] {title}",
            "text":     message,
            "footer":   f"{source}  |  {timestamp}",
            "fields":   [],
        }

        if fields:
            for key, value in fields.items():
                attachment["fields"].append({
                    "title": str(key),
                    "value": str(value),
                    "short": len(str(value)) < 40,
                })

        if link:
            attachment["title_link"] = link

        payload = {"attachments": [attachment]}

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200 and resp.text == "ok":
                return True
            else:
                print(
                    f"[ERROR] Slack returned {resp.status_code}: {resp.text}",
                    file=sys.stderr
                )
                return False
        except requests.RequestException as e:
            print(f"[ERROR] Failed to send Slack notification: {e}", file=sys.stderr)
            return False

    def send_raw(self, payload: dict) -> bool:
        """Send a raw Slack Block Kit payload."""
        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return False


def main():
    parser = argparse.ArgumentParser(description="Send a Slack security alert")
    parser.add_argument("--title",    required=True, help="Alert title")
    parser.add_argument("--message",  required=True, help="Alert body text")
    parser.add_argument("--severity", default="INFO",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Severity level (default: INFO)")
    parser.add_argument("--source",   default="Security Automation",
                        help="Source system label")
    parser.add_argument("--link",     default=None, help="Optional URL to attach")
    parser.add_argument("--field",    action="append", metavar="KEY=VALUE",
                        help="Extra fields (repeatable). E.g. --field Host=10.0.0.1")
    args = parser.parse_args()

    fields: dict = {}
    for kv in (args.field or []):
        if "=" in kv:
            k, v = kv.split("=", 1)
            fields[k] = v

    try:
        notifier = SlackNotifier()
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    success = notifier.send_alert(
        title=args.title,
        message=args.message,
        severity=args.severity,
        fields=fields or None,
        source=args.source,
        link=args.link,
    )

    if success:
        print("[OK] Alert sent to Slack.")
        sys.exit(0)
    else:
        print("[FAIL] Could not send alert.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
