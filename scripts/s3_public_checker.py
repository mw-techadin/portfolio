#!/usr/bin/env python3
"""
s3_public_checker.py
--------------------
Audits all S3 buckets in the configured AWS account for public
exposure vectors:
  - PublicAccessBlock settings (all four flags must be True)
  - Bucket ACL grants with public URIs
  - Bucket policy with wide-open principal ('*')

Requirements:
    pip install boto3

Usage:
    AWS_PROFILE=myprofile python3 s3_public_checker.py
    python3 s3_public_checker.py --region us-east-1 --output json
"""

from __future__ import annotations

import json
import sys
import argparse
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


PUBLIC_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def get_s3_client(region: str | None = None):
    try:
        return boto3.client("s3", region_name=region)
    except NoCredentialsError:
        print("[ERROR] AWS credentials not configured.", file=sys.stderr)
        sys.exit(1)


def check_public_access_block(client, bucket: str) -> dict:
    """Return PublicAccessBlock configuration for a bucket."""
    try:
        resp   = client.get_public_access_block(Bucket=bucket)
        config = resp["PublicAccessBlockConfiguration"]
        all_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])
        return {"enabled": all_blocked, "config": config}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            return {"enabled": False, "config": {}, "note": "No block config set"}
        return {"enabled": False, "config": {}, "error": str(e)}


def check_acl(client, bucket: str) -> dict:
    """Check if bucket ACL grants public access."""
    try:
        resp   = client.get_bucket_acl(Bucket=bucket)
        grants = resp.get("Grants", [])
        public_grants = [
            g for g in grants
            if g.get("Grantee", {}).get("URI") in PUBLIC_URIS
        ]
        return {"public": bool(public_grants), "grants": public_grants}
    except ClientError as e:
        return {"public": False, "error": str(e)}


def check_policy(client, bucket: str) -> dict:
    """Check if bucket policy allows public access."""
    try:
        resp   = client.get_bucket_policy(Bucket=bucket)
        policy = json.loads(resp["Policy"])
        for stmt in policy.get("Statement", []):
            effect    = stmt.get("Effect", "")
            principal = stmt.get("Principal", "")
            if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                return {"public": True, "statement": stmt}
        return {"public": False}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchBucketPolicy":
            return {"public": False, "note": "No policy attached"}
        return {"public": False, "error": str(e)}


def audit_buckets(region: str | None = None) -> list[dict]:
    client  = get_s3_client(region)
    results = []

    try:
        buckets = client.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"[ERROR] Cannot list buckets: {e}", file=sys.stderr)
        sys.exit(1)

    for bucket in buckets:
        name = bucket["Name"]
        pab  = check_public_access_block(client, name)
        acl  = check_acl(client, name)
        pol  = check_policy(client, name)

        is_risky = (not pab["enabled"]) or acl["public"] or pol["public"]

        results.append({
            "bucket":              name,
            "at_risk":             is_risky,
            "public_access_block": pab,
            "acl_public":          acl["public"],
            "policy_public":       pol["public"],
        })

    return results


def print_text_report(results: list[dict]) -> None:
    risky   = [r for r in results if r["at_risk"]]
    ok      = [r for r in results if not r["at_risk"]]
    divider = "=" * 60

    print(divider)
    print("  S3 Public Bucket Audit Report")
    print(divider)
    print(f"  Total buckets : {len(results)}")
    print(f"  At risk       : {len(risky)}")
    print(f"  Clean         : {len(ok)}")
    print()

    if risky:
        print(f"  [!] RISKY BUCKETS ({len(risky)} found)")
        print("-" * 60)
        for r in risky:
            flags = []
            if not r["public_access_block"]["enabled"]:
                flags.append("PublicAccessBlock disabled")
            if r["acl_public"]:
                flags.append("ACL grants public access")
            if r["policy_public"]:
                flags.append("Policy allows public principal")
            print(f"  {r['bucket']}")
            for f in flags:
                print(f"    → {f}")
            print()
    else:
        print("  [OK] All buckets have public access blocked.")

    print(divider)


def main():
    parser = argparse.ArgumentParser(description="Audit S3 buckets for public exposure")
    parser.add_argument("--region", default=None, help="AWS region (default: from profile)")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format")
    args = parser.parse_args()

    results = audit_buckets(args.region)

    if args.output == "json":
        print(json.dumps(results, indent=2))
    else:
        print_text_report(results)

    risky = [r for r in results if r["at_risk"]]
    sys.exit(1 if risky else 0)


if __name__ == "__main__":
    main()
