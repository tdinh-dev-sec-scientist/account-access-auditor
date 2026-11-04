#!/usr/bin/env python3
"""Capture exact Phase 3 Terraform role policies with a non-root read profile."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phase3.role_capture import RoleCaptureError, capture_role_evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--profile", required=True, help="Named non-root AWS profile with read-only IAM policy access")
    parser.add_argument("--stack", choices=("org", "control-plane"), required=True)
    parser.add_argument("--phase", choices=("plan", "apply"), required=True)
    parser.add_argument("--role-arn", required=True, help="Exact role ARN from the protected workflow environment")
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile)
        identity = session.client("sts").get_caller_identity()
        identity_arn = identity.get("Arn", "")
        identity_account = identity.get("Account", "")
        role_account = args.role_arn.split(":")[4] if args.role_arn.count(":") >= 5 else ""
        if identity_arn.endswith(":root"):
            raise RoleCaptureError("Root credentials are not accepted; use a named non-root read-only profile")
        if not identity_account or identity_account != role_account:
            raise RoleCaptureError("The read-only profile and requested role must belong to the same AWS account")
        digests = capture_role_evidence(
            root=args.root,
            stack=args.stack,
            phase=args.phase,
            role_arn=args.role_arn,
            iam_client=session.client("iam"),
        )
    except RoleCaptureError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "ClientError")
        print(f"AWS read-only capture failed ({error_code}).", file=sys.stderr)
        return 1
    except BotoCoreError as exc:
        print(f"AWS profile or read-only capture failed ({type(exc).__name__}).", file=sys.stderr)
        return 1

    for path, digest in sorted(digests["source_evidence_sha256"].items()):
        print(f"private-source {path}  sha256:{digest}")
    for path, digest in sorted(digests["evidence_sha256"].items()):
        print(f"redacted-evidence {path}  sha256:{digest}")
    print("Raw captures are gitignored. The role-scope manifest was not changed or approved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
