"""Generate the committed sample outputs from synthetic data.

Runs no AWS call and needs no credentials. The findings below are hand-built to
show every output format and every severity tier; the account is AWS's
documentation placeholder.

    python examples/generate_sample.py

For real, measured output from the deliberately misconfigured test environment,
see `results/` and `python -m lab.run_benchmark` instead.
"""

from __future__ import annotations

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from auditor import __version__  # noqa: E402
from auditor.models.finding import Finding  # noqa: E402
from auditor.models.report import build_report  # noqa: E402
from auditor.reporters import csv_reporter, json_reporter, ticket  # noqa: E402
from auditor.severity import Severity  # noqa: E402

STAMP = "2026-01-15T09:00:00+00:00"
ACCOUNT = "123456789012"  # AWS documentation placeholder


def findings():
    return [
        Finding.build(
            "IAM-004",
            "user:example-deploy/example-deploy-inline",
            'The inline policy "example-deploy-inline" attached to user "example-deploy" '
            'contains an Allow statement for Action "*" on all resources.',
            {
                "principal_type": "user",
                "principal_name": "example-deploy",
                "policy_name": "example-deploy-inline",
                "policy_type": "inline",
                "statements": [{"sid": "FullAdmin", "actions": ["*"], "resource_scope": "*"}],
            },
            detected_at=STAMP,
        ),
        Finding.build(
            "S3-003",
            "example-public-assets",
            "The bucket policy on 'example-public-assets' contains an Allow statement with "
            "an anonymous principal. The statements grant access to anonymous callers "
            "without any condition.",
            {
                "bucket": "example-public-assets",
                "statements": [{"sid": "PublicRead", "actions": ["s3:GetObject"],
                                "is_effectively_constrained": False}],
                "get_bucket_policy_status_is_public": True,
            },
            detected_at=STAMP,
        ),
        Finding.build(
            "CT-004",
            "example-management-trail",
            "Trail 'example-management-trail' is configured but GetTrailStatus reports that "
            "logging is stopped.",
            {"trail": "example-management-trail", "is_logging": False},
            title="CloudTrail trail exists but is not currently logging",
            detected_at=STAMP,
        ),
        Finding.build(
            "IAM-002",
            "user:example-service/AKIA…MPLE",
            "Access key AKIA…MPLE for user 'example-service' is 214 days old, above the "
            "configured rotation threshold of 90 days and above the escalation threshold "
            "of 180 days.",
            {"username": "example-service", "age_days": 214, "threshold_days": 90},
            severity=Severity.HIGH,
            detected_at=STAMP,
        ),
        Finding.build(
            "S3-001",
            "example-reports",
            "Bucket 'example-reports' has no Public Access Block configuration, so all four "
            "protections are off.",
            {"bucket": "example-reports", "public_access_block_configured": False},
            detected_at=STAMP,
        ),
        Finding.build(
            "S3-002",
            "example-legacy-static",
            "The ACL on bucket 'example-legacy-static' grants READ to the global group(s) "
            "AllUsers. IgnorePublicAcls is enabled, so the grants are not currently "
            "effective, but they remain in the ACL.",
            {"bucket": "example-legacy-static", "ignore_public_acls": True},
            severity=Severity.LOW,
            title="Bucket ACL grants public access (currently ignored by Public Access Block)",
            detected_at=STAMP,
        ),
        Finding.build(
            "IAM-006",
            "user:example-ci",
            "IAM user 'example-ci' has no console login profile and no MFA device.",
            {"username": "example-ci", "console_access_enabled": False, "mfa_device_count": 0},
            detected_at=STAMP,
        ),
    ]


def main() -> int:
    report = build_report(
        account_id=ACCOUNT,
        region="us-east-1",
        findings=findings(),
        collection_errors=[{
            "service": "S3", "operation": "s3:GetBucketAcl", "resource": "example-restricted",
            "code": "AccessDenied", "category": "access_denied",
            "message": "An error occurred (AccessDenied) when calling the GetBucketAcl operation",
            "required_permissions": ["s3:GetBucketAcl"],
        }],
        services_scanned=["IAM", "S3", "CloudTrail"],
        tool_version=__version__,
        run_id="example00run0",
        resource_counts={"iam_users": 6, "s3_buckets": 5, "cloudtrail_trails": 1},
        duration_seconds=2.418,
        api_call_count=57,
        environment_label="synthetic example (no AWS account was contacted)",
    )

    here = os.path.dirname(os.path.abspath(__file__))
    json_reporter.write(report, os.path.join(here, "sample_report.json"))
    csv_reporter.write(report, os.path.join(here, "sample_report.csv"))
    ticket.write(report, os.path.join(here, "sample_tickets.txt"))
    print("Wrote examples/sample_report.json, sample_report.csv, sample_tickets.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
