"""The lab manifest: every deliberately misconfigured resource, and why.

Each entry names the rule(s) it exists to trigger. That mapping is the source of
``expected_findings.json``, so the environment and the expectations cannot drift
apart -- adding a resource without saying what it should trigger is a manifest
error, not a silently unverified resource.

Every resource name starts with ``lab-`` so it is unmistakably test material.
No real credentials, account identifiers, or data appear anywhere: the emulated
account is AWS's documentation placeholder, 123456789012.
"""

from __future__ import annotations

from dataclasses import dataclass, field

LAB_PREFIX = "lab-"

# Policy documents used by the lab. These are the misconfigurations themselves.
ADMIN_STAR_STAR = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "FullAdmin", "Effect": "Allow", "Action": "*", "Resource": "*"}],
}

SERVICE_WIDE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "BroadServiceAccess", "Effect": "Allow", "Action": ["s3:*", "ec2:*"], "Resource": "*"},
    ],
}

IAM_WILDCARD = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "IamWide", "Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
}

SCOPED_LEAST_PRIVILEGE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReadOneBucket",
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::lab-clean-data/*",
        },
        # A Deny of everything must not be reported as an over-permission.
        {"Sid": "DenyEverythingElse", "Effect": "Deny", "Action": "iam:*", "Resource": "*"},
    ],
}


def public_read_policy(bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }
        ],
    }


def ip_conditioned_public_policy(bucket: str) -> dict:
    """Public principal, but genuinely narrowed to one network."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadFromOfficeRange",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                # TEST-NET-3, reserved for documentation (RFC 5737).
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            }
        ],
    }


def securetransport_only_policy(bucket: str) -> dict:
    """The trap case: a condition that constrains nothing about *who* can call.

    aws:SecureTransport only requires HTTPS. A scanner that downgrades any
    conditional public statement calls this bucket "needs review" when it is in
    fact open to the internet.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadOverTls",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}},
            }
        ],
    }


def cloudtrail_bucket_policy(bucket: str, account_id: str) -> dict:
    """The standard CloudTrail delivery policy.

    Included as a negative control: its principal is a *service*, not "*", and
    S3-003 must not report it as public.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }


ALL_PAB_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
ALL_PAB_OFF = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}
ONLY_IGNORE_ACLS = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}


@dataclass(frozen=True)
class Expectation:
    """One finding the lab is designed to produce."""

    rule_id: str
    resource: str
    severity: str
    why: str


@dataclass(frozen=True)
class LabResource:
    """One deliberately configured resource and the findings it should produce."""

    name: str
    kind: str
    intent: str
    expectations: tuple[Expectation, ...] = field(default_factory=tuple)
    negative_control: bool = False


# --------------------------------------------------------------------------
# Profile: "misconfigured" -- the primary lab account.
# --------------------------------------------------------------------------

MISCONFIGURED: tuple[LabResource, ...] = (
    # ------------------------------------------------------------- IAM ---
    LabResource(
        name="lab-admin-console-nomfa",
        kind="iam-user",
        intent="Console login profile, no MFA device, inline policy allowing * on *.",
        expectations=(
            Expectation(
                "IAM-001",
                "user:lab-admin-console-nomfa",
                "HIGH",
                "Login profile present with zero MFA devices.",
            ),
            Expectation(
                "IAM-004",
                "user:lab-admin-console-nomfa/lab-full-admin",
                "CRITICAL",
                'Inline policy with Action "*" on Resource "*".',
            ),
        ),
    ),
    LabResource(
        name="lab-svc-stale-keys",
        kind="iam-user",
        intent="Programmatic-only identity with an access key aged past the escalation "
        "threshold that has never been used.",
        expectations=(
            Expectation(
                "IAM-006",
                "user:lab-svc-stale-keys",
                "INFO",
                "No login profile and no MFA: inventory record, not a console weakness.",
            ),
            Expectation(
                "IAM-002",
                "user:lab-svc-stale-keys/<key>",
                "HIGH",
                "Active key aged 400 days, past the 180-day escalation threshold.",
            ),
            Expectation(
                "IAM-003",
                "user:lab-svc-stale-keys/<key>",
                "MEDIUM",
                "Active key never used in 400 days, past the 45-day dormancy threshold.",
            ),
        ),
    ),
    LabResource(
        name="lab-svc-rotating",
        kind="iam-user",
        intent="Programmatic identity whose key is overdue for rotation but actively used, "
        "so IAM-002 fires at MEDIUM and IAM-003 must not fire at all.",
        expectations=(
            Expectation("IAM-006", "user:lab-svc-rotating", "INFO", "No login profile and no MFA."),
            Expectation(
                "IAM-002",
                "user:lab-svc-rotating/<key>",
                "MEDIUM",
                "Active key aged 120 days: past 90, below the 180-day escalation.",
            ),
        ),
    ),
    LabResource(
        name="lab-contractor-offboarded",
        kind="iam-user",
        intent="Console user WITH MFA (so IAM-001 must stay silent) holding a leftover Inactive access key.",
        expectations=(
            Expectation(
                "IAM-003",
                "user:lab-contractor-offboarded/<key>",
                "LOW",
                "Inactive key still present; residual credential material.",
            ),
        ),
    ),
    LabResource(
        name="lab-clean-user",
        kind="iam-user",
        intent="Negative control: console access with MFA, no keys, a scoped inline policy "
        "containing a Deny that must not be read as a grant.",
        negative_control=True,
    ),
    LabResource(
        name="lab-developers",
        kind="iam-group",
        intent="Group carrying a customer-managed policy with service-wide wildcards, to "
        "prove group-inherited permissions are inspected and reported once at the "
        "group rather than once per member.",
        expectations=(
            Expectation(
                "IAM-005",
                "group:lab-developers/lab-broad-service-access",
                "HIGH",
                's3:* and ec2:* on Resource "*" in a customer-managed policy.',
            ),
        ),
    ),
    LabResource(
        name="lab-ci-deploy-role",
        kind="iam-role",
        intent="Role with an inline iam:* policy, to prove role policies are inspected.",
        expectations=(
            Expectation(
                "IAM-005",
                "role:lab-ci-deploy-role/lab-iam-wildcard",
                "HIGH",
                'iam:* on Resource "*" in an inline role policy.',
            ),
        ),
    ),
    LabResource(
        name="lab-readonly-role",
        kind="iam-role",
        intent="Negative control: role with a scoped, least-privilege inline policy.",
        negative_control=True,
    ),
    # -------------------------------------------------------------- S3 ---
    LabResource(
        name="lab-public-assets",
        kind="s3-bucket",
        intent="The worst case: no Public Access Block, public-read ACL, unconditional "
        "public bucket policy, no encryption configuration.",
        expectations=(
            Expectation("S3-001", "lab-public-assets", "MEDIUM", "No PAB configuration at all."),
            Expectation(
                "S3-002", "lab-public-assets", "CRITICAL", "AllUsers ACL grant with IgnorePublicAcls off."
            ),
            Expectation(
                "S3-003",
                "lab-public-assets",
                "CRITICAL",
                'Unconditional Principal "*" Allow with nothing blocking it.',
            ),
            Expectation(
                "S3-004", "lab-public-assets", "MEDIUM", "No explicit default encryption configuration."
            ),
        ),
    ),
    LabResource(
        name="lab-partner-share",
        kind="s3-bucket",
        intent="Public principal genuinely narrowed by an aws:SourceIp condition: the "
        "finding must be MEDIUM for review, not CRITICAL.",
        expectations=(
            Expectation("S3-001", "lab-partner-share", "MEDIUM", "PAB fully disabled."),
            Expectation(
                "S3-003", "lab-partner-share", "MEDIUM", "Public statement narrowed by aws:SourceIp."
            ),
        ),
    ),
    LabResource(
        name="lab-tls-only-public",
        kind="s3-bucket",
        intent="The false-negative trap: public principal with only an aws:SecureTransport "
        "condition. HTTPS is not an access restriction, so this must stay CRITICAL.",
        expectations=(
            Expectation("S3-001", "lab-tls-only-public", "MEDIUM", "PAB fully disabled."),
            Expectation(
                "S3-003",
                "lab-tls-only-public",
                "CRITICAL",
                "The only condition (aws:SecureTransport) constrains nobody.",
            ),
        ),
    ),
    LabResource(
        name="lab-latent-acl",
        kind="s3-bucket",
        intent="Public ACL that IgnorePublicAcls currently neutralises: a latent exposure, "
        "reported at LOW rather than dropped or reported as CRITICAL.",
        expectations=(
            Expectation("S3-001", "lab-latent-acl", "MEDIUM", "Three of the four PAB settings are off."),
            Expectation(
                "S3-002", "lab-latent-acl", "LOW", "AllUsers grant present but ignored by IgnorePublicAcls."
            ),
        ),
    ),
    LabResource(
        name="lab-blocked-public-policy",
        kind="s3-bucket",
        intent="Public bucket policy with all four PAB settings on: blocked today, live the "
        "moment PAB is removed. LOW, and not silent.",
        expectations=(
            Expectation(
                "S3-003",
                "lab-blocked-public-policy",
                "LOW",
                "Public statement neutralised by BlockPublicPolicy.",
            ),
        ),
    ),
    LabResource(
        name="lab-unencrypted-logs",
        kind="s3-bucket",
        intent="Correct public-access posture, but no explicit encryption configuration: "
        "isolates S3-004 from every other S3 rule.",
        expectations=(
            Expectation(
                "S3-004", "lab-unencrypted-logs", "MEDIUM", "No explicit default encryption configuration."
            ),
        ),
    ),
    LabResource(
        name="lab-clean-data",
        kind="s3-bucket",
        intent="Negative control: all four PAB settings on, explicit SSE-S3, no policy, "
        "private ACL. Must produce zero findings.",
        negative_control=True,
    ),
    LabResource(
        name="lab-trail-logs",
        kind="s3-bucket",
        intent="Negative control: CloudTrail delivery bucket whose policy has a *Service* "
        "principal. S3-003 must not mistake a service principal for a public one.",
        negative_control=True,
    ),
    # ------------------------------------------------------ CloudTrail ---
    LabResource(
        name="lab-single-region-trail",
        kind="cloudtrail-trail",
        intent="Single-region trail with log file validation disabled, created but never "
        "started: exercises the account-level and per-trail CloudTrail rules at once.",
        expectations=(
            Expectation("CT-002", "aws-account", "MEDIUM", "The only trail is single-region."),
            Expectation("CT-003", "lab-single-region-trail", "MEDIUM", "LogFileValidationEnabled is false."),
            Expectation(
                "CT-004", "lab-single-region-trail", "HIGH", "GetTrailStatus reports IsLogging false."
            ),
        ),
    ),
)

# --------------------------------------------------------------------------
# Profile: "no-trail" -- a second, minimal account.
#
# CT-001 ("no trail configured") cannot coexist with CT-002/003/004, which all
# require a trail to exist. Rather than leave a rule unverified against a live
# API, the lab provisions a second account containing no trail at all.
# --------------------------------------------------------------------------

NO_TRAIL: tuple[LabResource, ...] = (
    LabResource(
        name="lab-notrail-data",
        kind="s3-bucket",
        intent="Negative control so the profile is not empty: fully locked-down bucket.",
        negative_control=True,
    ),
    LabResource(
        name="aws-account",
        kind="cloudtrail-trail",
        intent="No trail is created at all, which is the only way CT-001 can fire.",
        expectations=(
            Expectation(
                "CT-001", "aws-account", "HIGH", "DescribeTrails succeeded and returned zero trails."
            ),
        ),
    ),
)

PROFILES: dict[str, tuple[LabResource, ...]] = {
    "misconfigured": MISCONFIGURED,
    "no-trail": NO_TRAIL,
}


def expectations_for(profile: str) -> list[Expectation]:
    return [e for resource in PROFILES[profile] for e in resource.expectations]


def negative_controls(profile: str) -> list[LabResource]:
    return [r for r in PROFILES[profile] if r.negative_control]
