"""The rule registry: one declarative record per security rule.

Everything that is constant about a rule -- its title, the service it applies
to, the tiers it is allowed to emit, why it matters, and how to fix it -- lives
here rather than being repeated at each emission site. Rule modules supply only
what is dynamic: the resource, the chosen severity, the evidence, and a
description written from that evidence.

Two properties are enforced by the test suite:

* the registry contains exactly ``EXPECTED_RULE_COUNT`` rules;
* every emitted finding's severity is a member of that rule's ``severities``.

The second is what makes the five-tier model deterministic instead of a
convention: a rule physically cannot emit a tier it did not declare.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..compliance import compliance_block
from ..severity import Severity

EXPECTED_RULE_COUNT = 14

IAM = "IAM"
S3 = "S3"
CLOUDTRAIL = "CloudTrail"


@dataclass(frozen=True)
class RuleSpec:
    """Static metadata for one rule."""

    rule_id: str
    title: str
    service: str
    resource_type: str
    summary: str
    rationale: str
    remediation: str
    default_severity: Severity
    severities: tuple[Severity, ...]
    required_permissions: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.default_severity not in self.severities:
            raise ValueError(
                f"{self.rule_id}: default severity {self.default_severity} is not in "
                f"declared severities {[s.value for s in self.severities]}"
            )

    @property
    def compliance(self) -> dict[str, Any]:
        return compliance_block(self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "service": self.service,
            "resource_type": self.resource_type,
            "summary": self.summary,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "default_severity": self.default_severity.value,
            "severities": [s.value for s in self.severities],
            "required_permissions": list(self.required_permissions),
            "compliance": self.compliance,
        }


_SPECS: list[RuleSpec] = [
    # ---------------------------------------------------------------- IAM ---
    RuleSpec(
        rule_id="IAM-001",
        title="Console-enabled IAM user lacks MFA",
        service=IAM,
        resource_type="iam-user",
        summary="An IAM user has a console login profile but no registered MFA device.",
        rationale=(
            "Console sign-in for this user depends on a password alone, so a single "
            "credential disclosure -- phishing, reuse, or a leaked password store -- is "
            "sufficient to obtain an interactive session in the account."
        ),
        remediation=(
            "Register a virtual or hardware MFA device for the user, or delete the login "
            "profile if the identity only needs programmatic access."
        ),
        default_severity=Severity.HIGH,
        severities=(Severity.HIGH,),
        required_permissions=("iam:ListUsers", "iam:GetLoginProfile", "iam:ListMFADevices"),
    ),
    RuleSpec(
        rule_id="IAM-002",
        title="Active IAM access key exceeds maximum age",
        service=IAM,
        resource_type="iam-access-key",
        summary="An Active access key is older than the configured rotation threshold.",
        rationale=(
            "A long-lived static credential accumulates exposure: every backup, CI log, "
            "laptop, and container image it was ever copied into remains a live path into "
            "the account until the key is rotated."
        ),
        remediation=(
            "Create a replacement key, migrate dependent workloads, then deactivate and "
            "delete the superseded key. Prefer IAM roles or IAM Identity Center over "
            "long-lived user keys where the workload allows it."
        ),
        default_severity=Severity.MEDIUM,
        severities=(Severity.HIGH, Severity.MEDIUM),
        required_permissions=("iam:ListUsers", "iam:ListAccessKeys"),
    ),
    RuleSpec(
        rule_id="IAM-003",
        title="Dormant or disabled IAM access key",
        service=IAM,
        resource_type="iam-access-key",
        summary=(
            "An Active access key has never been used or has been unused beyond the "
            "dormancy threshold, or an Inactive key still exists."
        ),
        rationale=(
            "A credential nobody uses is a credential nobody is watching. Dormant keys "
            "carry the full permissions of their user while producing no signal that "
            "would make their misuse noticeable, and an Inactive key can be re-enabled "
            "by anyone who can call UpdateAccessKey."
        ),
        remediation=(
            "Delete the key. If the workload may still need it, deactivate it first and "
            "delete it once a full billing cycle passes with no access failures."
        ),
        default_severity=Severity.MEDIUM,
        severities=(Severity.MEDIUM, Severity.LOW),
        required_permissions=("iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"),
    ),
    RuleSpec(
        rule_id="IAM-004",
        title="IAM policy grants unrestricted actions on all resources",
        service=IAM,
        resource_type="iam-policy",
        summary='An attached policy contains an Allow statement for Action "*" on Resource "*".',
        rationale=(
            "The statement grants every action against every resource, including the IAM "
            "actions needed to grant further access and the CloudTrail actions needed to "
            "stop recording it. Compromise of any principal holding it is equivalent to "
            "compromise of the account."
        ),
        remediation=(
            "Replace the wildcard statement with the specific actions the workload calls, "
            "scoped to specific resource ARNs. Derive the action list from CloudTrail or "
            "IAM Access Analyzer policy generation rather than guessing."
        ),
        default_severity=Severity.CRITICAL,
        severities=(Severity.CRITICAL,),
        required_permissions=(
            "iam:ListAttachedUserPolicies",
            "iam:ListUserPolicies",
            "iam:GetUserPolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
        ),
    ),
    RuleSpec(
        rule_id="IAM-005",
        title="IAM policy grants service-wide permissions on all resources",
        service=IAM,
        resource_type="iam-policy",
        summary='An attached policy allows service-wide wildcard actions (e.g. "s3:*") on Resource "*".',
        rationale=(
            "Service-wide wildcards grant the destructive and permission-changing actions "
            "of a service alongside the read actions a workload actually needs -- s3:* "
            "includes s3:DeleteBucket and s3:PutBucketPolicy. Whether that is excessive "
            "depends on the workload, which is why this is reported for review rather "
            "than as an outright administrative grant."
        ),
        remediation=(
            "Enumerate the actions the workload calls and replace the wildcard, scoping "
            "Resource to specific ARNs where the service supports it."
        ),
        default_severity=Severity.HIGH,
        severities=(Severity.HIGH, Severity.LOW),
        required_permissions=(
            "iam:ListAttachedUserPolicies",
            "iam:ListUserPolicies",
            "iam:GetUserPolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
        ),
    ),
    RuleSpec(
        rule_id="IAM-006",
        title="IAM user without MFA (no console access configured)",
        service=IAM,
        resource_type="iam-user",
        summary="An IAM user has no console login profile and no MFA device.",
        rationale=(
            "There is no interactive sign-in path to protect, so this is not a console "
            "authentication weakness. It is recorded so the inventory of MFA-less "
            "identities is complete and so the finding reappears at a higher tier if a "
            "login profile is added later."
        ),
        remediation=(
            "No MFA action is required while the identity remains programmatic-only. "
            "Re-evaluate if console access is enabled."
        ),
        default_severity=Severity.INFO,
        severities=(Severity.INFO,),
        required_permissions=("iam:GetLoginProfile", "iam:ListMFADevices"),
    ),
    # ----------------------------------------------------------------- S3 ---
    RuleSpec(
        rule_id="S3-001",
        title="S3 Public Access Block is not fully enabled",
        service=S3,
        resource_type="s3-bucket",
        summary="One or more of the four bucket-level Block Public Access settings is off or absent.",
        rationale=(
            "Block Public Access is the backstop that makes a public ACL or bucket policy "
            "non-effective even when one is applied by mistake. With it off, a single "
            "careless PutBucketAcl call is enough to expose the bucket."
        ),
        remediation=(
            "Enable all four Block Public Access settings on the bucket, and enable the "
            "account-level block, unless the bucket is intentionally serving public content."
        ),
        default_severity=Severity.MEDIUM,
        severities=(Severity.MEDIUM,),
        required_permissions=("s3:ListAllMyBuckets", "s3:GetBucketPublicAccessBlock"),
    ),
    RuleSpec(
        rule_id="S3-002",
        title="Bucket ACL grants public access",
        service=S3,
        resource_type="s3-bucket",
        summary="The bucket ACL grants a global group (AllUsers or AuthenticatedUsers).",
        rationale=(
            "AllUsers means anonymous callers on the internet. AuthenticatedUsers is "
            "commonly misread as 'my account' but means any AWS account holder, so both "
            "grants place the bucket outside the account's trust boundary."
        ),
        remediation=(
            "Remove the global-group grants from the bucket ACL, then enable Block Public "
            "Access so the grant cannot be reintroduced."
        ),
        default_severity=Severity.CRITICAL,
        severities=(Severity.CRITICAL, Severity.LOW),
        required_permissions=("s3:GetBucketAcl", "s3:GetBucketPublicAccessBlock"),
    ),
    RuleSpec(
        rule_id="S3-003",
        title="Bucket policy grants access to a public principal",
        service=S3,
        resource_type="s3-bucket",
        summary='The bucket policy contains an Allow statement with Principal "*".',
        rationale=(
            "An anonymous Allow in the resource policy grants access without any "
            "authentication, independently of IAM. Conditions can narrow it, but they "
            "have to be read: an aws:SourceIp condition constrains access while an "
            "aws:SecureTransport condition does not."
        ),
        remediation=(
            "Scope the Principal to specific account or role ARNs. If the bucket must "
            "serve public content, front it with CloudFront and an origin access control "
            "rather than a public bucket policy."
        ),
        default_severity=Severity.CRITICAL,
        severities=(Severity.CRITICAL, Severity.MEDIUM, Severity.LOW),
        required_permissions=("s3:GetBucketPolicy", "s3:GetBucketPolicyStatus"),
    ),
    RuleSpec(
        rule_id="S3-004",
        title="No explicit bucket-level encryption configuration observed",
        service=S3,
        resource_type="s3-bucket",
        summary="GetBucketEncryption returned no bucket-level default encryption configuration.",
        rationale=(
            "S3 has applied SSE-S3 to new objects by default since January 2023, so this "
            "is an evidence and enforcement gap rather than plaintext storage: there is "
            "no configuration to audit, no way to require SSE-KMS, and no key policy "
            "boundary around the data."
        ),
        remediation=(
            "Set an explicit default encryption configuration (SSE-S3, or SSE-KMS with a "
            "customer-managed key where key-level access control or auditing is required)."
        ),
        default_severity=Severity.MEDIUM,
        severities=(Severity.MEDIUM,),
        required_permissions=("s3:GetEncryptionConfiguration",),
    ),
    # --------------------------------------------------------- CloudTrail ---
    RuleSpec(
        rule_id="CT-001",
        title="No CloudTrail trail configured",
        service=CLOUDTRAIL,
        resource_type="aws-account",
        summary="DescribeTrails succeeded and returned no trails.",
        rationale=(
            "Without a trail there is no durable record of management-plane activity. "
            "The CloudTrail Event history console view retains only 90 days and cannot be "
            "used as tamper-evident evidence, so an incident older than that is "
            "uninvestigable."
        ),
        remediation=(
            "Create a multi-region trail with log file validation enabled, delivering to "
            "a dedicated log bucket with Block Public Access on."
        ),
        default_severity=Severity.HIGH,
        severities=(Severity.HIGH,),
        required_permissions=("cloudtrail:DescribeTrails",),
    ),
    RuleSpec(
        rule_id="CT-002",
        title="No multi-region CloudTrail trail configured",
        service=CLOUDTRAIL,
        resource_type="aws-account",
        summary="Every configured trail is single-region.",
        rationale=(
            "Activity in unmonitored regions is not recorded. Attackers routinely operate "
            "in regions an organisation does not use precisely because logging and "
            "detection are usually configured only where workloads run."
        ),
        remediation=(
            "Convert an existing trail to multi-region (IsMultiRegionTrail with "
            "IncludeGlobalServiceEvents), or create a dedicated multi-region trail."
        ),
        default_severity=Severity.MEDIUM,
        severities=(Severity.MEDIUM,),
        required_permissions=("cloudtrail:DescribeTrails",),
    ),
    RuleSpec(
        rule_id="CT-003",
        title="CloudTrail log file validation is disabled",
        service=CLOUDTRAIL,
        resource_type="cloudtrail-trail",
        summary="LogFileValidationEnabled is false for this trail.",
        rationale=(
            "Without the signed digest files that validation produces, a deleted or "
            "modified log file cannot be distinguished from one that never existed, which "
            "removes the log's value as incident evidence."
        ),
        remediation="Enable log file validation on the trail (update-trail --enable-log-file-validation).",
        default_severity=Severity.MEDIUM,
        severities=(Severity.MEDIUM,),
        required_permissions=("cloudtrail:DescribeTrails",),
    ),
    RuleSpec(
        rule_id="CT-004",
        title="CloudTrail trail is not delivering logs",
        service=CLOUDTRAIL,
        resource_type="cloudtrail-trail",
        summary="The trail exists but is stopped, or reports a latest delivery error.",
        rationale=(
            "A configured trail is not the same as an operating one. A stopped trail or a "
            "failing delivery leaves the same gap as having no trail at all, while still "
            "appearing correctly configured in every configuration-only review."
        ),
        remediation=(
            "Start logging on the trail and investigate why it stopped. For delivery "
            "errors, check the destination bucket policy, the bucket's existence, and the "
            "KMS key policy if the trail is encrypted."
        ),
        default_severity=Severity.HIGH,
        severities=(Severity.HIGH,),
        required_permissions=("cloudtrail:GetTrailStatus",),
    ),
]

REGISTRY: dict[str, RuleSpec] = {spec.rule_id: spec for spec in _SPECS}

if len(REGISTRY) != len(_SPECS):  # pragma: no cover - guards a copy/paste mistake
    raise RuntimeError("Duplicate rule_id in the registry")


def get(rule_id: str) -> RuleSpec:
    try:
        return REGISTRY[rule_id]
    except KeyError as exc:
        raise KeyError(f"Unknown rule_id '{rule_id}'. Known rules: {', '.join(sorted(REGISTRY))}") from exc


def all_rules() -> list[RuleSpec]:
    return list(_SPECS)


def rule_ids() -> list[str]:
    return [spec.rule_id for spec in _SPECS]


def by_service(service: str | None = None) -> list[RuleSpec]:
    if service is None:
        return all_rules()
    wanted = service.strip().lower()
    return [spec for spec in _SPECS if spec.service.lower() == wanted]


def required_permissions() -> list[str]:
    """Every IAM action any rule depends on, deduplicated and sorted."""
    actions = {action for spec in _SPECS for action in spec.required_permissions}
    return sorted(actions)
