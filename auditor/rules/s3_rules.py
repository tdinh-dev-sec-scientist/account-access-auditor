"""S3 rules.

  S3-001  Public Access Block not fully enabled        MEDIUM
  S3-002  Bucket ACL grants a global group             CRITICAL / LOW when ignored
  S3-003  Bucket policy allows an anonymous principal  CRITICAL / MEDIUM / LOW
  S3-004  No explicit bucket encryption configuration  MEDIUM

The severity ladder is the point of this module: a disabled Public Access Block
is a weakened control, an actual public grant is an exposure, and a public grant
that Public Access Block currently neutralises is a latent one. Collapsing those
into a single tier is what makes a scanner's output unactionable.
"""

from __future__ import annotations

from typing import Any

from ..models.finding import Finding
from ..severity import Severity
from .policy import public_principal_statements

SERVICE = "S3"

PAB_FLAGS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]


def evaluate(data: dict[str, Any], config: dict[str, Any], run_id: str | None = None) -> list[Finding]:
    settings = (config or {}).get("s3", {})
    findings: list[Finding] = []

    for bucket in data.get("buckets", []) or []:
        if settings.get("check_public_access", True):
            findings.extend(_public_access_block_rule(bucket, run_id))
            findings.extend(_acl_rule(bucket, run_id))
            findings.extend(_policy_rule(bucket, run_id))
        if settings.get("check_encryption", True):
            findings.extend(_encryption_rule(bucket, run_id))

    return findings


def _pab(bucket: dict[str, Any]) -> dict[str, bool]:
    """Effective Public Access Block flags.

    An absent configuration is not "unknown" -- S3 has no PAB configuration
    until one is created, and the effective behaviour is all four protections
    off. A denied GetPublicAccessBlock is a different thing and is recorded by
    the collector as an error, with ``public_access_block_known`` False.
    """
    config = bucket.get("public_access_block")
    if not isinstance(config, dict):
        return dict.fromkeys(PAB_FLAGS, False)
    return {flag: bool(config.get(flag, False)) for flag in PAB_FLAGS}


def _pab_known(bucket: dict[str, Any]) -> bool:
    return bucket.get("public_access_block_known", True) is not False


def _public_access_block_rule(bucket: dict[str, Any], run_id) -> list[Finding]:
    if not _pab_known(bucket):
        return []  # could not read it; do not assert it is off

    name = bucket["name"]
    pab = _pab(bucket)
    disabled = [flag for flag, enabled in pab.items() if not enabled]
    if not disabled:
        return []

    configured = isinstance(bucket.get("public_access_block"), dict)
    return [
        Finding.build(
            "S3-001",
            resource=name,
            description=(
                f"Bucket '{name}' "
                + (
                    "has no Public Access Block configuration, so all four protections are off."
                    if not configured
                    else f"has Public Access Block settings disabled: {', '.join(disabled)}."
                )
                + " This does not by itself mean the bucket is public; it means a public "
                "ACL or bucket policy would not be blocked if one were applied."
            ),
            evidence={
                "bucket": name,
                "public_access_block_configured": configured,
                "settings": pab,
                "disabled_settings": disabled,
            },
            run_id=run_id,
        )
    ]


def _acl_rule(bucket: dict[str, Any], run_id) -> list[Finding]:
    name = bucket["name"]
    public_grants = [g for g in bucket.get("acl_grants", []) or [] if g.get("group")]
    if not public_grants:
        return []

    pab = _pab(bucket)
    # Only IgnorePublicAcls neutralises an ACL that already exists;
    # BlockPublicAcls only prevents new ones from being set.
    ignored = _pab_known(bucket) and pab["IgnorePublicAcls"]
    groups = sorted({g["group"] for g in public_grants})
    permissions = sorted({g.get("permission") for g in public_grants if g.get("permission")})

    return [
        Finding.build(
            "S3-002",
            severity=Severity.LOW if ignored else Severity.CRITICAL,
            title=(
                "Bucket ACL grants public access (currently ignored by Public Access Block)"
                if ignored
                else "Bucket ACL grants public access"
            ),
            resource=name,
            description=(
                f"The ACL on bucket '{name}' grants {', '.join(permissions) or 'access'} to "
                f"the global group(s) {', '.join(groups)}. "
                + (
                    "IgnorePublicAcls is enabled, so the grants are not currently effective, "
                    "but they remain in the ACL and become effective the moment that setting "
                    "is turned off."
                    if ignored
                    else "IgnorePublicAcls is not enabled, so the grants are effective."
                )
                + (
                    " AuthenticatedUsers means any AWS account holder, not any principal in this account."
                    if "AuthenticatedUsers" in groups
                    else ""
                )
            ),
            evidence={
                "bucket": name,
                "grants": public_grants,
                "groups": groups,
                "ignore_public_acls": pab["IgnorePublicAcls"],
                "public_access_block_known": _pab_known(bucket),
            },
            run_id=run_id,
        )
    ]


def _policy_rule(bucket: dict[str, Any], run_id) -> list[Finding]:
    name = bucket["name"]
    statements = public_principal_statements(bucket.get("policy"))
    reported_public: bool | None = bucket.get("policy_is_public")

    # GetBucketPolicyStatus is authoritative when it is readable, so a True
    # there is reported even if the document itself could not be parsed.
    if not statements and not reported_public:
        return []

    pab = _pab(bucket)
    blocked = _pab_known(bucket) and (pab["BlockPublicPolicy"] or pab["RestrictPublicBuckets"])
    # A condition only downgrades the finding if it narrows *who* can call.
    # aws:SecureTransport requires HTTPS and constrains nobody.
    constrained = bool(statements) and all(s["is_effectively_constrained"] for s in statements)

    if blocked:
        severity = Severity.LOW
        note = (
            "Public access is currently blocked by the bucket's Public Access Block "
            "settings, but the statement remains in the policy and takes effect if those "
            "settings are removed."
        )
    elif constrained:
        severity = Severity.MEDIUM
        keys = sorted({k for s in statements for k in s["constraining_condition_keys"]})
        note = (
            f"Every public statement carries a narrowing condition ({', '.join(keys)}), so "
            "access may be limited to a specific network or organisation. The condition "
            "needs manual review; a scanner cannot tell whether the named range is trusted."
        )
    else:
        severity = Severity.CRITICAL
        unconstrained = [s for s in statements if not s["is_effectively_constrained"]]
        has_ineffective_condition = any(s["has_condition"] for s in unconstrained)
        note = "The statements grant access to anonymous callers" + (
            " with conditions that do not restrict who may call (for example "
            "aws:SecureTransport, which only requires HTTPS)."
            if has_ineffective_condition
            else " without any condition."
        )

    return [
        Finding.build(
            "S3-003",
            severity=severity,
            resource=name,
            description=(
                f"The bucket policy on '{name}' contains an Allow statement with an "
                f"anonymous principal. {note}"
            ),
            evidence={
                "bucket": name,
                "statements": statements,
                "get_bucket_policy_status_is_public": reported_public,
                "block_public_policy": pab["BlockPublicPolicy"],
                "restrict_public_buckets": pab["RestrictPublicBuckets"],
                "public_access_block_known": _pab_known(bucket),
            },
            run_id=run_id,
        )
    ]


def _encryption_rule(bucket: dict[str, Any], run_id) -> list[Finding]:
    encryption = bucket.get("encryption") or {}
    if encryption.get("configured"):
        return []
    if encryption.get("known") is False:
        return []  # GetBucketEncryption was denied; absence is not evidence

    name = bucket["name"]
    return [
        Finding.build(
            "S3-004",
            resource=name,
            description=(
                f"GetBucketEncryption returned no bucket-level default encryption "
                f"configuration for '{name}'. Amazon S3 has applied SSE-S3 to new objects "
                "by default since January 2023, so this records the absence of an "
                "explicit, auditable configuration rather than asserting that stored "
                "objects are unencrypted."
            ),
            evidence={"bucket": name, "encryption_configuration_present": False},
            run_id=run_id,
        )
    ]
