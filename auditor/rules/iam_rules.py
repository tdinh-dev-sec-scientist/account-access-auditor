"""IAM rules.

  IAM-001  Console-enabled user without MFA                  HIGH
  IAM-002  Active access key past the rotation threshold      MEDIUM / HIGH
  IAM-003  Dormant or disabled access key                     MEDIUM / LOW
  IAM-004  Policy allowing Action "*" on Resource "*"         CRITICAL
  IAM-005  Policy allowing service-wide wildcards on "*"      HIGH / LOW
  IAM-006  Programmatic-only user without MFA (inventory)     INFO

Pure functions: normalized IAM state in, Finding objects out. No boto3 import
appears anywhere in this module, which is what lets the whole rule set be
exercised offline against fixtures.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..models.finding import Finding
from ..severity import Severity
from .policy import analyze_permissions

SERVICE = "IAM"


def evaluate(data: dict[str, Any], config: dict[str, Any], run_id: str | None = None) -> list[Finding]:
    settings = (config or {}).get("iam", {})
    findings: list[Finding] = []

    for user in data.get("users", []) or []:
        findings.extend(_mfa_rules(user, settings, run_id))
        findings.extend(_access_key_rules(user, settings, run_id))

    if settings.get("check_wildcard_policies", True):
        findings.extend(_permission_rules(data, run_id))

    return findings


# --------------------------------------------------------------------- MFA --


def _mfa_rules(user: dict[str, Any], settings: dict[str, Any], run_id) -> list[Finding]:
    mfa_count = user.get("mfa_device_count")
    console = user.get("console_access_enabled")
    username = user.get("username")

    # Unknown state is not a finding. A denied GetLoginProfile or
    # ListMFADevices means "we could not tell", and guessing in either
    # direction produces either a false positive or a false sense of safety.
    if mfa_count is None or console is None:
        return []
    if mfa_count > 0:
        return []

    evidence = {
        "username": username,
        "user_arn": user.get("arn"),
        "console_access_enabled": console,
        "mfa_device_count": mfa_count,
        "password_last_used": user.get("password_last_used"),
    }

    if console and settings.get("require_mfa_for_console_users", True):
        return [
            Finding.build(
                "IAM-001",
                resource=f"user:{username}",
                description=(
                    f"IAM user '{username}' has a console login profile but no MFA device is "
                    "registered, so interactive sign-in is protected by a password alone."
                ),
                evidence=evidence,
                run_id=run_id,
            )
        ]

    if not console and settings.get("report_programmatic_users_without_mfa", True):
        return [
            Finding.build(
                "IAM-006",
                resource=f"user:{username}",
                description=(
                    f"IAM user '{username}' has no console login profile and no MFA device. "
                    "There is no interactive sign-in path to protect, so this is recorded "
                    "for inventory completeness rather than as an authentication weakness."
                ),
                evidence=evidence,
                run_id=run_id,
            )
        ]

    return []


# -------------------------------------------------------------- access keys --


def _access_key_rules(user: dict[str, Any], settings: dict[str, Any], run_id) -> list[Finding]:
    findings: list[Finding] = []
    max_age = settings.get("access_key_max_age_days", 90)
    critical_age = settings.get("access_key_critical_age_days", 180)
    unused_days = settings.get("access_key_unused_days", 45)
    username = user.get("username")

    for key in user.get("access_keys", []) or []:
        key_id = key.get("access_key_id")
        resource = f"user:{username}/{key_id}"
        age = key.get("age_days")
        status = key.get("status")

        base_evidence = {
            "username": username,
            "access_key_id": key_id,
            "status": status,
            "created": key.get("create_date"),
            "age_days": age,
            "last_used_date": key.get("last_used_date"),
            "last_used_days_ago": key.get("last_used_days_ago"),
            "last_used_service": key.get("last_used_service"),
        }

        if status == "Active" and age is not None and age > max_age:
            severity = Severity.HIGH if age > critical_age else Severity.MEDIUM
            findings.append(
                Finding.build(
                    "IAM-002",
                    severity=severity,
                    resource=resource,
                    description=(
                        f"Access key {key_id} for user '{username}' is {age} days old, above "
                        f"the configured rotation threshold of {max_age} days"
                        + (
                            f" and above the escalation threshold of {critical_age} days."
                            if severity is Severity.HIGH
                            else "."
                        )
                        + " Key age is credential metadata; it does not by itself indicate "
                        "that the key has been used or compromised."
                    ),
                    evidence={
                        **base_evidence,
                        "threshold_days": max_age,
                        "escalation_threshold_days": critical_age,
                    },
                    run_id=run_id,
                )
            )

        if status == "Inactive" and settings.get("inactive_key_check", True):
            findings.append(
                Finding.build(
                    "IAM-003",
                    severity=Severity.LOW,
                    title="Inactive IAM access key still present",
                    resource=resource,
                    description=(
                        f"Access key {key_id} for user '{username}' exists in an Inactive "
                        "state. It cannot currently authenticate, but it remains credential "
                        "material that a principal with iam:UpdateAccessKey can re-enable."
                    ),
                    evidence=base_evidence,
                    run_id=run_id,
                )
            )
            continue  # dormancy is meaningless for a key that is already disabled

        if status == "Active" and settings.get("dormant_key_check", True):
            finding = _dormancy_finding(user, key, base_evidence, resource, unused_days, run_id)
            if finding:
                findings.append(finding)

    return findings


def _dormancy_finding(user, key, base_evidence, resource, unused_days, run_id) -> Finding | None:
    """IAM-003 for an Active key that is not being used (CIS 1.12)."""
    username = user.get("username")
    key_id = key.get("access_key_id")
    age = key.get("age_days")
    last_used_days = key.get("last_used_days_ago")
    ever_used = key.get("last_used_date") is not None

    # Unknown last-used state (GetAccessKeyLastUsed denied) -> say nothing.
    if key.get("last_used_known") is False:
        return None

    if not ever_used:
        # A key created yesterday and not yet used is not dormant; only flag it
        # once it has had the full dormancy window to be used at all.
        if age is None or age <= unused_days:
            return None
        detail = (
            f"has never been used in {age} days since creation (GetAccessKeyLastUsed "
            "reports no last-used date)"
        )
    else:
        if last_used_days is None or last_used_days < unused_days:
            return None
        detail = f"was last used {last_used_days} days ago"

    return Finding.build(
        "IAM-003",
        severity=Severity.MEDIUM,
        title="Dormant IAM access key remains active",
        resource=resource,
        description=(
            f"Active access key {key_id} for user '{username}' {detail}, at or beyond the "
            f"{unused_days}-day dormancy threshold. An unused credential retains the full "
            "permissions of its user while producing no activity that would make its "
            "misuse noticeable."
        ),
        evidence={**base_evidence, "dormancy_threshold_days": unused_days, "ever_used": ever_used},
        run_id=run_id,
    )


# --------------------------------------------------------------- permissions --


def _principals(data: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Users, groups, and roles, each yielded with the policies attached to it.

    Group policies are evaluated once at the group, not once per member, so a
    single over-broad group policy produces one finding rather than one per
    user. The evidence names the members instead.
    """
    for user in data.get("users", []) or []:
        yield {
            "kind": "user",
            "name": user.get("username"),
            "arn": user.get("arn"),
            "policies": user.get("policies", []) or [],
            "context": {},
        }
    for group in data.get("groups", []) or []:
        yield {
            "kind": "group",
            "name": group.get("name"),
            "arn": group.get("arn"),
            "policies": group.get("policies", []) or [],
            "context": {"member_usernames": group.get("member_usernames", [])},
        }
    for role in data.get("roles", []) or []:
        yield {
            "kind": "role",
            "name": role.get("name"),
            "arn": role.get("arn"),
            "policies": role.get("policies", []) or [],
            "context": {"role_path": role.get("path")},
        }


def _permission_rules(data: dict[str, Any], run_id) -> list[Finding]:
    findings: list[Finding] = []

    for principal in _principals(data):
        for policy in principal["policies"]:
            document = policy.get("document")
            if not document:
                # A policy whose document could not be read is a collection
                # error, already recorded by the collector. Not a finding.
                continue

            analysis = analyze_permissions(document)
            policy_name = policy.get("name")
            resource = f"{principal['kind']}:{principal['name']}/{policy_name}"
            is_aws_managed = bool(policy.get("is_aws_managed"))
            base_evidence = {
                "principal_type": principal["kind"],
                "principal_name": principal["name"],
                "principal_arn": principal["arn"],
                "policy_name": policy_name,
                "policy_type": policy.get("type"),
                "policy_arn": policy.get("arn"),
                "policy_is_aws_managed": is_aws_managed,
                **principal["context"],
            }

            if analysis["admin_wildcard"]:
                findings.append(
                    Finding.build(
                        "IAM-004",
                        resource=resource,
                        description=(
                            f"The {policy.get('type')} policy '{policy_name}' attached to "
                            f"{principal['kind']} '{principal['name']}' contains an Allow "
                            'statement for Action "*" on all resources. The statement grants '
                            "every action against every resource in the account. This "
                            "reports the shape of the policy document; it does not evaluate "
                            "service control policies, permissions boundaries, or session "
                            "policies that may constrain the principal in practice."
                        ),
                        evidence={**base_evidence, "statements": analysis["admin_wildcard"]},
                        run_id=run_id,
                    )
                )
                # An admin grant supersedes any service-wide grant in the same
                # document: reporting both would double-count one problem.
                continue

            if analysis["service_wildcard"]:
                actions = sorted({a for s in analysis["service_wildcard"] for a in s["actions"]})
                # AWS-managed policies are a known, versioned, AWS-maintained set.
                # Their breadth is worth recording, but it is not a customer
                # misconfiguration in the way an inline "s3:*" grant is.
                severity = Severity.LOW if is_aws_managed else Severity.HIGH
                findings.append(
                    Finding.build(
                        "IAM-005",
                        severity=severity,
                        resource=resource,
                        description=(
                            f"The {policy.get('type')} policy '{policy_name}' attached to "
                            f"{principal['kind']} '{principal['name']}' allows service-wide "
                            f"wildcard actions ({', '.join(actions)}) on all resources."
                            + (
                                " The policy is AWS-managed, so its contents are maintained "
                                "by AWS and reviewable; it is recorded for permission-scope "
                                "review rather than as a misconfiguration."
                                if is_aws_managed
                                else " Whether that is excessive depends on the workload; the "
                                "scanner reports the policy shape, not an effective-"
                                "permissions verdict."
                            )
                        ),
                        evidence={**base_evidence, "statements": analysis["service_wildcard"]},
                        run_id=run_id,
                    )
                )

    return findings
