"""Builders for normalized AWS state.

These produce exactly what the collectors produce, so a rule cannot pass a test
against a shape that the collectors never emit. Every builder defaults to the
*clean* configuration, and each test names only the field it is exercising --
which keeps a case's intent visible in the case itself.

Nothing here imports boto3, and no test in this repository makes a network call.
"""

from __future__ import annotations

from typing import Any

ACCOUNT = "123456789012"  # AWS's documentation placeholder account.

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


def pab(**overrides: bool) -> dict[str, bool]:
    return {**ALL_PAB_ON, **overrides}


# ---------------------------------------------------------------------- IAM --


def iam_user(
    username: str = "test-user",
    console_access: bool | None = False,
    mfa_devices: int | None = 1,
    access_keys: list[dict[str, Any]] | None = None,
    policies: list[dict[str, Any]] | None = None,
    group_names: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "username": username,
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{username}",
        "user_id": "AIDAEXAMPLE",
        "path": "/",
        "create_date": "2024-01-01T00:00:00+00:00",
        "password_last_used": None,
        "console_access_enabled": console_access,
        "mfa_device_count": mfa_devices,
        "mfa_device_serials": [],
        "access_keys": access_keys or [],
        "policies": policies or [],
        "group_names": group_names or [],
        "collection_errors": [],
    }


def access_key(
    key_id: str = "AKIAEXAMPLE",
    status: str = "Active",
    age_days: int | None = 10,
    last_used_days_ago: int | None = 1,
    last_used_known: bool = True,
) -> dict[str, Any]:
    """One normalized access key.

    ``last_used_days_ago=None`` means the key has never been used, which is how
    AWS reports it (no LastUsedDate in the AccessKeyLastUsed object).
    """
    return {
        "access_key_id": key_id,
        "username": None,
        "status": status,
        "create_date": "2024-01-01T00:00:00+00:00",
        "age_days": age_days,
        "last_used_known": last_used_known,
        "last_used_date": None if last_used_days_ago is None else "2024-06-01T00:00:00+00:00",
        "last_used_days_ago": last_used_days_ago,
        "last_used_service": None if last_used_days_ago is None else "s3",
        "last_used_region": None if last_used_days_ago is None else "us-east-1",
    }


def policy(
    name: str = "inline-policy",
    statement: list[dict[str, Any]] | None = None,
    policy_type: str = "inline",
    aws_managed: bool = False,
    document: Any = "__build__",
) -> dict[str, Any]:
    if document == "__build__":
        document = {"Version": "2012-10-17", "Statement": statement or []}
    arn = (
        f"arn:aws:iam::aws:policy/{name}"
        if aws_managed
        else (f"arn:aws:iam::{ACCOUNT}:policy/{name}" if policy_type == "managed" else None)
    )
    return {
        "name": name,
        "arn": arn,
        "type": policy_type,
        "is_aws_managed": aws_managed,
        "document": document,
    }


def iam_group(name: str = "developers", policies=None, members=None) -> dict[str, Any]:
    return {
        "name": name,
        "arn": f"arn:aws:iam::{ACCOUNT}:group/{name}",
        "group_id": "AGPAEXAMPLE",
        "path": "/",
        "create_date": "2024-01-01T00:00:00+00:00",
        "policies": policies or [],
        "member_usernames": members or [],
        "collection_errors": [],
    }


def iam_role(name: str = "app-role", policies=None, path: str = "/") -> dict[str, Any]:
    return {
        "name": name,
        "arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
        "role_id": "AROAEXAMPLE",
        "path": path,
        "create_date": "2024-01-01T00:00:00+00:00",
        "max_session_duration": 3600,
        "trust_policy": None,
        "policies": policies or [],
        "collection_errors": [],
    }


def iam_state(users=None, groups=None, roles=None) -> dict[str, Any]:
    return {
        "users": users or [],
        "groups": groups or [],
        "roles": roles or [],
        "service_linked_roles_skipped": 0,
        "errors": [],
    }


# ----------------------------------------------------------------------- S3 --


def bucket(
    name: str = "test-bucket",
    public_access_block: Any = "__on__",
    public_access_block_known: bool = True,
    encryption_configured: bool = True,
    encryption_known: bool = True,
    bucket_policy: dict[str, Any] | None = None,
    acl_grants: list[dict[str, Any]] | None = None,
    policy_is_public: bool | None = None,
) -> dict[str, Any]:
    if public_access_block == "__on__":
        public_access_block = dict(ALL_PAB_ON)
    return {
        "name": name,
        "creation_date": "2024-01-01T00:00:00+00:00",
        "region": "us-east-1",
        "public_access_block": public_access_block,
        "public_access_block_known": public_access_block_known,
        "encryption": {
            "configured": encryption_configured,
            "known": encryption_known,
            "rules": [{"algorithm": "AES256", "kms_key_id": None, "bucket_key_enabled": False}]
            if encryption_configured
            else [],
        },
        "policy": bucket_policy,
        "policy_known": True,
        "policy_is_public": policy_is_public,
        "acl_grants": acl_grants or [],
        "acl_known": True,
        "collection_errors": [],
    }


def s3_state(*buckets: dict[str, Any]) -> dict[str, Any]:
    return {"buckets": list(buckets), "errors": [], "buckets_readable": True}


def public_acl_grant(group: str = "AllUsers", permission: str = "READ") -> dict[str, Any]:
    return {
        "type": "Group",
        "uri": f"http://acs.amazonaws.com/groups/global/{group}",
        "group": group,
        "display_name": None,
        "permission": permission,
    }


def private_acl_grant(permission: str = "FULL_CONTROL") -> dict[str, Any]:
    return {
        "type": "CanonicalUser",
        "uri": None,
        "group": None,
        "display_name": "bucket-owner",
        "permission": permission,
    }


def bucket_policy_doc(
    principal: Any = "*",
    action: Any = "s3:GetObject",
    resource: str = "arn:aws:s3:::test-bucket/*",
    effect: str = "Allow",
    condition: dict[str, Any] | None = None,
    sid: str = "Stmt",
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Sid": sid,
        "Effect": effect,
        "Principal": principal,
        "Action": action,
        "Resource": resource,
    }
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


# --------------------------------------------------------------- CloudTrail --


def trail(
    name: str = "management-trail",
    multi_region: bool = True,
    log_validation: bool = True,
    is_logging: bool | None = True,
    delivery_error: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "arn": f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/{name}",
        "home_region": "us-east-1",
        "is_multi_region": multi_region,
        "is_organization_trail": False,
        "include_global_service_events": True,
        "log_file_validation_enabled": log_validation,
        "s3_bucket_name": "audit-logs-bucket",
        "s3_key_prefix": None,
        "kms_key_id": None,
        "cloudwatch_logs_group_arn": None,
        "is_logging": is_logging,
        "logging_status_known": is_logging is not None,
        "latest_delivery_time": "2026-08-26T12:00:00+00:00",
        "latest_delivery_error": delivery_error,
        "collection_errors": [],
    }


def cloudtrail_state(*trails: dict[str, Any], readable: bool = True) -> dict[str, Any]:
    return {
        "trails": list(trails),
        "errors": [],
        "trails_readable": readable,
        "region": "us-east-1",
    }


# ------------------------------------------------------------------ helpers --


def rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


def by_rule(findings, rule_id: str):
    matches = [f for f in findings if f.rule_id == rule_id]
    assert matches, f"expected a {rule_id} finding, got {rule_ids(findings)}"
    return matches[0]
