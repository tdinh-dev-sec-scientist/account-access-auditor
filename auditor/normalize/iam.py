"""Normalize raw IAM responses into the internal model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..utils.dates import age_in_days, isoformat

AWS_MANAGED_POLICY_PREFIX = "arn:aws:iam::aws:policy/"
SERVICE_LINKED_ROLE_PATH = "/aws-service-role/"


def user_identity(raw: dict[str, Any]) -> dict[str, Any]:
    """The skeleton of a normalized user, before per-user calls fill it in.

    ``None`` for ``console_access_enabled`` and ``mfa_device_count`` means
    "could not determine". Rules must not read that as False -- it is the
    difference between "this user has no MFA" and "we were not allowed to look".
    """
    return {
        "username": raw.get("UserName"),
        "arn": raw.get("Arn"),
        "user_id": raw.get("UserId"),
        "path": raw.get("Path"),
        "create_date": isoformat(raw.get("CreateDate")),
        "password_last_used": isoformat(raw.get("PasswordLastUsed")),
        "console_access_enabled": None,
        "mfa_device_count": None,
        "mfa_device_serials": [],
        "access_keys": [],
        "policies": [],
        "group_names": [],
        "collection_errors": [],
    }


def mfa_devices(response: dict[str, Any] | None) -> dict[str, Any]:
    devices = (response or {}).get("MFADevices", []) or []
    return {
        "mfa_device_count": len(devices),
        "mfa_device_serials": [d.get("SerialNumber") for d in devices],
    }


def access_key(
    metadata: dict[str, Any],
    last_used: dict[str, Any] | None = None,
    last_used_known: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    """One access key, combining ListAccessKeys metadata with GetAccessKeyLastUsed.

    AWS signals "never used" by omitting ``LastUsedDate`` from the
    ``AccessKeyLastUsed`` object (ServiceName and Region come back as the
    literal string "N/A"), which is why absence is treated as never-used rather
    than as an error.
    """
    created = metadata.get("CreateDate")
    used_block = (last_used or {}).get("AccessKeyLastUsed", {}) or {}
    used_date = used_block.get("LastUsedDate")
    service_name = used_block.get("ServiceName")

    return {
        "access_key_id": metadata.get("AccessKeyId"),
        "username": metadata.get("UserName"),
        "status": metadata.get("Status"),
        "create_date": isoformat(created),
        "age_days": age_in_days(created, now),
        "last_used_known": last_used_known,
        "last_used_date": isoformat(used_date),
        "last_used_days_ago": age_in_days(used_date, now),
        "last_used_service": None if service_name in (None, "N/A") else service_name,
        "last_used_region": used_block.get("Region") if used_block.get("Region") != "N/A" else None,
    }


def is_aws_managed(policy_arn: str | None) -> bool:
    return bool(policy_arn) and policy_arn.startswith(AWS_MANAGED_POLICY_PREFIX)


def policy_record(
    name: str | None,
    document: dict[str, Any] | None,
    policy_type: str,
    arn: str | None = None,
) -> dict[str, Any]:
    """One attached or inline policy.

    ``document`` is None when the document could not be read; the rules skip
    those rather than treating an unreadable policy as a clean one.
    """
    return {
        "name": name,
        "arn": arn,
        "type": policy_type,
        "is_aws_managed": is_aws_managed(arn),
        "document": document,
    }


def managed_policy_document(
    policy_response: dict[str, Any] | None,
    version_response: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Extract the default version's document. Boto3 already URL-decodes it."""
    if not version_response:
        return None
    document = (version_response.get("PolicyVersion") or {}).get("Document")
    return document if isinstance(document, dict) else None


def group_record(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": raw.get("GroupName"),
        "arn": raw.get("Arn"),
        "group_id": raw.get("GroupId"),
        "path": raw.get("Path"),
        "create_date": isoformat(raw.get("CreateDate")),
        "policies": [],
        "member_usernames": [],
        "collection_errors": [],
    }


def is_service_linked_role(raw: dict[str, Any]) -> bool:
    """Service-linked roles are created and controlled by AWS services.

    Their policies are AWS-defined and cannot be edited, so flagging their
    breadth would be noise the operator cannot act on. They are skipped, and the
    collector records how many were skipped so the omission is visible.
    """
    return (raw.get("Path") or "").startswith(SERVICE_LINKED_ROLE_PATH)


def role_record(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": raw.get("RoleName"),
        "arn": raw.get("Arn"),
        "role_id": raw.get("RoleId"),
        "path": raw.get("Path"),
        "create_date": isoformat(raw.get("CreateDate")),
        "max_session_duration": raw.get("MaxSessionDuration"),
        "trust_policy": raw.get("AssumeRolePolicyDocument"),
        "policies": [],
        "collection_errors": [],
    }


def group_names(response: dict[str, Any] | None) -> list[str]:
    return [g.get("GroupName") for g in (response or {}).get("Groups", []) or []]
