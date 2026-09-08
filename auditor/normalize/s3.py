"""Normalize raw S3 responses into the internal model."""

from __future__ import annotations

import json
from typing import Any

from ..utils.dates import isoformat

PUBLIC_ACL_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}

PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def bucket_identity(raw: dict[str, Any]) -> dict[str, Any]:
    """The skeleton of a normalized bucket.

    The ``*_known`` flags separate "not configured" (a real, reportable state)
    from "we were denied and cannot say" (not reportable). Both look like a
    missing value otherwise, and conflating them is how scanners produce
    confident findings about resources they never read.
    """
    return {
        "name": raw.get("Name"),
        "creation_date": isoformat(raw.get("CreationDate")),
        "region": None,
        "public_access_block": None,
        "public_access_block_known": True,
        "encryption": {"configured": False, "known": True, "rules": []},
        "policy": None,
        "policy_known": True,
        "policy_is_public": None,
        "acl_grants": [],
        "acl_known": True,
        "collection_errors": [],
    }


def location(response: dict[str, Any] | None) -> str:
    """us-east-1 is historically returned as a null LocationConstraint."""
    constraint = (response or {}).get("LocationConstraint")
    return constraint or "us-east-1"


def public_access_block(response: dict[str, Any] | None) -> dict[str, bool]:
    config = (response or {}).get("PublicAccessBlockConfiguration", {}) or {}
    return {flag: bool(config.get(flag, False)) for flag in PAB_FLAGS}


def encryption(response: dict[str, Any] | None) -> dict[str, Any]:
    config = (response or {}).get("ServerSideEncryptionConfiguration", {}) or {}
    rules: list[dict[str, Any]] = []
    for rule in config.get("Rules", []) or []:
        default = rule.get("ApplyServerSideEncryptionByDefault", {}) or {}
        rules.append(
            {
                "algorithm": default.get("SSEAlgorithm"),
                "kms_key_id": default.get("KMSMasterKeyID"),
                "bucket_key_enabled": rule.get("BucketKeyEnabled"),
            }
        )
    return {"configured": bool(rules), "known": True, "rules": rules}


def no_encryption_configured() -> dict[str, Any]:
    return {"configured": False, "known": True, "rules": []}


def unknown_encryption() -> dict[str, Any]:
    return {"configured": False, "known": False, "rules": []}


def bucket_policy(response: dict[str, Any] | None) -> dict[str, Any] | None:
    """Parse the policy JSON string GetBucketPolicy returns.

    A policy that will not parse is kept as ``_unparsed`` rather than dropped,
    so the report shows that something is there that the scanner could not read.
    """
    document = (response or {}).get("Policy")
    if not document:
        return None
    if isinstance(document, dict):
        return document
    try:
        parsed = json.loads(document)
    except (TypeError, ValueError):
        return {"_unparsed": str(document)[:2000]}
    return parsed if isinstance(parsed, dict) else {"_unparsed": str(document)[:2000]}


def policy_status(response: dict[str, Any] | None) -> bool | None:
    return ((response or {}).get("PolicyStatus") or {}).get("IsPublic")


def acl_grants(response: dict[str, Any] | None) -> list[dict[str, Any]]:
    grants: list[dict[str, Any]] = []
    for grant in (response or {}).get("Grants", []) or []:
        grantee = grant.get("Grantee", {}) or {}
        uri = grantee.get("URI")
        grants.append(
            {
                "type": grantee.get("Type"),
                "uri": uri,
                # Non-null only for the two global groups; a canonical-user or
                # AWS-account grantee is a named identity, not the public.
                "group": PUBLIC_ACL_GROUPS.get(uri),
                "display_name": grantee.get("DisplayName"),
                "permission": grant.get("Permission"),
            }
        )
    return grants
