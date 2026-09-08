"""S3 collector: Public Access Block, ACL, bucket policy, encryption.

Each bucket costs six API calls, and any of them can fail independently. The
collector therefore treats each field as separately readable: a denied
GetBucketAcl degrades the ACL field and records why, while the policy and
encryption results for that same bucket still reach the rules.
"""

from __future__ import annotations

import logging
from typing import Any

from ..normalize import s3 as normalize
from ._common import AWS_EXCEPTIONS, FAILED, NOT_CONFIGURED, OK, record_error, safe_call

log = logging.getLogger(__name__)

SERVICE = "S3"

REQUIRED_PERMISSIONS = [
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketPolicy",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketAcl",
    "s3:GetEncryptionConfiguration",
]


def collect(session, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return normalized S3 state: ``{"buckets": [...], "errors": [...]}``."""
    client = session.client("s3")
    errors: list[dict[str, Any]] = []
    buckets: list[dict[str, Any]] = []

    log.info("Starting S3 collection")
    try:
        response = client.list_buckets()
    except AWS_EXCEPTIONS as exc:
        record_error(
            errors, SERVICE, "s3:ListAllMyBuckets", exc, required_permissions=["s3:ListAllMyBuckets"]
        )
        # Nothing was enumerated, so no bucket rule can run. Say so explicitly.
        return {"buckets": [], "errors": errors, "buckets_readable": False}

    for raw in response.get("Buckets", []):
        buckets.append(_collect_bucket(client, raw, errors))

    log.info("S3 collection complete: %d buckets", len(buckets))
    return {"buckets": buckets, "errors": errors, "buckets_readable": True}


def _collect_bucket(client, raw: dict[str, Any], errors) -> dict[str, Any]:
    bucket = normalize.bucket_identity(raw)
    name = bucket["name"]
    own = bucket["collection_errors"]

    def call(operation, permission, fetch):
        return safe_call(errors, own, SERVICE, operation, fetch, name, [permission])

    response, outcome = call(
        "s3:GetBucketLocation", "s3:GetBucketLocation", lambda: client.get_bucket_location(Bucket=name)
    )
    if outcome == OK:
        bucket["region"] = normalize.location(response)

    # No PAB configuration is a real, reportable state (all four protections
    # off). A denied call is not: public_access_block_known goes False and the
    # rules stay silent instead of asserting the bucket is unprotected.
    response, outcome = call(
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        lambda: client.get_public_access_block(Bucket=name),
    )
    if outcome == OK:
        bucket["public_access_block"] = normalize.public_access_block(response)
    elif outcome == FAILED:
        bucket["public_access_block_known"] = False

    response, outcome = call(
        "s3:GetEncryptionConfiguration",
        "s3:GetEncryptionConfiguration",
        lambda: client.get_bucket_encryption(Bucket=name),
    )
    if outcome == OK:
        bucket["encryption"] = normalize.encryption(response)
    elif outcome == NOT_CONFIGURED:
        bucket["encryption"] = normalize.no_encryption_configured()
    else:
        bucket["encryption"] = normalize.unknown_encryption()

    response, outcome = call(
        "s3:GetBucketPolicy", "s3:GetBucketPolicy", lambda: client.get_bucket_policy(Bucket=name)
    )
    if outcome == OK:
        bucket["policy"] = normalize.bucket_policy(response)
    elif outcome == FAILED:
        bucket["policy_known"] = False

    response, outcome = call(
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPolicyStatus",
        lambda: client.get_bucket_policy_status(Bucket=name),
    )
    if outcome == OK:
        bucket["policy_is_public"] = normalize.policy_status(response)

    response, outcome = call("s3:GetBucketAcl", "s3:GetBucketAcl", lambda: client.get_bucket_acl(Bucket=name))
    if outcome == OK:
        bucket["acl_grants"] = normalize.acl_grants(response)
    elif outcome == FAILED:
        bucket["acl_known"] = False

    return bucket
