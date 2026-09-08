"""Shared collector plumbing.

Collectors decide which API calls to make and how to survive their failures.
They do not decide what anything means -- that is the rules' job -- and they do
not shape data -- that is ``auditor.normalize``'s job.

The central rule here: one failed API call degrades one field, never the scan.
A bucket that refuses GetBucketAcl still contributes everything else it
returned, and the report says which call failed and which permission is likely
missing, so a partial scan is visibly partial instead of quietly clean.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger(__name__)

AWS_EXCEPTIONS: tuple[type, ...] = (ClientError, BotoCoreError)

# "This is not configured", not "something broke". These are normal, expected
# responses that carry information: a bucket with no policy really has no policy.
NOT_CONFIGURED_CODES = {
    "NoSuchEntity",
    "NoSuchBucketPolicy",
    "NoSuchPublicAccessBlockConfiguration",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchTagSet",
    "NoSuchConfiguration",
    "TrailNotFoundException",
}

ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "InvalidClientTokenId",
}

# Botocore retries these itself under the standard retry mode; if one still
# surfaces here the retries were exhausted, which is worth saying explicitly.
THROTTLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
}

# Outcomes of a guarded call.
OK = "ok"
NOT_CONFIGURED = "not_configured"
FAILED = "error"


def error_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "Unknown")
    return exc.__class__.__name__


def is_not_configured(exc: Exception) -> bool:
    return error_code(exc) in NOT_CONFIGURED_CODES


def is_access_denied(exc: Exception) -> bool:
    return error_code(exc) in ACCESS_DENIED_CODES


def is_throttling(exc: Exception) -> bool:
    return error_code(exc) in THROTTLE_CODES


def record_error(
    errors: list[dict[str, Any]],
    service: str,
    operation: str,
    exc: Exception,
    resource: str | None = None,
    required_permissions: list[str] | None = None,
) -> dict[str, Any]:
    """Log an API failure and append a structured entry to ``errors``.

    Collection errors are reported separately from security findings. An
    inaccessible resource is a gap in coverage, not an insecure resource, and
    merging the two is how a scan that read nothing can look like a clean account.
    """
    code = error_code(exc)
    entry: dict[str, Any] = {
        "service": service,
        "operation": operation,
        "resource": resource,
        "code": code,
        "category": _category(code),
        "message": str(exc)[:500],
    }
    if is_access_denied(exc) and required_permissions:
        entry["required_permissions"] = list(required_permissions)
        log.error(
            "Access denied calling %s on %s; missing permission(s) likely: %s",
            operation,
            resource or service,
            ", ".join(required_permissions),
        )
    elif is_throttling(exc):
        log.warning(
            "%s on %s was throttled after botocore's retries were exhausted; "
            "results for this resource are incomplete.",
            operation,
            resource or service,
        )
    else:
        log.warning("%s failed for %s: %s", operation, resource or service, code)
    errors.append(entry)
    return entry


def _category(code: str) -> str:
    if code in ACCESS_DENIED_CODES:
        return "access_denied"
    if code in THROTTLE_CODES:
        return "throttled"
    if code in NOT_CONFIGURED_CODES:
        return "not_configured"
    return "error"


def safe_call(
    errors: list[dict[str, Any]],
    resource_errors: list[dict[str, Any]] | None,
    service: str,
    operation: str,
    fetch: Callable[[], Any],
    resource: str | None = None,
    required_permissions: list[str] | None = None,
) -> tuple[Any, str]:
    """Run one API call, returning ``(value, outcome)``.

    ``outcome`` is one of ``OK``, ``NOT_CONFIGURED`` (the resource legitimately
    has no such configuration), or ``FAILED`` (recorded as a collection error).
    Callers branch on the outcome instead of guessing from a None return, which
    is what keeps "not configured" and "not readable" distinguishable all the
    way to the rules.
    """
    try:
        return fetch(), OK
    except AWS_EXCEPTIONS as exc:
        if is_not_configured(exc):
            return None, NOT_CONFIGURED
        entry = record_error(errors, service, operation, exc, resource, required_permissions)
        if resource_errors is not None:
            resource_errors.append(entry)
        return None, FAILED


def paginate(client, operation: str, **kwargs):
    """Page through an operation, falling back to a single call if unpaginated.

    boto3 raises OperationNotPageableError for operations without a paginator
    (``cloudtrail:DescribeTrails``, ``s3:ListBuckets``), and a collector should
    not have to know which is which.
    """
    if client.can_paginate(operation):
        yield from client.get_paginator(operation).paginate(**kwargs)
    else:  # pragma: no cover - exercised via the collectors' own tests
        yield getattr(client, operation)(**kwargs)
