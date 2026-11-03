"""Boto3 session construction, credential validation, and read-only enforcement.

Sessions built here always carry the read-only guard, so there is no code path
in the tool that produces a session capable of writing.
"""

from __future__ import annotations

import logging
import re

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

from . import __version__
from .permissions import OPTIONAL_ALLOWED_OPERATIONS
from .readonly import ReadOnlyGuard, install_read_only_guard

log = logging.getLogger(__name__)

# Standard retry mode gives exponential backoff with jitter on throttling and
# transient 5xx responses, which is what an account-wide scan needs: the S3 and
# IAM read APIs throttle well before a large account is fully enumerated.
BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "standard"},
    user_agent_extra=f"account-access-auditor/{__version__}",
)


class SessionError(RuntimeError):
    """A usable AWS session could not be established."""


_READ_ONLY_ROLE_ARN = re.compile(
    r"^arn:aws:iam::[0-9]{12}:role/AccountAccessAuditorReadOnly$"
)
_ROLE_SESSION_NAME = re.compile(r"^[A-Za-z0-9+=,.@_-]{2,64}$")
_REGION_NAME = re.compile(r"^[a-z]{2,}(?:-[a-z0-9]+)+-[0-9]+$")


def build_session(
    profile: str | None = None,
    region: str | None = None,
    guard: bool = True,
) -> tuple[boto3.session.Session, ReadOnlyGuard | None]:
    """Build a session and attach the read-only guard.

    Returns ``(session, guard)``. The guard also counts API operations, which is
    what the benchmark uses to report the call volume of a scan.
    """
    try:
        session = boto3.session.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as exc:
        raise SessionError(
            f"AWS profile '{profile}' was not found in ~/.aws/config or ~/.aws/credentials."
        ) from exc

    # Every client from this session inherits the retry configuration.
    session._auditor_config = BOTO_CONFIG  # noqa: SLF001 - see _patch_client below
    _patch_client(session)

    return session, (install_read_only_guard(session) if guard else None)


def build_access_analyzer_session(
    profile: str | None = None, region: str | None = None
) -> tuple[boto3.session.Session, ReadOnlyGuard]:
    """Build an authenticated session with only the opt-in validation API added."""
    session, guard = build_session(profile=profile, region=region)
    if guard is None:  # pragma: no cover - build_session's default is guarded
        raise SessionError("Could not install the read-only guard for Access Analyzer validation.")
    guard.allowed = frozenset(set(guard.allowed) | set(OPTIONAL_ALLOWED_OPERATIONS))
    return session, guard


def build_assumed_role_session(
    source_session: boto3.session.Session,
    *,
    role_arn: str,
    role_session_name: str,
    external_id: str | None = None,
    region_name: str | None = None,
) -> tuple[boto3.session.Session, ReadOnlyGuard]:
    """Assume the one approved target-role name and guard the resulting session.

    STS returns short-lived credentials; the target session receives the same
    before-call allowlist as a directly configured profile. External ID values
    are sent only to STS and are never included in errors or logs.
    """
    if not _READ_ONLY_ROLE_ARN.fullmatch(role_arn):
        raise SessionError("Target role ARN must name AccountAccessAuditorReadOnly in an AWS account.")
    if not _ROLE_SESSION_NAME.fullmatch(role_session_name):
        raise SessionError("Role session name must be 2-64 safe characters.")
    selected_region = region_name or source_session.region_name
    if selected_region is not None and not _REGION_NAME.fullmatch(selected_region):
        raise SessionError("Target region must be an exact AWS region name.")
    if external_id is not None and (not external_id.strip() or len(external_id) > 1224):
        raise SessionError("External ID must contain 1-1224 non-whitespace characters.")

    request = {
        "RoleArn": role_arn,
        "RoleSessionName": role_session_name,
        "DurationSeconds": 900,
    }
    if external_id is not None:
        request["ExternalId"] = external_id
    try:
        response = source_session.client("sts").assume_role(**request)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        raise SessionError(f"Could not assume the configured read-only target role ({code}).") from None
    except (NoCredentialsError, PartialCredentialsError, EndpointConnectionError) as exc:
        raise SessionError(
            f"Could not assume the configured read-only target role ({exc.__class__.__name__})."
        ) from None

    credentials = response.get("Credentials")
    if not isinstance(credentials, dict) or not all(
        isinstance(credentials.get(key), str) and credentials[key]
        for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")
    ):
        raise SessionError("STS returned incomplete temporary credentials for the target role.")

    session_credentials = {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }
    session = boto3.session.Session(region_name=selected_region, **session_credentials)
    session._auditor_config = BOTO_CONFIG  # noqa: SLF001 - see _patch_client below
    _patch_client(session)
    return session, install_read_only_guard(session)


def _patch_client(session: boto3.session.Session) -> None:
    """Apply BOTO_CONFIG to every client the session creates.

    boto3 has no session-level default config, and threading one through every
    call site would be easy to forget in a new collector.
    """
    original = session.client

    def client(*args, **kwargs):
        kwargs.setdefault("config", BOTO_CONFIG)
        return original(*args, **kwargs)

    session.client = client  # type: ignore[method-assign]


def describe_caller(session: boto3.session.Session) -> tuple[str | None, str | None]:
    """Return ``(account_id, caller_arn)``, verifying that credentials work.

    This is the first real API call the tool makes, so it is where credential
    problems surface with a message that says what to do about them.
    """
    try:
        identity = session.client("sts").get_caller_identity()
        return identity.get("Account"), identity.get("Arn")
    except NoCredentialsError as exc:
        raise SessionError(
            "No AWS credentials found.\n"
            "Configure credentials with `aws configure`, set AWS_PROFILE, or pass --profile."
        ) from exc
    except PartialCredentialsError as exc:
        raise SessionError("Incomplete AWS credentials (an access key or secret key is missing).") from exc
    except EndpointConnectionError as exc:
        raise SessionError(
            "Could not reach the AWS STS endpoint. Check network connectivity and --region."
        ) from exc
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        hint = {
            "InvalidClientTokenId": "The access key ID is not valid for this partition or has been deleted.",
            "SignatureDoesNotMatch": "The secret access key does not match the access key ID.",
            "ExpiredToken": "The session token has expired; refresh the credentials.",
            "AccessDenied": "The credentials are valid but not allowed to call sts:GetCallerIdentity.",
        }.get(code, "")
        raise SessionError(f"STS GetCallerIdentity failed ({code}). {hint}".strip()) from exc
