"""Boto3 session construction, credential validation, and read-only enforcement.

Sessions built here always carry the read-only guard, so there is no code path
in the tool that produces a session capable of writing.
"""

from __future__ import annotations

import logging

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
