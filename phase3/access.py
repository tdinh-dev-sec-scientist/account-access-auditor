"""Caller identity for invite-only Phase 3 API and Rin requests.

API Gateway's Cognito authorizer verifies the ID token's signature and expiry
before a Lambda runs. This module re-checks the claims the authorizer passes
on, so a misconfigured method (for example, authorization accidentally set to
NONE) cannot serve data to anonymous callers. It fails closed: an unknown or
missing access mode is treated as invite-only, and invite-only without a
configured issuer and client is a configuration error.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

INVITE_ONLY = "invite_only"
PUBLIC = "public"

_ISSUER = re.compile(r"^https://cognito-idp\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9-]+_[A-Za-z0-9]+$")
_CLIENT_ID = re.compile(r"^[a-z0-9]{1,128}$")
_SUB = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class AccessDenied(Exception):
    """The request did not carry a valid identity for invite-only access."""


class AccessConfigurationError(Exception):
    """Invite-only access is required but the expected issuer or client is not configured."""


@dataclass(frozen=True)
class AccessContext:
    mode: str
    user_id: str | None = None

    @property
    def invite_only(self) -> bool:
        return self.mode == INVITE_ONLY

    @property
    def quota_identity(self) -> str | None:
        """A stable per-user quota key derived only from the verified subject."""
        return f"user-{self.user_id}" if self.user_id else None


def access_mode(environ: Mapping[str, str]) -> str:
    value = environ.get("PHASE3_ACCESS_MODE", "").strip()
    return PUBLIC if value == PUBLIC else INVITE_ONLY


def authenticate(event: Any, environ: Mapping[str, str]) -> AccessContext:
    """Return the caller's access context or raise AccessDenied/AccessConfigurationError."""
    mode = access_mode(environ)
    if mode == PUBLIC:
        return AccessContext(PUBLIC)

    issuer = environ.get("PHASE3_COGNITO_ISSUER", "").strip()
    client_id = environ.get("PHASE3_COGNITO_CLIENT_ID", "").strip()
    if not _ISSUER.fullmatch(issuer) or not _CLIENT_ID.fullmatch(client_id):
        raise AccessConfigurationError("invite-only access is not configured")

    claims = _authorizer_claims(event)
    subject = claims.get("sub")
    if (
        claims.get("iss") != issuer
        or claims.get("aud") != client_id
        or claims.get("token_use") != "id"
        or not isinstance(subject, str)
        or not _SUB.fullmatch(subject)
    ):
        raise AccessDenied("request identity is not valid for this console")
    return AccessContext(INVITE_ONLY, subject)


def _authorizer_claims(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise AccessDenied("request identity is missing")
    context = event.get("requestContext")
    authorizer = context.get("authorizer") if isinstance(context, dict) else None
    claims = authorizer.get("claims") if isinstance(authorizer, dict) else None
    if not isinstance(claims, dict):
        raise AccessDenied("request identity is missing")
    return claims
