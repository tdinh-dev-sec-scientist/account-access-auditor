"""Invite-only access: identity checks, fail-closed configuration, and per-user quotas."""

from __future__ import annotations

import json

import pytest

from phase3 import public_api, rin_service
from phase3.access import (
    AccessConfigurationError,
    AccessContext,
    AccessDenied,
    access_mode,
    authenticate,
)

ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123"
CLIENT = "4ab5c6d7e8f9g0h1i2j3k4l5m6"
SUB = "1f2e3d4c-5b6a-4789-8abc-def012345678"
INVITE_ENV = {
    "PHASE3_ACCESS_MODE": "invite_only",
    "PHASE3_COGNITO_ISSUER": ISSUER,
    "PHASE3_COGNITO_CLIENT_ID": CLIENT,
}


def _claims(**overrides):
    claims = {"iss": ISSUER, "aud": CLIENT, "token_use": "id", "sub": SUB, "email": "invitee@example.com"}
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


def _event(claims=None, *, method="GET", path="/api/latest", body=None):
    event = {"httpMethod": method, "path": path}
    if claims is not None:
        event["requestContext"] = {"authorizer": {"claims": claims}}
    if body is not None:
        event["body"] = json.dumps(body)
    return event


# ------------------------------------------------------------------ module --


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("public", "public"),
        ("invite_only", "invite_only"),
        ("", "invite_only"),
        ("PUBLIC", "invite_only"),
        ("open", "invite_only"),
    ],
)
def test_unknown_or_missing_modes_fail_closed_to_invite_only(value, expected):
    assert access_mode({"PHASE3_ACCESS_MODE": value}) == expected


def test_missing_mode_is_invite_only():
    assert access_mode({}) == "invite_only"


def test_public_mode_needs_no_identity():
    assert authenticate({}, {"PHASE3_ACCESS_MODE": "public"}) == AccessContext("public")


def test_valid_claims_yield_a_verified_user():
    context = authenticate(_event(_claims()), INVITE_ENV)

    assert context.invite_only
    assert context.user_id == SUB
    assert context.quota_identity == f"user-{SUB}"


@pytest.mark.parametrize(
    "env",
    [
        {"PHASE3_ACCESS_MODE": "invite_only"},
        {**INVITE_ENV, "PHASE3_COGNITO_ISSUER": "https://evil.example.com/us-east-1_AbCdEf123"},
        {**INVITE_ENV, "PHASE3_COGNITO_CLIENT_ID": "Client With Spaces"},
    ],
)
def test_invite_only_without_a_valid_issuer_and_client_is_a_configuration_error(env):
    with pytest.raises(AccessConfigurationError):
        authenticate(_event(_claims()), env)


@pytest.mark.parametrize(
    "event",
    [
        None,
        [],
        {"httpMethod": "GET"},
        {"requestContext": "not-a-dict"},
        {"requestContext": {"authorizer": None}},
        {"requestContext": {"authorizer": {"claims": "sub=x"}}},
    ],
)
def test_requests_without_authorizer_claims_are_denied(event):
    with pytest.raises(AccessDenied):
        authenticate(event, INVITE_ENV)


@pytest.mark.parametrize(
    "claims",
    [
        _claims(iss="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_OtherPool1"),
        _claims(aud="someotherclientid"),
        _claims(token_use="access"),
        _claims(sub=None),
        _claims(sub="not-a-uuid"),
        _claims(sub=SUB.upper()),
        _claims(iss=None),
    ],
    ids=["other-pool", "other-client", "access-token", "no-sub", "bad-sub", "uppercase-sub", "no-issuer"],
)
def test_tokens_for_another_pool_client_or_purpose_are_denied(claims):
    with pytest.raises(AccessDenied):
        authenticate(_event(claims), INVITE_ENV)


# ------------------------------------------------------------- public API --


def _invite_env(monkeypatch, **extra):
    for name in ("PHASE3_PUBLIC_RESULTS_BUCKET", "PHASE3_PUBLIC_INDEX_TABLE", "AWS_REGION"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {**INVITE_ENV, **extra}.items():
        monkeypatch.setenv(name, value)


def test_api_rejects_anonymous_requests_with_401(monkeypatch):
    _invite_env(monkeypatch)

    response = public_api.lambda_handler(_event(), None)

    assert response["statusCode"] == 401
    assert response["headers"]["WWW-Authenticate"] == "Bearer"
    assert response["headers"]["Cache-Control"] == "private, no-store"
    assert json.loads(response["body"]) == {"error": "UNAUTHENTICATED"}


def test_api_rejects_a_token_from_another_client(monkeypatch):
    _invite_env(monkeypatch)

    response = public_api.lambda_handler(_event(_claims(aud="someotherclientid")), None)

    assert response["statusCode"] == 401


def test_api_fails_closed_when_invite_only_is_not_configured(monkeypatch):
    _invite_env(monkeypatch, PHASE3_COGNITO_CLIENT_ID="")

    response = public_api.lambda_handler(_event(_claims()), None)

    assert response["statusCode"] == 503
    assert response["headers"]["Cache-Control"] == "private, no-store"


def test_signed_in_api_responses_are_never_cacheable(monkeypatch):
    _invite_env(monkeypatch)
    # Data configuration is missing, so the handler stops after authentication.
    response = public_api.lambda_handler(_event(_claims()), None)

    assert response["statusCode"] == 503
    assert response["headers"]["Cache-Control"] == "private, no-store"
    assert response["headers"]["Vary"] == "Authorization"


def test_signed_in_api_success_is_private(monkeypatch):
    _invite_env(monkeypatch)
    captured = {}

    def fake_public_response(event, *, store):
        captured["event"] = event
        return public_api._response(200, {"runs": []})

    class FakeSession:
        def __init__(self, **_kwargs):
            pass

        def resource(self, _name):
            return type("Resource", (), {"Table": lambda self, name: name})()

        def client(self, _name):
            return object()

    monkeypatch.setenv("PHASE3_PUBLIC_RESULTS_BUCKET", "bucket")
    monkeypatch.setenv("PHASE3_PUBLIC_INDEX_TABLE", "table")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PHASE3_FEATURE_TABLE", "")
    monkeypatch.setattr(public_api.boto3.session, "Session", FakeSession)
    monkeypatch.setattr(public_api, "public_response", fake_public_response)

    response = public_api.lambda_handler(_event(_claims(), path="/api/runs"), None)

    assert response["statusCode"] == 200
    assert response["headers"]["Cache-Control"] == "private, no-store"
    assert response["headers"]["Vary"] == "Authorization"
    assert captured["event"]["path"] == "/api/runs"


# --------------------------------------------------------------------- Rin --


def test_rin_rejects_anonymous_requests_before_any_aws_client_is_built(monkeypatch):
    _invite_env(monkeypatch)

    def no_session(**_kwargs):
        raise AssertionError("no AWS client may be created for an anonymous request")

    monkeypatch.setattr(rin_service.boto3.session, "Session", no_session)

    response = rin_service.lambda_handler(_event(method="POST", path="/api/rin"), None)

    assert response["statusCode"] == 401
    assert response["headers"]["WWW-Authenticate"] == "Bearer"
    assert response["headers"]["Cache-Control"] == "private, no-store"
    assert json.loads(response["body"])["reason_code"] == "UNAUTHENTICATED"


def test_rin_fails_closed_when_invite_only_is_not_configured(monkeypatch):
    _invite_env(monkeypatch, PHASE3_COGNITO_ISSUER="")

    response = rin_service.lambda_handler(_event(_claims(), method="POST", path="/api/rin"), None)

    assert response["statusCode"] == 503
    assert json.loads(response["body"])["reason_code"] == "RIN_CONFIGURATION_UNAVAILABLE"


def test_rin_passes_the_verified_user_as_quota_identity(monkeypatch):
    _invite_env(monkeypatch)
    captured = {}

    def fake_configured(event, *, access_quota_identity):
        captured["identity"] = access_quota_identity
        return rin_service._response(200, {"status": "UNAVAILABLE", "reason_code": "RIN_DISABLED"})

    monkeypatch.setattr(rin_service, "_configured_rin_response", fake_configured)

    response = rin_service.lambda_handler(_event(_claims(), method="POST", path="/api/rin"), None)

    assert captured["identity"] == f"user-{SUB}"
    assert response["headers"]["Cache-Control"] == "private, no-store"


def test_quota_uses_the_verified_identity_not_the_client_session_token():
    """A user cannot reset their limit by sending a fresh session token."""
    from tests.test_phase3_rin import Store, _rin_response, _snapshot

    seen = []

    def quota_consumer(identity):
        seen.append(identity)
        return {"allowed": False, "reason": "SESSION_LIMIT"}

    snapshot = _snapshot()
    finding_id = snapshot["findings"][0]["id"]
    responses = [
        _rin_response(
            _event(
                method="POST",
                path="/api/rin",
                body={"question": "Why does this matter?", "finding_id": finding_id, "session_token": token},
            ),
            store=Store(snapshot),
            enabled=True,
            model="model-v1",
            api_key="key",
            max_output_tokens=500,
            quota_consumer=quota_consumer,
            provider=lambda *_: pytest.fail("a denied quota must not reach the provider"),
            quota_identity=f"user-{SUB}",
        )
        for token in ("a" * 40, "b" * 40)
    ]

    assert seen == [f"user-{SUB}", f"user-{SUB}"]
    assert [response["statusCode"] for response in responses] == [429, 429]
