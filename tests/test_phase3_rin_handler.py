"""Wiring of the live Rin Lambda handler: configuration, feature flag, and clients."""

from __future__ import annotations

import json
from io import BytesIO

import boto3
import pytest
from moto import mock_aws

from phase3 import rin_service
from phase3.rin_service import RinRequestError

REGION = "us-east-1"
GUARDRAIL = "arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123"
BASE_ENV = {
    "AWS_REGION": REGION,
    "PHASE3_PUBLIC_RESULTS_BUCKET": "phase3-public-results",
    "PHASE3_PUBLIC_INDEX_TABLE": "phase3-public-index",
    "PHASE3_RIN_FEATURE_TABLE": "phase3-features",
    "PHASE3_RIN_QUOTA_FUNCTION_ARN": "arn:aws:lambda:us-east-1:123456789012:function:quota",
    "PHASE3_RIN_MODEL": "provider-model",
    "PHASE3_RIN_MAX_OUTPUT_TOKENS": "300",
    "PHASE3_RIN_MAX_INPUT_TOKENS": "2048",
}


def _table(name):
    return boto3.resource("dynamodb", region_name=REGION).create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class QuotaLambda:
    def __init__(self, response):
        self.response = response
        self.payloads = []

    def invoke(self, **kwargs):
        self.payloads.append(json.loads(kwargs["Payload"]))
        return self.response


@pytest.fixture
def wired(monkeypatch):
    """Run the handler against Moto and capture what it hands to rin_response."""
    with mock_aws():
        boto3.client("s3", region_name=REGION).create_bucket(Bucket=BASE_ENV["PHASE3_PUBLIC_RESULTS_BUCKET"])
        _table(BASE_ENV["PHASE3_PUBLIC_INDEX_TABLE"])
        features = _table(BASE_ENV["PHASE3_RIN_FEATURE_TABLE"])
        secret = boto3.client("secretsmanager", region_name=REGION).create_secret(
            Name="rin-provider", SecretString="provider-key"
        )
        quota = QuotaLambda({"StatusCode": 200, "Payload": BytesIO(b'{"allowed": true}')})
        real_session = boto3.session.Session

        class Session(real_session):
            def client(self, service_name, *args, **kwargs):
                if service_name == "lambda":
                    return quota
                return super().client(service_name, *args, **kwargs)

        captured = {}

        def fake_rin_response(event, **kwargs):
            captured.update(kwargs, event=event)
            return {"statusCode": 200}

        monkeypatch.setattr(rin_service.boto3.session, "Session", Session)
        monkeypatch.setattr(rin_service, "rin_response", fake_rin_response)
        for name, value in BASE_ENV.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setenv("PHASE3_RIN_PROVIDER_SECRET_ARN", secret["ARN"])
        yield {"features": features, "captured": captured, "quota": quota}


def test_handler_reports_missing_configuration(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)

    response = rin_service.lambda_handler({}, None)

    assert response["statusCode"] == 200
    assert json.loads(response["body"])["reason_code"] == "RIN_NOT_CONFIGURED"


def test_handler_fails_closed_when_clients_cannot_be_built(monkeypatch):
    for name, value in BASE_ENV.items():
        monkeypatch.setenv(name, value)

    def broken_session(**_kwargs):
        raise RuntimeError("no credentials")

    monkeypatch.setattr(rin_service.boto3.session, "Session", broken_session)

    response = rin_service.lambda_handler({}, None)

    assert response["statusCode"] == 503
    assert json.loads(response["body"])["reason_code"] == "RIN_CONFIGURATION_UNAVAILABLE"


def test_handler_is_disabled_when_the_feature_flag_is_missing(wired):
    rin_service.lambda_handler({"body": "{}"}, None)
    captured = wired["captured"]

    assert captured["enabled"] is False
    assert captured["guardrail"] is None
    assert captured["max_output_tokens"] == 300
    assert captured["max_input_tokens"] == 2048
    assert captured["model"] == "provider-model"


def test_handler_wires_live_clients_when_rin_is_enabled(wired, monkeypatch):
    wired["features"].put_item(
        Item={"pk": "PLATFORM", "sk": "CONFIG", "rin_enabled": True, "static_mode": False}
    )
    monkeypatch.setenv("PHASE3_RIN_GUARDRAIL_ARN", GUARDRAIL)
    monkeypatch.setenv("PHASE3_RIN_GUARDRAIL_VERSION", "1")

    rin_service.lambda_handler({"body": "{}"}, None)
    captured = wired["captured"]

    assert captured["enabled"] is True
    assert captured["guardrail"] is not None
    assert captured["api_key"]() == "provider-key"
    assert captured["enabled_check"]() is True
    assert captured["quota_consumer"]("session-token") == {"allowed": True}
    assert wired["quota"].payloads == [{"session_token": "session-token"}]

    wired["features"].put_item(
        Item={"pk": "PLATFORM", "sk": "CONFIG", "rin_enabled": True, "static_mode": True}
    )
    assert captured["enabled_check"]() is False


def test_handler_does_not_build_a_guardrail_for_an_unpinned_version(wired, monkeypatch):
    wired["features"].put_item(Item={"pk": "PLATFORM", "sk": "CONFIG", "rin_enabled": True})
    monkeypatch.setenv("PHASE3_RIN_GUARDRAIL_ARN", GUARDRAIL)
    monkeypatch.setenv("PHASE3_RIN_GUARDRAIL_VERSION", "DRAFT")
    monkeypatch.setenv("PHASE3_RIN_MAX_OUTPUT_TOKENS", "lots")
    monkeypatch.setenv("PHASE3_RIN_MAX_INPUT_TOKENS", "")

    rin_service.lambda_handler({"body": "{}"}, None)
    captured = wired["captured"]

    assert captured["guardrail"] is None
    assert captured["max_output_tokens"] is None
    assert captured["max_input_tokens"] == 4096


def test_quota_service_errors_are_raised_as_request_errors(wired):
    wired["quota"].response = {"StatusCode": 200, "FunctionError": "Unhandled", "Payload": BytesIO(b"{}")}

    rin_service.lambda_handler({"body": "{}"}, None)

    with pytest.raises(RinRequestError, match="quota service failed"):
        wired["captured"]["quota_consumer"]("session-token")


def test_provider_key_is_absent_without_a_configured_secret(wired, monkeypatch):
    monkeypatch.setenv("PHASE3_RIN_PROVIDER_SECRET_ARN", "")

    rin_service.lambda_handler({"body": "{}"}, None)

    assert wired["captured"]["api_key"]() is None
