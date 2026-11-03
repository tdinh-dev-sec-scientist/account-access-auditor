from __future__ import annotations

from botocore.stub import Stubber
import pytest

from auditor.access_analyzer import validate_policy_document
from auditor.aws_session import build_access_analyzer_session
from auditor.permissions import ReadOnlyViolation


def test_access_analyzer_validation_is_opt_in_guarded_and_preserves_findings(monkeypatch):
    session, guard = build_access_analyzer_session(region="us-east-1")
    client = session.client("accessanalyzer")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    policy_text = '{"Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}'
    first_finding = {
        "findingDetails": "The policy grants broad access.",
        "findingType": "SECURITY_WARNING",
        "issueCode": "WILDCARD_USAGE",
        "learnMoreLink": "https://docs.aws.amazon.com/iam/",
        "locations": [
            {
                "path": [{"value": "Statement"}, {"index": 0}, {"value": "Action"}],
                "span": {
                    "start": {"line": 4, "column": 8, "offset": 10},
                    "end": {"line": 4, "column": 13, "offset": 15},
                },
            }
        ],
    }
    second_finding = {
        "findingDetails": "Consider an explicit policy version.",
        "findingType": "SUGGESTION",
        "issueCode": "POLICY_VERSION_NOT_RECOMMENDED",
        "learnMoreLink": "https://docs.aws.amazon.com/iam/",
        "locations": [],
    }
    stubber = Stubber(client)
    stubber.add_response(
        "validate_policy",
        {"findings": [first_finding], "nextToken": "page-2"},
        {
            "policyDocument": policy_text,
            "policyType": "IDENTITY_POLICY",
            "locale": "EN",
            "maxResults": 100,
        },
    )
    stubber.add_response(
        "validate_policy",
        {"findings": [second_finding]},
        {
            "policyDocument": policy_text,
            "policyType": "IDENTITY_POLICY",
            "locale": "EN",
            "maxResults": 100,
            "nextToken": "page-2",
        },
    )
    monkeypatch.setattr(session, "client", lambda name, **kwargs: client)

    with stubber:
        findings, errors = validate_policy_document(
            session,
            policy,
            policy_type="IDENTITY_POLICY",
            source_file="policies/example.json",
            account_ref={"provider": "aws", "id": "123456789012"},
            region="us-east-1",
        )

    assert errors == []
    assert [finding["severity"] for finding in findings] == ["HIGH", "INFO"]
    assert findings[0]["source_location"] == {"file": "policies/example.json", "line": 4}
    assert findings[0]["account_ref"]["id"] == "123456789012"
    assert findings[0]["scanner_rule_id"] == "WILDCARD_USAGE"
    assert guard is not None
    with pytest.raises(ReadOnlyViolation, match="Blocked 'accessanalyzer:CreateAnalyzer'"):
        client.create_analyzer(analyzerName="must-not-be-created", type="ACCOUNT")


def test_access_analyzer_rejects_unrecognized_policy_types_before_aws_call():
    class NoAwsCalls:
        def client(self, _name):
            raise AssertionError("AWS client must not be created for an invalid policy type")

    findings, errors = validate_policy_document(
        NoAwsCalls(),
        {"Statement": []},
        policy_type="UNSUPPORTED",
        source_file="policy.json",
    )

    assert findings == []
    assert errors[0]["code"] == "InvalidPolicyType"
