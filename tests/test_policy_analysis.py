"""Policy-document analysis: the shared engine behind IAM-004/005 and S3-003."""

from __future__ import annotations

import pytest

from auditor.rules.policy import (
    analyze_permissions,
    applies_to_all_resources,
    as_list,
    condition_keys,
    constraining_condition_keys,
    public_principal_statements,
    statements,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, []),
        ("a", ["a"]),
        (["a", "b"], ["a", "b"]),
        ({}, [{}]),
        (0, [0]),
    ],
)
def test_scalar_or_list_fields_normalise_to_a_list(value, expected):
    assert as_list(value) == expected


@pytest.mark.parametrize("document", [None, "string", 42, [], {"NoStatement": 1}])
def test_malformed_documents_yield_no_statements_instead_of_raising(document):
    assert statements(document) == []


def test_non_object_statement_entries_are_skipped():
    document = {"Statement": [None, "x", 1, {"Effect": "Allow"}]}
    assert statements(document) == [{"Effect": "Allow"}]


# --------------------------------------------------------- resource scope ---


@pytest.mark.parametrize(
    "statement,expected",
    [
        ({"Resource": "*"}, True),
        ({"Resource": ["*", "arn:aws:s3:::b"]}, True),
        ({"Resource": "arn:aws:s3:::b/*"}, False),
        ({"NotResource": "arn:aws:s3:::secret"}, True),
        ({}, False),
        ({"Resource": [123]}, False),
    ],
)
def test_all_resources_detection(statement, expected):
    assert applies_to_all_resources(statement) is expected


# ------------------------------------------------------------ permissions ---


def test_admin_wildcard_is_detected():
    result = analyze_permissions({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert len(result["admin_wildcard"]) == 1
    assert result["service_wildcard"] == []


def test_deny_statements_are_never_reported_as_grants():
    result = analyze_permissions({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    assert result == {"admin_wildcard": [], "service_wildcard": []}


def test_service_wildcards_are_collected_and_deduplicated():
    result = analyze_permissions(
        {
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:*", "s3:GetObject", "ec2:*"], "Resource": "*"},
            ]
        }
    )
    assert result["service_wildcard"][0]["actions"] == ["ec2:*", "s3:*"]


def test_a_scoped_service_wildcard_is_not_reported():
    result = analyze_permissions(
        {
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"},
            ]
        }
    )
    assert result["service_wildcard"] == []


def test_admin_and_service_wildcards_are_reported_separately_per_statement():
    result = analyze_permissions(
        {
            "Statement": [
                {"Sid": "A", "Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Sid": "B", "Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            ]
        }
    )
    assert [s["sid"] for s in result["admin_wildcard"]] == ["A"]
    assert [s["sid"] for s in result["service_wildcard"]] == ["B"]


def test_condition_keys_are_recorded_on_permission_statements():
    result = analyze_permissions(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/team": "ops"}},
                },
            ]
        }
    )
    entry = result["admin_wildcard"][0]
    assert entry["has_condition"] is True
    assert entry["condition_keys"] == ["aws:principaltag/team"]


# ------------------------------------------------------------- principals ---


@pytest.mark.parametrize(
    "principal",
    [
        "*",
        {"AWS": "*"},
        {"AWS": ["*"]},
        {"AWS": ["arn:aws:iam::1:root", "*"]},
    ],
)
def test_anonymous_principal_forms_are_all_detected(principal):
    document = {"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject"}]}
    assert len(public_principal_statements(document)) == 1


@pytest.mark.parametrize(
    "principal",
    [
        {"Service": "cloudtrail.amazonaws.com"},
        {"AWS": "arn:aws:iam::123456789012:root"},
        {"Federated": "cognito-identity.amazonaws.com"},
        {"CanonicalUser": "abc123"},
        None,
    ],
)
def test_named_principals_are_not_public(principal):
    document = {"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject"}]}
    assert public_principal_statements(document) == []


def test_not_principal_allow_is_treated_as_public():
    document = {
        "Statement": [
            {"Effect": "Allow", "NotPrincipal": {"AWS": "arn:aws:iam::1:root"}, "Action": "s3:*"},
        ]
    }
    result = public_principal_statements(document)
    assert result[0]["principal_form"] == "NotPrincipal"


def test_public_deny_is_not_reported():
    document = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*"}]}
    assert public_principal_statements(document) == []


# ------------------------------------------------------------- conditions ---


@pytest.mark.parametrize(
    "condition,constraining",
    [
        ({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, ["aws:sourceip"]),
        ({"StringEquals": {"aws:PrincipalOrgID": "o-x"}}, ["aws:principalorgid"]),
        ({"StringEquals": {"aws:SourceVpce": "vpce-1"}}, ["aws:sourcevpce"]),
        ({"Bool": {"aws:SecureTransport": "true"}}, []),
        ({"StringEquals": {"s3:x-amz-acl": "public-read"}}, []),
        ({"NumericLessThan": {"s3:max-keys": "10"}}, []),
    ],
)
def test_only_principal_or_source_conditions_count_as_constraining(condition, constraining):
    statement = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Condition": condition}
    assert constraining_condition_keys(statement) == constraining
    result = public_principal_statements({"Statement": [statement]})
    assert result[0]["is_effectively_constrained"] is bool(constraining)


def test_a_mixed_condition_counts_if_any_key_constrains():
    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Condition": {"Bool": {"aws:SecureTransport": "true"}, "IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    }
    result = public_principal_statements({"Statement": [statement]})
    assert result[0]["is_effectively_constrained"] is True
    assert result[0]["condition_keys"] == ["aws:securetransport", "aws:sourceip"]


@pytest.mark.parametrize("condition", [None, "nonsense", [], 5])
def test_malformed_conditions_yield_no_keys(condition):
    assert condition_keys({"Condition": condition}) == []
