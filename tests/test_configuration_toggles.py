"""Configuration toggles and the remaining collector error paths.

Every rule can be switched off in config.yaml. A toggle that silently does
nothing is worse than no toggle at all, so each one is exercised: the rule it
names goes quiet, and the rules it does not name keep firing.
"""

from __future__ import annotations

import pytest

from auditor import compliance, permissions
from auditor.collectors import _common, iam
from auditor.config import defaults
from auditor.normalize import s3 as normalize_s3
from auditor.rules import engine, registry
from tests.builders import (
    access_key,
    bucket,
    cloudtrail_state,
    iam_group,
    iam_state,
    iam_user,
    policy,
    public_acl_grant,
    s3_state,
    trail,
)
from tests.test_collectors import StubClient, StubSession, client_error


def evaluate(service, data, **overrides):
    config = defaults()
    for section, values in overrides.items():
        config[section].update(values)
    return {f.rule_id for f in engine.evaluate_service(service, data, config)}


# ------------------------------------------------------------ IAM toggles ---


def test_require_mfa_for_console_users_off_silences_iam_001():
    data = iam_state(users=[iam_user("a", console_access=True, mfa_devices=0)])
    assert evaluate("iam", data) == {"IAM-001"}
    assert evaluate("iam", data, iam={"require_mfa_for_console_users": False}) == set()


def test_programmatic_inventory_can_be_switched_off():
    data = iam_state(users=[iam_user("svc", console_access=False, mfa_devices=0)])
    assert evaluate("iam", data) == {"IAM-006"}
    assert evaluate("iam", data, iam={"report_programmatic_users_without_mfa": False}) == set()


def test_inactive_key_check_off_silences_only_the_inactive_branch():
    data = iam_state(
        users=[
            iam_user(
                "svc",
                mfa_devices=1,
                access_keys=[
                    access_key("AKIAOLD", status="Inactive", age_days=400),
                    access_key("AKIADORMANT", age_days=400, last_used_days_ago=None),
                ],
            )
        ]
    )
    assert evaluate("iam", data) == {"IAM-002", "IAM-003"}
    reduced = evaluate("iam", data, iam={"inactive_key_check": False, "dormant_key_check": False})
    assert reduced == {"IAM-002"}


def test_dormant_key_check_off_keeps_the_inactive_branch():
    data = iam_state(
        users=[
            iam_user(
                "svc",
                mfa_devices=1,
                access_keys=[access_key("AKIADORMANT", age_days=60, last_used_days_ago=None)],
            )
        ]
    )
    assert evaluate("iam", data) == {"IAM-003"}
    assert evaluate("iam", data, iam={"dormant_key_check": False}) == set()


def test_custom_thresholds_move_the_severity_boundary():
    data = iam_state(
        users=[iam_user("svc", mfa_devices=1, access_keys=[access_key(age_days=45, last_used_days_ago=1)])]
    )
    assert evaluate("iam", data) == set()
    config = defaults()
    config["iam"]["access_key_max_age_days"] = 30
    config["iam"]["access_key_critical_age_days"] = 40
    findings = engine.evaluate_service("iam", data, config)
    assert [f.severity.value for f in findings] == ["HIGH"]


def test_wildcard_policy_checks_can_be_switched_off():
    data = iam_state(
        users=[
            iam_user(
                "a",
                mfa_devices=1,
                policies=[policy("admin", [{"Effect": "Allow", "Action": "*", "Resource": "*"}])],
            )
        ]
    )
    assert evaluate("iam", data) == {"IAM-004"}
    assert evaluate("iam", data, iam={"check_wildcard_policies": False}) == set()


def test_group_policies_are_still_checked_when_a_group_has_no_members():
    data = iam_state(
        groups=[
            iam_group(
                "empty", policies=[policy("broad", [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])]
            )
        ]
    )
    assert evaluate("iam", data) == {"IAM-005"}


# ------------------------------------------------------------- S3 toggles ---


def test_public_access_checks_can_be_switched_off_independently_of_encryption():
    data = s3_state(
        bucket("b", public_access_block=None, encryption_configured=False, acl_grants=[public_acl_grant()])
    )
    assert evaluate("s3", data) == {"S3-001", "S3-002", "S3-004"}
    assert evaluate("s3", data, s3={"check_public_access": False}) == {"S3-004"}
    assert evaluate("s3", data, s3={"check_encryption": False}) == {"S3-001", "S3-002"}


# ------------------------------------------------------ CloudTrail toggles ---


def test_require_trail_off_silences_ct_001():
    assert evaluate("cloudtrail", cloudtrail_state()) == {"CT-001"}
    assert evaluate("cloudtrail", cloudtrail_state(), cloudtrail={"require_trail": False}) == set()


def test_require_multi_region_off_silences_only_ct_002():
    data = cloudtrail_state(trail(multi_region=False, log_validation=False))
    assert evaluate("cloudtrail", data) == {"CT-002", "CT-003"}
    assert evaluate("cloudtrail", data, cloudtrail={"require_multi_region": False}) == {"CT-003"}


def test_require_log_validation_off_silences_only_ct_003():
    data = cloudtrail_state(trail(multi_region=False, log_validation=False))
    assert evaluate("cloudtrail", data, cloudtrail={"require_log_validation": False}) == {"CT-002"}


def test_check_logging_status_off_silences_only_ct_004():
    data = cloudtrail_state(trail(log_validation=False, is_logging=False))
    assert evaluate("cloudtrail", data) == {"CT-003", "CT-004"}
    assert evaluate("cloudtrail", data, cloudtrail={"check_logging_status": False}) == {"CT-003"}


# ----------------------------------------------- remaining collector paths ---


def _iam_stub(pages=None, responses=None):
    base_pages = {
        "list_users": [{"Users": [{"UserName": "u1"}]}],
        "list_access_keys": [{"AccessKeyMetadata": []}],
        "list_groups_for_user": [{"Groups": []}],
        "list_attached_user_policies": [{"AttachedPolicies": []}],
        "list_user_policies": [{"PolicyNames": []}],
        "list_groups": [{"Groups": []}],
        "list_roles": [{"Roles": []}],
        "list_attached_group_policies": [{"AttachedPolicies": []}],
        "list_group_policies": [{"PolicyNames": []}],
        "list_attached_role_policies": [{"AttachedPolicies": []}],
        "list_role_policies": [{"PolicyNames": []}],
    }
    base_responses = {
        "get_login_profile": client_error("NoSuchEntity"),
        "list_mfa_devices": {"MFADevices": []},
        "get_group": {"Users": []},
    }
    base_pages.update(pages or {})
    base_responses.update(responses or {})
    return StubClient(base_responses, base_pages)


def test_denied_list_access_keys_is_recorded_against_the_user():
    client = _iam_stub(pages={"list_access_keys": client_error("AccessDenied")})
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"][0]["access_keys"] == []
    assert data["users"][0]["collection_errors"][0]["code"] == "AccessDenied"


def test_denied_list_groups_for_user_is_recorded_without_losing_the_user():
    client = _iam_stub(pages={"list_groups_for_user": client_error("AccessDenied")})
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"][0]["username"] == "u1"
    assert data["users"][0]["group_names"] == []


def test_denied_list_groups_and_list_roles_leave_the_rest_of_the_scan_intact():
    client = _iam_stub(
        pages={"list_groups": client_error("AccessDenied"), "list_roles": client_error("AccessDenied")}
    )
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"] and data["groups"] == [] and data["roles"] == []
    codes = {error["operation"] for error in data["errors"]}
    assert {"iam:ListGroups", "iam:ListRoles"} <= codes


def test_denied_get_group_still_reports_the_groups_policies():
    client = _iam_stub(
        pages={
            "list_groups": [{"Groups": [{"GroupName": "g"}]}],
            "list_group_policies": [{"PolicyNames": ["p"]}],
        },
        responses={
            "get_group": client_error("AccessDenied"),
            "get_group_policy": {"PolicyDocument": {"Statement": []}},
        },
    )
    data = iam.collect(StubSession({"iam": client}), {})
    group = data["groups"][0]
    assert group["member_usernames"] == []
    assert [p["name"] for p in group["policies"]] == ["p"]


def test_denied_inline_policy_listing_is_recorded_per_principal():
    client = _iam_stub(
        pages={
            "list_user_policies": client_error("AccessDenied"),
            "list_attached_user_policies": client_error("AccessDenied"),
        }
    )
    data = iam.collect(StubSession({"iam": client}), {})
    operations = {error["operation"] for error in data["users"][0]["collection_errors"]}
    assert operations == {"iam:ListUserPolicies", "iam:ListAttachedUserPolicies"}


def test_a_managed_policy_without_a_default_version_yields_no_document():
    client = _iam_stub(
        pages={
            "list_attached_user_policies": [
                {"AttachedPolicies": [{"PolicyName": "P", "PolicyArn": "arn:aws:iam::1:policy/P"}]}
            ]
        },
        responses={"get_policy": {"Policy": {}}},
    )
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"][0]["policies"][0]["document"] is None


def test_a_denied_policy_version_yields_no_document():
    client = _iam_stub(
        pages={
            "list_attached_user_policies": [
                {"AttachedPolicies": [{"PolicyName": "P", "PolicyArn": "arn:aws:iam::1:policy/P"}]}
            ]
        },
        responses={
            "get_policy": {"Policy": {"DefaultVersionId": "v1"}},
            "get_policy_version": client_error("AccessDenied"),
        },
    )
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"][0]["policies"][0]["document"] is None


def test_role_inline_policies_are_read():
    client = _iam_stub(
        pages={
            "list_roles": [{"Roles": [{"RoleName": "r", "Path": "/"}]}],
            "list_role_policies": [{"PolicyNames": ["inline"]}],
        },
        responses={"get_role_policy": {"PolicyDocument": {"Statement": []}}},
    )
    data = iam.collect(StubSession({"iam": client}), {})
    assert [p["name"] for p in data["roles"][0]["policies"]] == ["inline"]


def test_unclassified_error_codes_fall_through_to_a_generic_category():
    assert _common._category("InternalError") == "error"
    assert _common._category("NoSuchEntity") == "not_configured"


def test_a_botocore_error_that_is_not_a_client_error_is_still_recorded():
    from botocore.exceptions import EndpointConnectionError

    errors = []
    _common.record_error(
        errors, "S3", "s3:GetBucketAcl", EndpointConnectionError(endpoint_url="https://s3"), "b"
    )
    assert errors[0]["code"] == "EndpointConnectionError"


def test_safe_call_without_a_per_resource_error_list_still_records_globally():
    errors = []
    value, outcome = _common.safe_call(
        errors,
        None,
        "S3",
        "op",
        lambda: (_ for _ in ()).throw(client_error("AccessDenied")),
    )
    assert value is None and outcome == _common.FAILED and len(errors) == 1


def test_an_already_parsed_bucket_policy_is_passed_through():
    assert normalize_s3.bucket_policy({"Policy": {"Version": "2012-10-17"}}) == {"Version": "2012-10-17"}


# ------------------------------------------------- remaining helper paths ---


def test_is_allowed_matches_the_declared_inventory():
    assert permissions.is_allowed("iam", "ListUsers")
    assert not permissions.is_allowed("iam", "CreateUser")
    assert not permissions.is_allowed("ec2", "DescribeInstances")


def test_calls_for_groups_the_inventory_by_service():
    assert {call.operation for call in permissions.calls_for("cloudtrail")} == {
        "DescribeTrails",
        "GetTrailStatus",
    }
    assert permissions.calls_for("dynamodb") == []


def test_assert_all_read_only_raises_when_a_write_call_is_declared(monkeypatch):
    """Proves the guard would actually catch a regression, not just pass today."""
    write_call = permissions.ApiCall(
        service="iam",
        operation="CreateUser",
        boto3_method="create_user",
        iam_action="iam:CreateUser",
        statement_id="Bad",
        resources=("*",),
        purpose="deliberately invalid",
        used_by=("test",),
    )
    monkeypatch.setattr(permissions, "API_CALLS", permissions.API_CALLS + (write_call,))
    with pytest.raises(permissions.ReadOnlyViolation, match="iam:CreateUser"):
        permissions.assert_all_read_only()


def test_unused_permissions_reports_anything_granted_but_unneeded():
    assert permissions.unused_permissions([]) == list(permissions.ALLOWED_IAM_ACTIONS)


def test_by_service_returns_everything_when_no_service_is_named():
    assert len(registry.by_service()) == 14


def test_duplicate_mapping_entries_are_rejected(tmp_path):
    import json

    entry = {
        "rule_id": "X",
        "finding": "f",
        "control_id": "1.1",
        "control_title": "t",
        "status": "mapped",
        "rationale": "r",
    }
    path = tmp_path / "dupe.json"
    path.write_text(
        json.dumps({"benchmark": {"name": "CIS", "version": "3.0.0"}, "rules": [entry, dict(entry)]})
    )
    with pytest.raises(compliance.ComplianceMappingError, match="Duplicate"):
        compliance.load_mapping(str(path))


def test_an_unknown_mapping_status_is_rejected(tmp_path):
    import json

    path = tmp_path / "status.json"
    path.write_text(
        json.dumps(
            {
                "benchmark": {"name": "CIS", "version": "3.0.0"},
                "rules": [
                    {
                        "rule_id": "X",
                        "finding": "f",
                        "control_id": "1.1",
                        "control_title": "t",
                        "status": "maybe",
                        "rationale": "r",
                    }
                ],
            }
        )
    )
    with pytest.raises(compliance.ComplianceMappingError, match="unknown status"):
        compliance.load_mapping(str(path))


def test_a_mapping_document_without_rules_is_rejected(tmp_path):
    path = tmp_path / "norules.json"
    path.write_text('{"benchmark": {}}')
    with pytest.raises(compliance.ComplianceMappingError, match="'rules' array"):
        compliance.load_mapping(str(path))


def test_invalid_mapping_json_is_reported_as_such(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(compliance.ComplianceMappingError, match="not valid JSON"):
        compliance.load_mapping(str(path))


# ------------------------------------------------- last remaining branches ---


def test_a_denied_bucket_policy_call_marks_the_policy_unknown():
    from auditor.collectors import s3 as s3_collector

    client = StubClient(
        {
            "list_buckets": {"Buckets": [{"Name": "b1"}]},
            "get_bucket_location": {"LocationConstraint": None},
            "get_public_access_block": client_error("NoSuchPublicAccessBlockConfiguration"),
            "get_bucket_encryption": client_error("ServerSideEncryptionConfigurationNotFoundError"),
            "get_bucket_policy": client_error("AccessDenied"),
            "get_bucket_policy_status": client_error("AccessDenied"),
            "get_bucket_acl": {"Grants": []},
        }
    )
    data = s3_collector.collect(StubSession({"s3": client}), {})
    assert data["buckets"][0]["policy_known"] is False
    assert data["buckets"][0]["policy_is_public"] is None


def test_invalid_values_are_dropped_leaving_a_section_out_entirely():
    from auditor.config import _drop_invalid

    cleaned = _drop_invalid(
        {
            "iam": {"access_key_max_age_days": "ninety", "require_mfa_for_console_users": 1},
            "s3": {"check_encryption": False},
        }
    )
    assert cleaned == {"s3": {"check_encryption": False}}


def test_a_failed_collector_is_reported_on_the_progress_line():
    from auditor import cli, collectors

    seen = []
    original = collectors.COLLECTORS["s3"]
    collectors.COLLECTORS["s3"] = lambda session, config: (_ for _ in ()).throw(RuntimeError("x"))
    try:
        cli.run_scan(object(), ["s3"], {}, "run", on_progress=lambda s, status: seen.append(status))
    finally:
        collectors.COLLECTORS["s3"] = original
    assert seen == ["FAILED"]


def test_an_unknown_rule_id_in_a_filter_exits_with_the_error_code(tmp_path, monkeypatch):
    from auditor import cli

    class FakeSession:
        region_name = "us-east-1"

    monkeypatch.setattr(cli, "build_session", lambda **kwargs: (FakeSession(), None))
    monkeypatch.setattr(cli, "describe_caller", lambda session: ("123456789012", "arn:aws:iam::1:user/a"))
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: ([], [], {}))
    assert (
        cli.main(
            [
                "audit",
                "--rules",
                "IAM-999",
                "--output",
                "none",
                "--output-dir",
                str(tmp_path),
                "--config",
                "missing.yaml",
            ]
        )
        == cli.EXIT_ERROR
    )


def test_validate_policy_reports_a_read_only_violation(monkeypatch, capsys, tmp_path):
    """If the inventory ever gained a write call, the self-audit must fail."""
    import json

    from auditor import cli
    from auditor import permissions as perms

    def explode():
        raise perms.ReadOnlyViolation("Non-read-only operations declared: iam:CreateUser")

    monkeypatch.setattr(perms, "assert_all_read_only", explode)
    path = tmp_path / "p.json"
    path.write_text(json.dumps(perms.generate_policy()))
    assert cli.main(["validate-policy", str(path)]) == cli.EXIT_FINDINGS
    assert "declared calls read-only:    FAIL" in capsys.readouterr().out


def test_terminal_truncates_a_long_collection_error_list(capsys):
    from auditor.models.report import build_report
    from auditor.reporters import terminal

    errors = [
        {
            "service": "S3",
            "operation": "s3:GetBucketAcl",
            "resource": f"b{i}",
            "code": "AccessDenied",
            "category": "access_denied",
            "message": "x",
        }
        for i in range(15)
    ]
    terminal.print_summary(build_report(None, None, [], collection_errors=errors))
    out = capsys.readouterr().out
    assert "and 5 more" in out


def test_policy_analysis_skips_non_string_actions():
    from auditor.rules.policy import analyze_permissions

    result = analyze_permissions(
        {"Statement": [{"Effect": "Allow", "Action": [123, None, "s3:*"], "Resource": "*"}]}
    )
    assert result["service_wildcard"][0]["actions"] == ["s3:*"]


def test_redaction_can_be_disabled_per_identifier_class():
    from auditor.redaction import redact_report

    report = {
        "findings": [{"resource": "user:a/" + "AKIA" + "IOSFODNN7EXAMPLE"}],
        "metadata": {"account_id": "123456789012"},
    }
    untouched = redact_report(report, access_keys=False, account_ids=False)
    assert untouched["findings"][0]["resource"].endswith("IOSFODNN7EXAMPLE")
    assert untouched["metadata"]["account_id"] == "123456789012"
