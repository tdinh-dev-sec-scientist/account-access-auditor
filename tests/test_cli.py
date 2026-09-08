"""CLI: argument parsing, filtering, exit codes, and each subcommand."""

from __future__ import annotations

import json

import pytest

from auditor import cli
from auditor.models.finding import Finding
from auditor.rules import engine
from auditor.severity import Severity

# ------------------------------------------------------------- parsing ----


def test_all_expands_to_the_canonical_service_order():
    assert cli.parse_services("all") == ["iam", "s3", "cloudtrail"]


def test_services_are_returned_in_canonical_order_regardless_of_input():
    assert cli.parse_services("cloudtrail,iam") == ["iam", "cloudtrail"]
    assert cli.parse_services(" S3 , IAM ") == ["iam", "s3"]


@pytest.mark.parametrize("value", ["ec2", "iam,ec2", ""])
def test_unknown_or_empty_service_lists_are_rejected(value):
    with pytest.raises(ValueError):
        cli.parse_services(value)


def test_output_formats_keep_a_stable_order():
    assert cli.parse_outputs("csv,json") == ["json", "csv"]
    assert cli.parse_outputs("tickets") == ["tickets"]


def test_none_suppresses_all_file_output():
    assert cli.parse_outputs("none") == []
    assert cli.parse_outputs("json,none") == []


def test_unknown_output_format_is_rejected():
    with pytest.raises(ValueError, match="Unknown output format"):
        cli.parse_outputs("pdf")


def test_rule_lists_are_upper_cased_and_trimmed():
    assert cli.parse_rule_list(" iam-004 , s3-002 ") == ["IAM-004", "S3-002"]
    assert cli.parse_rule_list(None) is None


# ----------------------------------------------------------- filtering ----


@pytest.fixture
def findings():
    return [
        Finding.build("IAM-004", "user:a/p", "d"),  # CRITICAL
        Finding.build("IAM-002", "user:a/k", "d", severity=Severity.MEDIUM),
        Finding.build("IAM-006", "user:b", "d"),  # INFO
        Finding.build("S3-001", "bucket", "d"),  # MEDIUM
    ]


def test_severity_filter_keeps_everything_at_or_above_the_threshold(findings):
    assert len(engine.filter_findings(findings, min_severity="medium")) == 3
    assert len(engine.filter_findings(findings, min_severity="critical")) == 1
    assert len(engine.filter_findings(findings, min_severity="info")) == 4


def test_rule_filters_include_and_exclude(findings):
    assert {f.rule_id for f in engine.filter_findings(findings, rule_ids=["IAM-004"])} == {"IAM-004"}
    remaining = engine.filter_findings(findings, exclude_rule_ids=["IAM-006", "S3-001"])
    assert {f.rule_id for f in remaining} == {"IAM-004", "IAM-002"}


def test_service_filter(findings):
    assert len(engine.filter_findings(findings, services=["s3"])) == 1


def test_a_typo_in_a_rule_id_is_an_error_not_a_clean_account(findings):
    """--rules IAM-04 must not silently match nothing and look like success."""
    with pytest.raises(ValueError, match="Unknown rule id"):
        engine.filter_findings(findings, rule_ids=["IAM-04"])


def test_filters_compose(findings):
    result = engine.filter_findings(findings, min_severity="medium", exclude_rule_ids=["S3-001"])
    assert {f.rule_id for f in result} == {"IAM-004", "IAM-002"}


def test_sort_findings_is_stable_and_severity_first(findings):
    assert [f.severity.value for f in engine.sort_findings(findings)] == [
        "CRITICAL",
        "MEDIUM",
        "MEDIUM",
        "INFO",
    ]


# ---------------------------------------------------------- subcommands ---


def test_no_subcommand_prints_help_and_fails(capsys):
    assert cli.main([]) == cli.EXIT_ERROR
    assert "usage:" in capsys.readouterr().out


def test_list_rules_prints_all_fourteen(capsys):
    assert cli.main(["list-rules"]) == cli.EXIT_OK
    assert "14 rules." in capsys.readouterr().out


def test_list_rules_json_is_machine_readable(capsys):
    assert cli.main(["list-rules", "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 14
    assert payload[0]["compliance"]["control_id"] == "1.10"


def test_list_rules_filters_by_service(capsys):
    assert cli.main(["list-rules", "--service", "s3", "--json"]) == cli.EXIT_OK
    assert len(json.loads(capsys.readouterr().out)) == 4


def test_list_rules_rejects_an_unknown_service(capsys):
    assert cli.main(["list-rules", "--service", "ec2"]) == cli.EXIT_ERROR


def test_list_permissions_reports_that_every_call_is_read_only(capsys):
    assert cli.main(["list-permissions"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "all read-only: True" in out
    assert "iam:ListUsers" in out


def test_list_permissions_json_matches_the_inventory(capsys):
    assert cli.main(["list-permissions", "--json"]) == cli.EXIT_OK
    rows = json.loads(capsys.readouterr().out)
    from auditor.permissions import API_CALLS

    assert len(rows) == len(API_CALLS)
    assert all(row["read_only"] for row in rows)


def test_generate_policy_writes_a_regenerable_file(tmp_path, capsys):
    path = tmp_path / "p.json"
    assert cli.main(["generate-policy", "--write", "--path", str(path)]) == cli.EXIT_OK
    from auditor.permissions import generate_policy

    assert json.loads(path.read_text()) == generate_policy()


def test_generate_policy_to_stdout_by_default(capsys):
    assert cli.main(["generate-policy"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["Version"] == "2012-10-17"


# -------------------------------------------------------- self-audit ------


def test_validate_policy_passes_on_the_projects_own_policy(capsys):
    assert cli.main(["validate-policy"]) == cli.EXIT_OK
    assert "RESULT: PASS" in capsys.readouterr().out


def test_validate_policy_json_reports_the_full_result(capsys):
    assert cli.main(["validate-policy", "--json"]) == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result["passed"] is True
    assert result["wildcard_findings"] == []
    assert result["declared_operations_all_read_only"] is True
    assert result["statements"] == 10


def test_validate_policy_fails_on_an_admin_policy(tmp_path, capsys):
    """The detector must not have been weakened to let the project's policy pass."""
    path = tmp_path / "admin.json"
    path.write_text(
        json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        )
    )
    assert cli.main(["validate-policy", str(path)]) == cli.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "IAM-004 (Action * on *):     FAIL" in out
    assert "RESULT: FAIL" in out


def test_validate_policy_fails_on_a_service_wide_policy(tmp_path):
    path = tmp_path / "broad.json"
    path.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["iam:*", "s3:*"], "Resource": "*"}],
            }
        )
    )
    assert cli.main(["validate-policy", str(path)]) == cli.EXIT_FINDINGS


def test_validate_policy_reports_a_missing_or_invalid_file(tmp_path):
    assert cli.main(["validate-policy", str(tmp_path / "nope.json")]) == cli.EXIT_ERROR
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert cli.main(["validate-policy", str(bad)]) == cli.EXIT_ERROR


# ------------------------------------------------------------- audit ------


@pytest.mark.usefixtures("aws")
def test_audit_end_to_end_against_an_emulated_account(tmp_path, capsys):
    import boto3

    session = boto3.session.Session(region_name="us-east-1")
    session.client("s3").create_bucket(Bucket="cli-test-bucket")

    code = cli.main(
        [
            "audit",
            "--services",
            "s3",
            "--output",
            "json,csv,tickets",
            "--output-dir",
            str(tmp_path),
            "--config",
            str(tmp_path / "absent.yaml"),
            "--region",
            "us-east-1",
            "--environment-label",
            "unit-test",
        ]
    )
    assert code == cli.EXIT_OK

    written = sorted(p.suffix for p in tmp_path.iterdir())
    assert written == [".csv", ".json", ".txt"]

    report = json.loads(next(tmp_path.glob("audit-*.json")).read_text())
    assert report["metadata"]["environment"] == "unit-test"
    assert report["metadata"]["services_scanned"] == ["S3"]
    assert report["summary"]["resources_scanned"] == {"s3_buckets": 1}
    assert report["summary"]["api_call_count"] > 0
    assert {f["rule_id"] for f in report["findings"]} == {"S3-001", "S3-004"}


@pytest.mark.usefixtures("aws")
def test_fail_on_returns_a_nonzero_exit_code(tmp_path):
    import boto3

    boto3.session.Session(region_name="us-east-1").client("s3").create_bucket(Bucket="failon-bucket")
    code = cli.main(
        [
            "audit",
            "--services",
            "s3",
            "--output",
            "none",
            "--output-dir",
            str(tmp_path),
            "--config",
            "missing.yaml",
            "--fail-on",
            "medium",
        ]
    )
    assert code == cli.EXIT_FINDINGS


@pytest.mark.usefixtures("aws")
def test_severity_filter_can_suppress_every_finding(tmp_path):
    import boto3

    boto3.session.Session(region_name="us-east-1").client("s3").create_bucket(Bucket="sev-bucket")
    code = cli.main(
        [
            "audit",
            "--services",
            "s3",
            "--output",
            "none",
            "--output-dir",
            str(tmp_path),
            "--config",
            "missing.yaml",
            "--severity",
            "critical",
            "--fail-on",
            "info",
        ]
    )
    assert code == cli.EXIT_OK  # nothing survived the filter, so nothing to fail on


@pytest.mark.usefixtures("aws")
def test_redaction_masks_key_ids_in_the_written_report(tmp_path):
    import boto3

    session = boto3.session.Session(region_name="us-east-1")
    iam_client = session.client("iam")
    iam_client.create_user(UserName="redact-me")
    iam_client.create_access_key(UserName="redact-me")

    cli.main(
        [
            "audit",
            "--services",
            "iam",
            "--output",
            "json",
            "--output-dir",
            str(tmp_path),
            "--config",
            "missing.yaml",
            "--redact",
        ]
    )
    payload = next(tmp_path.glob("audit-*.json")).read_text()
    assert "…" in payload or "AKIA" not in payload


def test_bad_credentials_exit_with_the_error_code_not_a_traceback(monkeypatch, tmp_path):
    from auditor import aws_session

    def explode(*args, **kwargs):
        raise aws_session.SessionError("no credentials")

    monkeypatch.setattr(cli, "describe_caller", explode)
    assert (
        cli.main(["audit", "--output", "none", "--output-dir", str(tmp_path), "--config", "missing.yaml"])
        == cli.EXIT_ERROR
    )


def test_invalid_arguments_exit_with_the_error_code(tmp_path):
    assert cli.main(["audit", "--services", "ec2", "--output-dir", str(tmp_path)]) == cli.EXIT_ERROR
    assert cli.main(["audit", "--output", "pdf", "--output-dir", str(tmp_path)]) == cli.EXIT_ERROR


def test_strict_config_failure_exits_with_the_error_code(tmp_path):
    config = tmp_path / "bad.yaml"
    config.write_text("iam:\n  bogus: 1\n")
    assert (
        cli.main(
            [
                "audit",
                "--strict-config",
                "--config",
                str(config),
                "--output",
                "none",
                "--output-dir",
                str(tmp_path),
            ]
        )
        == cli.EXIT_ERROR
    )


def test_a_broken_collector_is_recorded_as_an_error_not_a_crash(monkeypatch):
    from auditor import collectors

    monkeypatch.setitem(
        collectors.COLLECTORS,
        "s3",
        lambda session, config: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    findings, errors, counts = cli.run_scan(object(), ["s3"], {}, "run")
    assert findings == [] and counts == {}
    assert errors[0]["code"] == "RuntimeError"


def test_version_flag_reports_the_tool_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "account-access-auditor" in capsys.readouterr().out
