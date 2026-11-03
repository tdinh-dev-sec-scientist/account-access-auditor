from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from auditor import __version__
from auditor.iac.scanning import (
    InputError,
    ScannerOutputError,
    _directory_candidates,
    classify_input,
    deduplicate_findings,
    map_checkov_severity,
    parse_checkov_output,
    parse_conftest_output,
    scan_paths,
)

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures" / "iac"


def test_classify_inputs_including_terraform_json_and_rendered_helm(tmp_path):
    terraform_json = tmp_path / "main.tf.json"
    terraform_json.write_text('{"resource": {"aws_s3_bucket": {}}}')
    iam_json = tmp_path / "policy.json"
    iam_json.write_text('{"Version": "2012-10-17", "Statement": []}')
    kubernetes_json = tmp_path / "pod.json"
    kubernetes_json.write_text('{"apiVersion": "v1", "kind": "Pod"}')
    manifest = tmp_path / "rendered.yaml"
    manifest.write_text("apiVersion: v1\nkind: Pod\n")
    generic_yaml = tmp_path / "workflow.yaml"
    generic_yaml.write_text("jobs:\n  test:\n    runs-on: ubuntu-latest\n")
    invalid_kubernetes_json = tmp_path / "invalid-pod.json"
    invalid_kubernetes_json.write_text('{"apiVersion": "", "kind": "Pod"}')
    invalid_kubernetes_yaml = tmp_path / "invalid-pod.yaml"
    invalid_kubernetes_yaml.write_text("apiVersion: v1\nkind: ''\n")

    with pytest.raises(InputError, match="Terraform JSON input is not supported"):
        classify_input(terraform_json)
    assert classify_input(iam_json).source_type == "iam"
    assert classify_input(kubernetes_json).source_type == "kubernetes"
    assert classify_input(manifest, helm_rendered=True).source_type == "helm"
    assert classify_input(generic_yaml, strict=False) is None
    with pytest.raises(InputError, match="Kubernetes objects"):
        classify_input(generic_yaml)
    with pytest.raises(InputError, match="non-empty apiVersion and kind"):
        classify_input(invalid_kubernetes_json)
    with pytest.raises(InputError, match="non-empty apiVersion and kind"):
        classify_input(invalid_kubernetes_yaml)


def test_directory_scan_reports_invalid_kubernetes_json(tmp_path):
    directory = tmp_path / "manifests"
    directory.mkdir()
    (directory / "pod.json").write_text('{"apiVersion": "", "kind": "Pod"}')

    candidates, errors = _directory_candidates(directory, tmp_path, helm_rendered=False)

    assert candidates == []
    assert any(error["code"] == "UnsupportedInput" for error in errors)


def test_directory_scan_flags_skipped_symlink_directories(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.tf").write_text('resource "aws_s3_bucket" "example" {}\n')
    linked_target = tmp_path / "linked-target"
    linked_target.mkdir()
    (linked_target / "hidden.tf").write_text('resource "aws_s3_bucket" "hidden" {}\n')
    try:
        (source / "linked").symlink_to(linked_target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    candidates, errors = _directory_candidates(source, tmp_path, helm_rendered=False)

    assert [candidate.path.name for candidate in candidates] == ["main.tf"]
    assert candidates[0].checkov_scope == source
    assert any(error["message"] == "symbolic-link directory skipped" for error in errors)


@pytest.mark.integration
def test_real_checkov_directory_scan_keeps_cross_file_graph_context(tmp_path):
    from shutil import which

    if not which("checkov") or not which("conftest"):
        pytest.skip("Checkov and Conftest are optional local scanner binaries")

    (tmp_path / "bucket.tf").write_text(
        'resource "aws_s3_bucket" "example" {\n  bucket = "review-bucket"\n  acl = "private"\n}\n'
    )
    (tmp_path / "public-access.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "example" {\n'
        '  bucket = aws_s3_bucket.example.id\n'
        '  block_public_acls = true\n'
        '  block_public_policy = true\n'
        '  ignore_public_acls = true\n'
        '  restrict_public_buckets = true\n'
        '}\n'
    )

    report = scan_paths(
        [tmp_path / "bucket.tf", tmp_path], run_id="terraform-graph-context"
    )

    assert "CHECKOV-CKV2_AWS_6" not in {
        finding["control_id"] for finding in report["contract"]["findings"]
    }


@pytest.mark.integration
def test_checkov_directory_scan_honors_excluded_fixture_paths(tmp_path):
    from shutil import which

    if not which("checkov") or not which("conftest"):
        pytest.skip("Checkov and Conftest are optional local scanner binaries")
    vulnerable = tmp_path / "tests" / "fixtures" / "iac"
    vulnerable.mkdir(parents=True)
    (vulnerable / "vulnerable.tf").write_text(
        'resource "aws_s3_bucket" "vulnerable" {\n'
        '  bucket = "excluded-demo-bucket"\n'
        '  acl = "public-read"\n'
        '}\n'
    )
    clean = tmp_path / "infra"
    clean.mkdir()
    (clean / "main.tf").write_text(
        (FIXTURES / "terraform" / "clean" / "main.tf").read_text()
    )

    report = scan_paths(
        [tmp_path],
        root=tmp_path,
        run_id="exclude-fixtures",
        exclude_paths=["tests/fixtures/iac/**"],
    )

    assert report["contract"]["scan_run"]["status"] == "PASS", report["collection_errors"]
    assert report["contract"]["findings"] == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (None, "MEDIUM"),
        ("", "MEDIUM"),
        ("critical", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("medium", "MEDIUM"),
        ("low", "LOW"),
        ("info", "INFO"),
        ("unknown-upstream-tier", "MEDIUM"),
    ],
)
def test_checkov_severity_mapping_is_case_insensitive_and_conservative(source, expected):
    assert map_checkov_severity(source) == expected


def test_checkov_adapter_preserves_upstream_identity_location_and_evidence():
    payload = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_21",
                    "check_name": "S3 versioning must be enabled",
                    "severity": "HIGH",
                    "resource": "aws_s3_bucket.assets",
                    "file_abs_path": "/repo/infra/main.tf",
                    "file_line_range": [8, 14],
                    "evaluated_keys": ["versioning/enabled"],
                    "code_block": [[8, "secret = \"do-not-copy\"\n"]],
                    "check_result": {"result": "FAILED"},
                }
            ],
            "parsing_errors": [],
        },
        "summary": {"checkov_version": "3.4.3"},
    }

    findings = parse_checkov_output(
        json.dumps(payload), source_type="terraform", root=Path("/repo"), run_id="run-1"
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["scanner"] == "checkov"
    assert finding["scanner_rule_id"] == "CKV_AWS_21"
    assert finding["source_type"] == "terraform"
    assert finding["source_location"] == {"file": "infra/main.tf", "line": 8}
    assert finding["resource_reference"] == "aws_s3_bucket.assets"
    assert finding["source_severity"] == "HIGH"
    assert finding["severity"] == "HIGH"
    assert finding["evidence"]["evaluated_keys"] == ["versioning/enabled"]
    assert "do-not-copy" not in json.dumps(finding)


def test_checkov_parser_rejects_malformed_or_incomplete_results():
    with pytest.raises(ScannerOutputError, match="valid JSON"):
        parse_checkov_output("not-json", source_type="terraform", root=Path("."))
    with pytest.raises(ScannerOutputError, match="results"):
        parse_checkov_output("{}", source_type="terraform", root=Path("."))


def test_checkov_parser_accepts_valid_zero_resource_summary():
    payload = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 0,
        "checkov_version": "3.4.3",
    }

    assert parse_checkov_output(
        json.dumps(payload), source_type="terraform", root=Path(".")
    ) == []


def test_conftest_adapter_preserves_policy_metadata_and_file_only_location():
    payload = [
        {
            "filename": "/repo/k8s/pod.yaml",
            "namespace": "main",
            "successes": 2,
            "failures": [
                {
                    "msg": "privileged containers are prohibited",
                    "metadata": {
                        "query": "data.main.deny",
                        "metadata": {
                            "control_id": "IAC-K8S-001",
                            "severity": "HIGH",
                            "title": "Privileged container",
                            "remediation": "Disable privileged mode.",
                        },
                    },
                }
            ],
        }
    ]

    findings = parse_conftest_output(
        json.dumps(payload), source_type="kubernetes", root=Path("/repo"), run_id="run-2"
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["control_id"] == "IAC-K8S-001"
    assert finding["scanner"] == "conftest"
    assert finding["scanner_rule_id"] == "data.main.deny"
    assert finding["source_location"] == {"file": "k8s/pod.yaml"}
    assert finding["source_severity"] == "HIGH"
    assert finding["severity"] == "HIGH"
    assert finding["evidence"]["message"] == "privileged containers are prohibited"


def test_conftest_parser_rejects_unusable_output():
    with pytest.raises(ScannerOutputError, match="valid JSON"):
        parse_conftest_output("{", source_type="iam", root=Path("."))
    with pytest.raises(ScannerOutputError, match="result list"):
        parse_conftest_output("{}", source_type="iam", root=Path("."))


def test_deduplication_uses_control_source_and_resource_not_message():
    first = {
        "control_id": "IAC-K8S-001",
        "scanner": "conftest",
        "scanner_rule_id": "data.main.deny",
        "source_type": "kubernetes",
        "resource_reference": "Deployment/api",
        "source_location": None,
        "severity": "HIGH",
        "title": "Privileged container",
        "description": "first description",
        "evidence": {"message": "first"},
        "remediation": "Disable privileged mode.",
        "references": [],
        "fingerprint": "same",
        "lifecycle_state": "open",
        "detected_at": "2026-01-01T00:00:00+00:00",
        "run_id": "run-1",
    }
    duplicate = {**first, "evidence": {"message": "second"}}
    other_source = {**first, "source_type": "helm"}

    findings = deduplicate_findings([first, duplicate, other_source])

    assert len(findings) == 2
    kubernetes = next(finding for finding in findings if finding["source_type"] == "kubernetes")
    assert kubernetes["evidence"]["observations"] == [
        {"message": "first"},
        {"message": "second"},
    ]


def test_local_scan_reports_iam_findings_and_never_passes_aws_credentials(monkeypatch, tmp_path):
    env = {
        "AWS_ACCESS_KEY_ID": "AKIAEXAMPLESECRET",
        "AWS_SECRET_ACCESS_KEY": "do-not-forward",
        "AWS_SESSION_TOKEN": "session-secret",
        "GITHUB_TOKEN": "github-secret",
        "ACTIONS_RUNTIME_TOKEN": "runtime-secret",
        "AZURE_CLIENT_SECRET": "azure-secret",
        "KUBECONFIG": "/tmp/secret-kubeconfig",
        "PATH": os.environ.get("PATH", ""),
    }
    monkeypatch.setattr("auditor.iac.scanning.os.environ", env)
    calls = []

    def fake_run(command, *, capture_output, text, check, timeout, env):
        calls.append((command, env))
        if "--version" in command:
            stdout = "3.4.3" if command[0] == "checkov" else "Conftest: 0.71.1\nOPA: 1.21.1"
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        if command[0] == "checkov":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"results": {"failed_checks": [], "parsing_errors": []}, "summary": {}}),
                stderr="",
            )
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{"filename": command[-1], "namespace": "main", "successes": 1}]),
            stderr="",
        )

    monkeypatch.setattr("auditor.iac.scanning.shutil.which", lambda name: name)
    monkeypatch.setattr("auditor.iac.scanning.subprocess.run", fake_run)

    report = scan_paths(
        [FIXTURES / "iam" / "vulnerable-policy.json", FIXTURES / "kubernetes" / "clean.yaml"],
        run_id="offline-1",
    )

    assert report["contract"]["scan_run"]["status"] == "FAIL"
    assert report["contract"]["scan_run"]["scanner_versions"] == {
        "account-access-auditor": __version__,
        "checkov": "3.4.3",
        "conftest": "0.71.1",
        "opa": "1.21.1",
    }
    assert any(f["control_id"] == "IAM-004" for f in report["contract"]["findings"])
    assert calls
    for _, scanner_env in calls:
        assert "AWS_ACCESS_KEY_ID" not in scanner_env
        assert "AWS_SECRET_ACCESS_KEY" not in scanner_env
        assert "AWS_SESSION_TOKEN" not in scanner_env
        assert "GITHUB_TOKEN" not in scanner_env
        assert "ACTIONS_RUNTIME_TOKEN" not in scanner_env
        assert "AZURE_CLIENT_SECRET" not in scanner_env
        assert "KUBECONFIG" not in scanner_env
        assert scanner_env["AWS_EC2_METADATA_DISABLED"] == "true"
    checkov_call = next(command for command, _ in calls if command[0] == "checkov" and "--version" not in command)
    assert "--skip-download" in checkov_call
    assert "--skip-results-upload" in checkov_call
    report_json = json.dumps(report)
    assert "AKIAEXAMPLESECRET" not in report_json
    assert "do-not-forward" not in report_json
    assert "session-secret" not in report_json
    assert "github-secret" not in report_json
    assert "runtime-secret" not in report_json
    assert "azure-secret" not in report_json


def test_clean_and_vulnerable_project_fixtures_cover_each_input_family():
    expected = {
        "terraform": ("clean/main.tf", "vulnerable/main.tf"),
        "iam": ("clean-policy.json", "vulnerable-policy.json"),
        "kubernetes": ("clean.yaml", "vulnerable.yaml"),
        "helm": ("clean-rendered.yaml", "vulnerable-rendered.yaml"),
    }
    for kind, (clean, vulnerable) in expected.items():
        assert (FIXTURES / kind / clean).is_file()
        assert (FIXTURES / kind / vulnerable).is_file()
    assert (FIXTURES / "iam" / "vulnerable-service-policy.json").is_file()


def test_malformed_iam_policy_is_an_error_not_a_clean_result(monkeypatch, tmp_path):
    malformed = tmp_path / "policy.json"
    malformed.write_text(json.dumps({"Version": "2012-10-17", "Statement": "Allow:*"}))

    def fake_run(command, *, capture_output, text, check, timeout, env):
        if "--version" in command:
            stdout = "Conftest: 0.71.1\nOPA: 1.21.1"
        else:
            stdout = json.dumps([{"filename": command[-1], "namespace": "main", "successes": 1}])
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr("auditor.iac.scanning.shutil.which", lambda name: name)
    monkeypatch.setattr("auditor.iac.scanning.subprocess.run", fake_run)
    report = scan_paths([malformed], run_id="malformed-policy")

    assert report["contract"]["scan_run"]["status"] == "ERROR"
    assert report["contract"]["scan_run"]["exit_code"] == 2
    assert report["collection_errors"][0]["operation"] == "iam-policy"


def test_missing_conftest_is_an_error_even_when_the_iam_policy_is_clean(monkeypatch):
    monkeypatch.setattr("auditor.iac.scanning.shutil.which", lambda name: None)
    report = scan_paths([FIXTURES / "iam" / "clean-policy.json"], run_id="missing-tool")

    assert report["contract"]["scan_run"]["status"] == "ERROR"
    assert report["contract"]["scan_run"]["exit_code"] == 2
    assert report["collection_errors"][0]["code"] == "ScannerUnavailable"


def test_empty_input_is_an_error_not_a_clean_scan():
    report = scan_paths([], run_id="empty-scan")

    assert report["contract"]["scan_run"]["status"] == "ERROR"
    assert report["contract"]["scan_run"]["exit_code"] == 2
    assert report["collection_errors"][0]["code"] == "EmptyInput"


def test_scan_threshold_controls_gate_without_removing_findings(monkeypatch):
    def fake_run(command, *, capture_output, text, check, timeout, env):
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Conftest: 0.71.1\nOPA: 1.21.1", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{"filename": command[-1], "namespace": "main", "successes": 1}]),
            stderr="",
        )

    monkeypatch.setattr("auditor.iac.scanning.shutil.which", lambda name: name)
    monkeypatch.setattr("auditor.iac.scanning.subprocess.run", fake_run)

    report = scan_paths(
        [FIXTURES / "iam" / "vulnerable-service-policy.json"],
        run_id="threshold-scan",
        fail_on="CRITICAL",
    )

    assert report["contract"]["scan_run"]["status"] == "PASS"
    assert report["contract"]["scan_run"]["gate_threshold"] == "CRITICAL"
    assert report["contract"]["findings"]
    assert all(finding["gate"] is False for finding in report["findings"])


def test_active_exception_is_applied_to_iac_report_without_hiding_finding(
    monkeypatch, tmp_path
):
    exceptions_path = tmp_path / "exceptions.yaml"
    exceptions_path.write_text(
        "exceptions:\n"
        "  - id: EXC-SERVICE-POLICY\n"
        "    control_id: IAM-005\n"
        "    source_file: tests/fixtures/iac/iam/vulnerable-service-policy.json\n"
        "    owner: platform-team\n"
        "    reason: approved for the migration window\n"
        "    created_at: '2026-01-01T00:00:00Z'\n"
        "    expires_at: '2027-01-01T00:00:00Z'\n"
    )

    def fake_run(command, *, capture_output, text, check, timeout, env):
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Conftest: 0.71.1\nOPA: 1.21.1", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{"filename": command[-1], "namespace": "main", "successes": 1}]),
            stderr="",
        )

    monkeypatch.setattr("auditor.iac.scanning.shutil.which", lambda name: name)
    monkeypatch.setattr("auditor.iac.scanning.subprocess.run", fake_run)

    report = scan_paths(
        [FIXTURES / "iam" / "vulnerable-service-policy.json"],
        run_id="exception-scan",
        fail_on="HIGH",
        exceptions_path=exceptions_path,
    )

    assert report["contract"]["scan_run"]["status"] == "PASS"
    assert report["summary"]["gate_violations"] == 0
    assert len(report["contract"]["findings"]) == 1
    assert report["contract"]["findings"][0]["gate"] is False
    assert report["contract"]["findings"][0]["exceptions"][0]["id"] == "EXC-SERVICE-POLICY"
    assert report["contract"]["exceptions"][0]["state"] == "MATCHED_ACTIVE"


def test_invalid_exception_file_is_an_error_and_does_not_suppress(monkeypatch, tmp_path):
    exceptions_path = tmp_path / "exceptions.yaml"
    exceptions_path.write_text("exceptions: [\n")

    def fake_run(command, *, capture_output, text, check, timeout, env):
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="Conftest: 0.71.1\nOPA: 1.21.1", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{"filename": command[-1], "namespace": "main", "successes": 1}]),
            stderr="",
        )

    monkeypatch.setattr("auditor.iac.scanning.shutil.which", lambda name: name)
    monkeypatch.setattr("auditor.iac.scanning.subprocess.run", fake_run)

    report = scan_paths(
        [FIXTURES / "iam" / "vulnerable-service-policy.json"],
        run_id="bad-exception-file",
        fail_on="HIGH",
        exceptions_path=exceptions_path,
    )

    assert report["contract"]["scan_run"]["status"] == "ERROR"
    assert report["contract"]["scan_run"]["exit_code"] == 2
    assert report["contract"]["findings"][0]["gate"] is True
    assert report["contract"]["exceptions"] == []
    assert any(error["code"] == "InvalidExceptionFile" for error in report["collection_errors"])


def test_allow_empty_and_excludes_make_clean_repository_scan_pass(monkeypatch, tmp_path):
    source = tmp_path / "tests" / "fixtures" / "iac"
    source.mkdir(parents=True)
    (source / "vulnerable.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\n"
        "spec:\n  containers:\n  - name: app\n    image: nginx:latest\n"
    )
    monkeypatch.setattr("auditor.iac.scanning.shutil.which", lambda name: None)

    report = scan_paths(
        [tmp_path],
        root=tmp_path,
        run_id="empty-allowed",
        allow_empty=True,
        exclude_paths=["tests/fixtures/iac/**"],
    )

    assert report["contract"]["scan_run"]["status"] == "PASS"
    assert report["contract"]["findings"] == []
    assert report["collection_errors"] == []


def test_scanner_timeout_is_reported_as_error_not_clean(monkeypatch):
    def fake_run(command, *, capture_output, text, check, timeout, env):
        if "--version" in command:
            stdout = "3.4.3" if command[0] == "checkov" else "Conftest: 0.71.1\nOPA: 1.21.1"
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        if command[0] == "checkov":
            raise subprocess.TimeoutExpired(command, timeout)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{"filename": command[-1], "namespace": "main", "successes": 1}]),
            stderr="",
        )

    monkeypatch.setattr("auditor.iac.scanning.shutil.which", lambda name: name)
    monkeypatch.setattr("auditor.iac.scanning.subprocess.run", fake_run)
    report = scan_paths([FIXTURES / "terraform" / "clean" / "main.tf"], run_id="timeout")

    assert report["contract"]["scan_run"]["status"] == "ERROR"
    assert report["contract"]["scan_run"]["exit_code"] == 2
    assert any(error["code"] == "ScannerFailure" for error in report["collection_errors"])


@pytest.mark.integration
@pytest.mark.parametrize(
    ("kind", "fixture", "expected_controls"),
    [
        (
            "terraform",
            "terraform/vulnerable/main.tf",
            {
                "IAC-TF-001",
                "CHECKOV-CKV_AWS_20",
                "CHECKOV-CKV_AWS_21",
                "CHECKOV-CKV_AWS_145",
                "CHECKOV-CKV2_AWS_6",
            },
        ),
        (
            "kubernetes",
            "kubernetes/vulnerable.yaml",
            {
                "IAC-K8S-001",
                "IAC-K8S-002",
                "IAC-K8S-003",
                "CHECKOV-CKV_K8S_20",
                "CHECKOV-CKV_K8S_29",
                "CHECKOV-CKV_K8S_43",
            },
        ),
        (
            "helm",
            "helm/vulnerable-rendered.yaml",
            {
                "IAC-K8S-001",
                "IAC-K8S-002",
                "IAC-K8S-003",
                "CHECKOV-CKV_K8S_20",
                "CHECKOV-CKV_K8S_29",
                "CHECKOV-CKV_K8S_43",
            },
        ),
        ("iam", "iam/vulnerable-policy.json", {"IAM-004"}),
        ("iam", "iam/vulnerable-service-policy.json", {"IAM-005"}),
    ],
)
def test_real_scanners_detect_vulnerable_fixtures(kind, fixture, expected_controls):
    from shutil import which

    if not which("conftest") or (kind != "iam" and not which("checkov")):
        pytest.skip("Checkov and Conftest are optional local scanner binaries")

    report = scan_paths([FIXTURES / fixture], helm_rendered=kind == "helm", run_id="real-scan")
    findings = report["contract"]["findings"]
    assert report["contract"]["scan_run"]["status"] == "FAIL"
    assert expected_controls <= {finding["control_id"] for finding in findings}


@pytest.mark.integration
@pytest.mark.parametrize(
    ("fixture", "helm_rendered"),
    [
        ("terraform/clean/main.tf", False),
        ("iam/clean-policy.json", False),
        ("kubernetes/clean.yaml", False),
        ("helm/clean-rendered.yaml", True),
    ],
)
def test_real_scanners_accept_clean_fixtures(fixture, helm_rendered):
    from shutil import which

    if not which("conftest") or (fixture.startswith(("terraform/", "kubernetes/", "helm/")) and not which("checkov")):
        pytest.skip("Checkov and Conftest are optional local scanner binaries")

    report = scan_paths([FIXTURES / fixture], helm_rendered=helm_rendered, run_id="clean-scan")
    assert report["contract"]["scan_run"]["status"] == "PASS", report["collection_errors"]
    assert report["contract"]["findings"] == []
