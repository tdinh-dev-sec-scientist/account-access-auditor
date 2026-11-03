from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from auditor import remediation


def test_cli_exposes_reviewable_remediation_preview(capsys):
    from auditor import cli

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["remediation-preview", "--help"])

    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "--source" in help_text
    assert "--plan" in help_text


def test_cli_exposes_explicit_sandbox_only_rescan(capsys):
    from auditor import cli

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["remediation-sandbox", "--help"])

    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "--confirm-sandbox" in help_text
    assert "--profile" not in help_text


def _source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.tf").write_text('resource "aws_s3_bucket" "data" {\n  acl = "public-read"\n}\n')
    return source


def _pending_plan():
    return {
        "schema_version": remediation.SCHEMA_VERSION,
        "target": "sandbox",
        "review": {"status": "PENDING"},
        "target_fingerprints": ["a1b2c3d4e5f60718"],
        "operations": [
            {
                "op": "replace_text",
                "path": "main.tf",
                "before": 'acl = "public-read"',
                "after": 'acl = "private"',
            }
        ],
    }


def _approved_plan(source):
    plan = _pending_plan()
    preview = remediation.create_remediation_preview(source_dir=source, plan=plan)
    plan["review"] = {
        "status": "APPROVED",
        "reviewer": "security-lead",
        "reference": "https://github.com/example/auditor/pull/42",
        "preview_sha256": preview["preview_sha256"],
    }
    return plan


def _scan_result(*, status="PASS", gate_status="PASS", fingerprints=()):
    findings = [{"fingerprint": fingerprint} for fingerprint in fingerprints]
    return {
        "metadata": {"scan_source": "local-iac", "aws_accessed": False},
        "summary": {"status": status, "gate_status": gate_status},
        "findings": findings,
        "contract": {
            "findings": findings,
            "scan_run": {"status": status, "gate_status": gate_status},
        },
    }


def _github_preview(preview_sha256, *, contents='acl = "private"\n'):
    return {
        "preview_sha256": preview_sha256,
        "changed_files": [
            {
                "path": "main.tf",
                "after_sha256": hashlib.sha256(contents.encode("utf-8")).hexdigest(),
            }
        ],
    }


def _github_pull(preview_sha256, *, head="c" * 40):
    return {
        "state": "OPEN",
        "reviewDecision": "APPROVED",
        "body": f"Remediation Preview SHA-256: {preview_sha256}",
        "headRefOid": head,
    }


def _github_approval(*, state="APPROVED", head="c" * 40):
    return [[
        {
            "user": {"login": "security-lead"},
            "state": state,
            "submitted_at": "2026-11-02T10:00:00Z",
            "commit_id": head,
        }
    ]]


def _github_file_responses(contents='acl = "private"\n'):
    blob_sha = "a" * 40
    return [
        [[{"filename": "main.tf", "status": "modified", "sha": blob_sha}]],
        {"sha": blob_sha},
        {
            "encoding": "base64",
            "content": base64.b64encode(contents.encode("utf-8")).decode("ascii"),
        },
    ]


def _use_example_github_origin(monkeypatch):
    monkeypatch.setattr(
        remediation,
        "_github_source_context",
        lambda _source: ("example", "auditor", ""),
    )


def test_preview_returns_a_patch_without_changing_source(tmp_path):
    source = _source(tmp_path)
    original = (source / "main.tf").read_text()

    preview = remediation.create_remediation_preview(source_dir=source, plan=_pending_plan())

    assert preview["status"] == "PREVIEW"
    assert preview["review"]["status"] == "PENDING"
    assert preview["target_fingerprints"] == ["a1b2c3d4e5f60718"]
    assert "acl = \"public-read\"" in preview["patch"]
    assert "acl = \"private\"" in preview["patch"]
    assert len(preview["preview_sha256"]) == 64
    assert (source / "main.tf").read_text() == original


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target", "production", "production remediation is never applied"),
        ("target", "aws-sandbox", "target must be the isolated local sandbox"),
    ],
)
def test_preview_rejects_non_sandbox_targets(tmp_path, field, value, message):
    plan = _pending_plan()
    plan[field] = value

    with pytest.raises(remediation.RemediationError, match=message):
        remediation.create_remediation_preview(source_dir=_source(tmp_path), plan=plan)


def test_preview_rejects_malformed_review_status(tmp_path):
    plan = _pending_plan()
    plan["review"] = {"status": []}

    with pytest.raises(remediation.RemediationError, match="review must be"):
        remediation.create_remediation_preview(source_dir=_source(tmp_path), plan=plan)


@pytest.mark.parametrize("path", ["../outside.tf", "/tmp/outside.tf", "nested/*.tf", "main.py"])
def test_preview_rejects_unsafe_or_non_iac_paths(tmp_path, path):
    source = _source(tmp_path)
    plan = _pending_plan()
    plan["operations"][0]["path"] = path

    with pytest.raises(remediation.RemediationError):
        remediation.create_remediation_preview(source_dir=source, plan=plan)


def test_preview_rejects_sensitive_paths_even_when_the_file_is_json(tmp_path):
    source = _source(tmp_path)
    target = source / ".aws" / "cli" / "cache" / "credentials.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"SecretAccessKey": "not-a-real-key"}\n')
    plan = _pending_plan()
    plan["operations"][0]["path"] = ".aws/cli/cache/credentials.json"
    plan["operations"][0]["before"] = "not-a-real-key"
    plan["operations"][0]["after"] = "redacted"

    with pytest.raises(remediation.RemediationError, match="sensitive source paths"):
        remediation.create_remediation_preview(source_dir=source, plan=plan)


@pytest.mark.parametrize(
    ("filename", "original", "before", "after"),
    [
        (
            "main.tf",
            'resource "demo" "item" {\n'
            '  SecretAccessKey = "synthetic-camel-case-secret-value"\n'
            '  acl = "public-read"\n'
            '}\n',
            'acl = "public-read"',
            'acl = "private"',
        ),
        (
            "main.json",
            '{"acl": "public-read", "SecretAccessKey": "synthetic-json-secret-value"}\n',
            '"public-read"',
            '"private"',
        ),
        (
            "main.yaml",
            "acl: public-read\nSecretAccessKey: synthetic-unquoted-secret-value\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\nSecretAccessKey: >-\n  synthetic-block-scalar-secret-value\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\nSecretAccessKey: !!str |\n  synthetic-tagged-secret-value\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\nSecretAccessKey: &secret >-\n  synthetic-anchored-secret-value\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\n? SecretAccessKey\n: |-\n  synthetic-explicit-key-secret-value\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\ncredentials:\n  - SecretAccessKey: |-\n      synthetic-sequence-secret-value\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\nSecretAccessKey: |-\n\n  synthetic-blank-line-secret-value\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            'acl: public-read\nSecretAccessKey: "syntheti\\\n  csecretvalu"\n',
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\ncredentials: |-\n  synthetic-credential-value\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\nprivateKey: |-\n  synthetic-unarmored-key-material\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\nAuthorization: |-\n  Bearer synthetic-long-token\n",
            "acl: public-read",
            "acl: private",
        ),
        (
            "main.yaml",
            "acl: public-read\npassphrase: |-\n  synthetic-passphrase-material\n",
            "acl: public-read",
            "acl: private",
        ),
    ],
)
def test_preview_rejects_camel_case_secrets_in_changed_file(
    tmp_path, filename, original, before, after
):
    source = _source(tmp_path)
    (source / filename).write_text(original)
    plan = _pending_plan()
    plan["operations"][0]["path"] = filename
    plan["operations"][0]["before"] = before
    plan["operations"][0]["after"] = after

    with pytest.raises(remediation.RemediationError, match="credential or private-key material"):
        remediation.create_remediation_preview(source_dir=source, plan=plan)


@pytest.mark.parametrize(
    "case",
    [
        "not_object",
        "missing_field",
        "schema_version",
        "production_target",
        "unknown_target",
        "review_not_object",
        "review_status_type",
        "review_status_unknown",
        "pending_metadata",
        "pending_requires_approval",
        "approved_metadata",
        "reviewer",
        "reference",
        "digest",
        "fingerprints_type",
        "fingerprints_empty",
        "fingerprints_too_many",
        "fingerprints_malformed",
        "fingerprints_duplicate",
        "operations_type",
        "operations_empty",
        "operations_too_many",
        "operation_type",
        "operation_fields",
        "operation_type_unknown",
        "path_invalid",
        "before_type",
        "after_type",
        "before_empty",
        "after_empty",
        "before_too_long",
        "after_too_long",
        "same_text",
        "before_nul",
        "after_nul",
        "sensitive_before",
        "sensitive_after",
    ],
)
def test_plan_validation_rejects_invalid_inputs(case):
    plan = _pending_plan()
    operation = plan["operations"][0]
    require_approval = case == "pending_requires_approval"
    if case == "not_object":
        plan = []
    elif case == "missing_field":
        plan.pop("target")
    elif case == "schema_version":
        plan["schema_version"] = "99.0.0"
    elif case == "production_target":
        plan["target"] = "production"
    elif case == "unknown_target":
        plan["target"] = "elsewhere"
    elif case == "review_not_object":
        plan["review"] = []
    elif case == "review_status_type":
        plan["review"] = {"status": None}
    elif case == "review_status_unknown":
        plan["review"] = {"status": "DENIED"}
    elif case == "pending_metadata":
        plan["review"]["reviewer"] = "someone"
    elif case == "approved_metadata":
        plan["review"] = {
            "status": "APPROVED",
            "reviewer": "security-lead",
            "reference": "https://github.com/example/auditor/pull/42",
            "preview_sha256": "a" * 64,
            "unexpected": True,
        }
    elif case == "reviewer":
        plan["review"] = {
            "status": "APPROVED",
            "reviewer": "not a login",
            "reference": "https://github.com/example/auditor/pull/42",
            "preview_sha256": "a" * 64,
        }
    elif case == "reference":
        plan["review"] = {
            "status": "APPROVED",
            "reviewer": "security-lead",
            "reference": "http://github.com/example/auditor/pull/42",
            "preview_sha256": "a" * 64,
        }
    elif case == "digest":
        plan["review"] = {
            "status": "APPROVED",
            "reviewer": "security-lead",
            "reference": "https://github.com/example/auditor/pull/42",
            "preview_sha256": "A" * 64,
        }
    elif case == "fingerprints_type":
        plan["target_fingerprints"] = "a1b2c3d4e5f60718"
    elif case == "fingerprints_empty":
        plan["target_fingerprints"] = []
    elif case == "fingerprints_too_many":
        plan["target_fingerprints"] = [f"{index:016x}" for index in range(101)]
    elif case == "fingerprints_malformed":
        plan["target_fingerprints"] = ["not-a-fingerprint"]
    elif case == "fingerprints_duplicate":
        plan["target_fingerprints"] *= 2
    elif case == "operations_type":
        plan["operations"] = {}
    elif case == "operations_empty":
        plan["operations"] = []
    elif case == "operations_too_many":
        plan["operations"] *= remediation.MAX_OPERATIONS + 1
    elif case == "operation_type":
        plan["operations"] = ["replace_text"]
    elif case == "operation_fields":
        operation["extra"] = "rejected"
    elif case == "operation_type_unknown":
        operation["op"] = "write_file"
    elif case == "path_invalid":
        operation["path"] = "../outside.tf"
    elif case == "before_type":
        operation["before"] = None
    elif case == "after_type":
        operation["after"] = None
    elif case == "before_empty":
        operation["before"] = ""
    elif case == "after_empty":
        operation["after"] = ""
    elif case == "before_too_long":
        operation["before"] = "x" * (remediation.MAX_EDIT_CHARS + 1)
    elif case == "after_too_long":
        operation["after"] = "x" * (remediation.MAX_EDIT_CHARS + 1)
    elif case == "same_text":
        operation["after"] = operation["before"]
    elif case == "before_nul":
        operation["before"] = "x\x00y"
    elif case == "after_nul":
        operation["after"] = "x\x00y"
    elif case == "sensitive_before":
        operation["before"] = "password: synthetic-secret-value"
    elif case == "sensitive_after":
        operation["after"] = "password: synthetic-secret-value"

    with pytest.raises(remediation.RemediationError):
        remediation._validate_plan(plan, require_approval=require_approval)


@pytest.mark.parametrize("case", ["missing", "symlink", "oversized", "bad_json", "duplicate_key", "bad_utf8"])
def test_plan_loader_rejects_invalid_files(tmp_path, monkeypatch, case):
    plan_file = tmp_path / "plan.json"
    if case == "symlink":
        target = tmp_path / "target.json"
        target.write_text("{}")
        plan_file.symlink_to(target)
    elif case == "oversized":
        plan_file.write_text("{}")
        monkeypatch.setattr(remediation, "MAX_PLAN_BYTES", 1)
    elif case == "bad_json":
        plan_file.write_text("{")
    elif case == "duplicate_key":
        plan_file.write_text('{"status":"PENDING","status":"APPROVED"}')
    elif case == "bad_utf8":
        plan_file.write_bytes(b"\xff")

    with pytest.raises(remediation.RemediationError):
        remediation._load_plan(plan_file)


def test_preview_omits_unmodified_lines_from_patch_context(tmp_path):
    source = _source(tmp_path)
    path = source / "main.tf"
    context = '  description = "context-marker-that-must-not-appear-in-preview"\n'
    path.write_text(
        'resource "aws_s3_bucket" "data" {\n'
        + context
        + '  acl = "public-read"\n'
        + '}\n'
    )

    preview = remediation.create_remediation_preview(source_dir=source, plan=_pending_plan())

    assert "acl = \"public-read\"" in preview["patch"]
    assert "acl = \"private\"" in preview["patch"]
    assert "context-marker-that-must-not-appear-in-preview" not in preview["patch"]


def test_preview_rejects_edits_that_are_not_exactly_applicable(tmp_path):
    source = _source(tmp_path)
    plan = _pending_plan()
    plan["operations"][0]["before"] = "missing text"

    with pytest.raises(remediation.RemediationError, match="exactly once"):
        remediation.create_remediation_preview(source_dir=source, plan=plan)


def test_preview_blocks_credential_material_from_patch_artifacts(tmp_path):
    plan = _pending_plan()
    plan["operations"][0]["after"] = 'access_key = "' + "AKIA" + "ABCDEFGHIJKLMNOP" + '"'

    with pytest.raises(remediation.RemediationError, match="cannot contain credential"):
        remediation.create_remediation_preview(source_dir=_source(tmp_path), plan=plan)


def test_preview_blocks_literal_password_values_in_patch_artifacts(tmp_path):
    plan = _pending_plan()
    plan["operations"][0]["after"] = 'password = "literal-password-value-123"'

    with pytest.raises(remediation.RemediationError, match="cannot contain credential"):
        remediation.create_remediation_preview(source_dir=_source(tmp_path), plan=plan)


def test_preview_does_not_expose_secret_in_diff_context(tmp_path):
    source = _source(tmp_path)
    path = source / "main.tf"
    path.write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  acl = "public-read"\n'
        '  password = "literal-password-value-123"\n'
        '}\n'
    )

    with pytest.raises(remediation.RemediationError, match="credential or private-key material"):
        remediation.create_remediation_preview(source_dir=source, plan=_pending_plan())


def test_sandbox_requires_an_approved_preview_digest(tmp_path):
    source = _source(tmp_path)
    plan = _approved_plan(source)
    plan["operations"][0]["after"] = 'acl = "public-read-acl"'
    rescan_calls = []

    result = remediation.run_sandbox_remediation(
        source_dir=source,
        plan=plan,
        output_dir=tmp_path / "release",
        rescan=lambda *_args: rescan_calls.append(True) or _scan_result(),
    )

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "ReviewDigestMismatch"
    assert not rescan_calls
    assert not (tmp_path / "release" / "remediation.patch").exists()


def test_sandbox_blocks_when_review_is_not_verified(tmp_path):
    source = _source(tmp_path)
    plan = _approved_plan(source)
    output = tmp_path / "release"
    rescans = []

    result = remediation.run_sandbox_remediation(
        source_dir=source,
        plan=plan,
        output_dir=output,
        review_verifier=lambda *_args: False,
        rescan=lambda *_args: rescans.append(True) or _scan_result(),
    )

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "ReviewNotApproved"
    assert not rescans
    assert not (output / "remediation.patch").exists()


def test_sandbox_blocks_when_review_verification_is_unavailable(tmp_path):
    source = _source(tmp_path)
    plan = _approved_plan(source)
    output = tmp_path / "release"

    result = remediation.run_sandbox_remediation(
        source_dir=source,
        plan=plan,
        output_dir=output,
        review_verifier=lambda *_args: (_ for _ in ()).throw(
            remediation.RemediationError("review lookup unavailable", code="ReviewVerificationUnavailable")
        ),
        rescan=lambda *_args: _scan_result(),
    )

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "ReviewVerificationUnavailable"
    assert not (output / "remediation.patch").exists()


def test_sandbox_applies_only_to_temp_copy_and_requires_clean_rescan(tmp_path):
    source = _source(tmp_path)
    original = (source / "main.tf").read_bytes()
    plan = _approved_plan(source)
    calls = []

    def rescan(sandbox, fail_on):
        calls.append((sandbox, fail_on))
        assert sandbox != source
        assert (sandbox / "main.tf").read_text().find('acl = "private"') >= 0
        assert not (sandbox / ".aws" / "credentials").exists()
        return _scan_result()

    output = tmp_path / "release"
    result = remediation.run_sandbox_remediation(
        source_dir=source,
        plan=plan,
        output_dir=output,
        fail_on="HIGH",
        rescan=rescan,
        review_verifier=lambda *_args: True,
    )

    assert result["status"] == "PASS"
    assert result["rescan_status"] == "PASS"
    assert result["review"]["reference"].endswith("/pull/42")
    assert len(calls) == 1 and calls[0][1] == "HIGH"
    assert (output / "remediation.patch").exists()
    assert (output / "rescan-report.json").exists()
    assert json.loads((output / "remediation-result.json").read_text())["status"] == "PASS"
    assert stat.S_IMODE(output.stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE((output / "remediation.patch").stat().st_mode) & 0o077 == 0
    assert (source / "main.tf").read_bytes() == original


def test_sandbox_blocks_if_target_finding_remains_after_rescan(tmp_path):
    source = _source(tmp_path)
    plan = _approved_plan(source)
    output = tmp_path / "release"

    result = remediation.run_sandbox_remediation(
        source_dir=source,
        plan=plan,
        output_dir=output,
        review_verifier=lambda *_args: True,
        rescan=lambda *_args: _scan_result(
            status="PASS", gate_status="PASS", fingerprints=["a1b2c3d4e5f60718"]
        ),
    )

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "TargetFindingRemains"
    assert not (output / "remediation.patch").exists()


@pytest.mark.parametrize("status", ["UNKNOWN", "ERROR", "FAIL"])
def test_sandbox_blocks_nonpassing_or_incomplete_rescan(tmp_path, status):
    source = _source(tmp_path)
    plan = _approved_plan(source)
    output = tmp_path / "release"
    gate = "FAIL" if status == "FAIL" else "NOT_CONFIGURED"

    result = remediation.run_sandbox_remediation(
        source_dir=source,
        plan=plan,
        output_dir=output,
        review_verifier=lambda *_args: True,
        rescan=lambda *_args: _scan_result(status=status, gate_status=gate),
    )

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "RescanDidNotPass"
    assert not (output / "remediation.patch").exists()


def test_sandbox_blocks_a_report_without_contract_scan_status(tmp_path):
    source = _source(tmp_path)
    plan = _approved_plan(source)
    result = remediation.run_sandbox_remediation(
        source_dir=source,
        plan=plan,
        output_dir=tmp_path / "release",
        review_verifier=lambda *_args: True,
        rescan=lambda *_args: {
            "metadata": {"scan_source": "local-iac", "aws_accessed": False},
            "summary": {"status": "PASS", "gate_status": "PASS"},
            "findings": [],
            "contract": {"findings": []},
        },
    )

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "InvalidRescanOutput"


def test_malformed_rescan_summary_is_recorded_without_crashing(tmp_path):
    source = _source(tmp_path)
    plan = _approved_plan(source)
    output = tmp_path / "release"
    report = {
        "metadata": {"scan_source": "local-iac", "aws_accessed": False},
        "summary": [],
        "findings": [],
        "contract": {"findings": [], "scan_run": {"status": "PASS", "gate_status": "PASS"}},
    }

    result = remediation.run_sandbox_remediation(
        source_dir=source,
        plan=plan,
        output_dir=output,
        review_verifier=lambda *_args: True,
        rescan=lambda *_args: report,
    )

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == "InvalidRescanOutput"
    assert (output / "remediation-result.json").exists()


def test_sandbox_refuses_unapproved_or_unbound_reviews(tmp_path):
    source = _source(tmp_path)
    plan = _pending_plan()

    with pytest.raises(remediation.RemediationError, match="approved pull request review"):
        remediation.run_sandbox_remediation(
            source_dir=source,
            plan=plan,
            output_dir=tmp_path / "release",
            review_verifier=lambda *_args: True,
            rescan=lambda *_args: _scan_result(),
        )


def test_github_review_verification_requires_digest_and_approved_reviewer(monkeypatch):
    preview_sha256 = "b" * 64
    monkeypatch.setenv("GH_TOKEN", "github-read-only-token")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "aws-secret")
    monkeypatch.setenv("GH_HOST", "attacker.example")
    _use_example_github_origin(monkeypatch)
    captured = {}
    responses = [
        _github_pull(preview_sha256),
        _github_approval(),
        *_github_file_responses(),
        _github_pull(preview_sha256),
    ]
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout=json.dumps(responses.pop(0)), stderr="")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    review = {
        "status": "APPROVED",
        "reviewer": "security-lead",
        "reference": "https://github.com/example/auditor/pull/42",
        "preview_sha256": preview_sha256,
    }

    assert remediation._verify_github_review(
        review, _github_preview(preview_sha256), Path(".")
    ) is True
    assert commands[0][:3] == ["gh", "pr", "view"]
    assert commands[1][:2] == ["gh", "api"]
    assert "repos/example/auditor/pulls/42/reviews" in commands[1]
    assert "--paginate" in commands[1]
    assert "--slurp" in commands[1]
    assert "repos/example/auditor/pulls/42/files" in commands[2]
    assert "repos/example/auditor/contents/main.tf" in commands[3]
    assert f"ref={'c' * 40}" in commands[3]
    assert captured["env"]["GH_TOKEN"] == "github-read-only-token"
    assert captured["env"]["GH_HOST"] == "github.com"
    assert "AWS_ACCESS_KEY_ID" not in captured["env"]
    assert "GITHUB_TOKEN" not in captured["env"]
    assert captured["env"]["AWS_EC2_METADATA_DISABLED"] == "true"


@pytest.mark.parametrize(
    "case",
    [
        "not_pages",
        "page_not_list",
        "changed_files_missing",
        "changed_files_empty",
        "changed_file_not_dict",
        "changed_file_no_path",
        "changed_file_invalid_path",
        "changed_file_bad_hash",
        "changed_file_duplicate",
        "actual_not_dict",
        "filename_type",
        "status",
        "blob_sha_type",
        "blob_sha_format",
        "actual_duplicate",
        "file_set_mismatch",
    ],
)
def test_github_preview_file_verification_rejects_malformed_file_sets(case):
    preview_sha256 = "b" * 64
    preview = _github_preview(preview_sha256)
    file_item = {"filename": "main.tf", "status": "modified", "sha": "a" * 40}
    files_pages = [[file_item]]

    if case == "not_pages":
        files_pages = None
    elif case == "page_not_list":
        files_pages = [file_item]
    elif case == "changed_files_missing":
        preview.pop("changed_files")
    elif case == "changed_files_empty":
        preview["changed_files"] = []
    elif case == "changed_file_not_dict":
        preview["changed_files"] = [None]
    elif case == "changed_file_no_path":
        preview["changed_files"] = [{"after_sha256": "c" * 64}]
    elif case == "changed_file_invalid_path":
        preview["changed_files"] = [{"path": "../main.tf", "after_sha256": "c" * 64}]
    elif case == "changed_file_bad_hash":
        preview["changed_files"][0]["after_sha256"] = "not-a-sha256"
    elif case == "changed_file_duplicate":
        preview["changed_files"] *= 2
    elif case == "actual_not_dict":
        files_pages = [[None]]
    elif case == "filename_type":
        file_item["filename"] = 42
    elif case == "status":
        file_item["status"] = "added"
    elif case == "blob_sha_type":
        file_item["sha"] = None
    elif case == "blob_sha_format":
        file_item["sha"] = "not-a-git-blob-sha"
    elif case == "actual_duplicate":
        files_pages = [[file_item, file_item]]
    elif case == "file_set_mismatch":
        file_item["filename"] = "other.tf"

    assert not remediation._verify_preview_files(
        files_pages=files_pages,
        preview=preview,
        source_prefix="",
        owner="example",
        repository="auditor",
        head_sha="c" * 40,
        environment={},
    )


@pytest.mark.parametrize(
    ("case", "raises"),
    [
        ("file_missing", True),
        ("file_timeout", True),
        ("file_failed", True),
        ("file_invalid_json", True),
        ("file_sha_mismatch", False),
        ("blob_missing", True),
        ("blob_timeout", True),
        ("blob_failed", True),
        ("blob_invalid_json", True),
        ("blob_encoding", False),
        ("blob_invalid_base64", True),
        ("blob_content_mismatch", False),
    ],
)
def test_github_preview_content_verification_fails_closed(monkeypatch, case, raises):
    preview = _github_preview("b" * 64)
    file_item = {"filename": "main.tf", "status": "modified", "sha": "a" * 40}

    def fake_run(command, **_kwargs):
        is_contents = "/contents/" in command[2]
        current_case = (
            case if is_contents and case.startswith("file_") else
            case if not is_contents and case.startswith("blob_") else
            "ok"
        )
        if current_case.endswith("missing"):
            raise FileNotFoundError
        if current_case.endswith("timeout"):
            raise remediation.subprocess.TimeoutExpired(command, timeout=1)
        if current_case.endswith("failed"):
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if is_contents:
            if current_case == "file_invalid_json":
                stdout = "{"
            else:
                sha = "z" * 40 if current_case == "file_sha_mismatch" else file_item["sha"]
                stdout = json.dumps({"sha": sha})
        elif current_case == "blob_invalid_json":
            stdout = "{"
        elif current_case == "blob_encoding":
            stdout = json.dumps({"encoding": "utf8", "content": "not-base64"})
        elif current_case == "blob_invalid_base64":
            stdout = json.dumps({"encoding": "base64", "content": "!!!!"})
        else:
            contents = "different bytes\n" if current_case == "blob_content_mismatch" else 'acl = "private"\n'
            stdout = json.dumps(
                {
                    "encoding": "base64",
                    "content": base64.b64encode(contents.encode()).decode(),
                }
            )
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    args = {
        "files_pages": [[file_item]],
        "preview": preview,
        "source_prefix": "",
        "owner": "example",
        "repository": "auditor",
        "head_sha": "c" * 40,
        "environment": {},
    }
    if raises:
        with pytest.raises(remediation.RemediationError):
            remediation._verify_preview_files(**args)
    else:
        assert not remediation._verify_preview_files(**args)


def test_github_review_verification_rejects_unapproved_or_wrong_digest(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "github-read-only-token")
    _use_example_github_origin(monkeypatch)
    responses = [
        {
            "state": "OPEN",
            "reviewDecision": "APPROVED",
            "body": "Remediation Preview SHA-256: " + "c" * 64,
            "headRefOid": "c" * 40,
        },
        [[
            {
                "user": {"login": "security-lead"},
                "state": "CHANGES_REQUESTED",
                "submitted_at": "2026-11-02T10:00:00Z",
                "commit_id": "c" * 40,
            }
        ]],
    ]
    monkeypatch.setattr(
        remediation.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(responses.pop(0)), stderr=""
        ),
    )

    assert remediation._verify_github_review(
        {
            "reviewer": "security-lead",
            "reference": "https://github.com/example/auditor/pull/42",
        },
        _github_preview("b" * 64),
        Path("."),
    ) is False


def test_github_review_verification_rejects_a_pr_with_unrelated_files(monkeypatch):
    preview_sha256 = "b" * 64
    monkeypatch.setenv("GH_TOKEN", "github-read-only-token")
    _use_example_github_origin(monkeypatch)
    responses = [
        _github_pull(preview_sha256),
        _github_approval(),
        [[{"filename": "infra/unrelated.tf", "status": "modified"}]],
    ]
    monkeypatch.setattr(
        remediation.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(responses.pop(0)), stderr=""
        ),
    )

    assert not remediation._verify_github_review(
        {
            "reviewer": "security-lead",
            "reference": "https://github.com/example/auditor/pull/42",
        },
        _github_preview(preview_sha256),
        Path("."),
    )


def test_github_review_verification_requires_the_source_repository(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "github-read-only-token")
    _use_example_github_origin(monkeypatch)
    monkeypatch.setattr(
        remediation.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("must reject before querying a different repository"),
    )

    assert not remediation._verify_github_review(
        {
            "reviewer": "security-lead",
            "reference": "https://github.com/other/repository/pull/42",
        },
        _github_preview("b" * 64),
        Path("."),
    )


def test_github_source_context_resolves_repository_and_subdirectory(monkeypatch, tmp_path):
    repository_root = tmp_path / "repo"
    source = repository_root / "infra"
    source.mkdir(parents=True)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "aws-secret")
    responses = [
        SimpleNamespace(returncode=0, stdout=f"{repository_root}\n", stderr=""),
        SimpleNamespace(returncode=0, stdout="git@github.com:example/auditor.git\n", stderr=""),
    ]
    environments = []

    def fake_run(_command, **kwargs):
        environments.append(kwargs["env"])
        return responses.pop(0)

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)

    assert remediation._github_source_context(source) == ("example", "auditor", "infra")
    assert all("AWS_ACCESS_KEY_ID" not in environment for environment in environments)


def test_github_review_verification_rejects_preview_content_mismatch(monkeypatch):
    preview_sha256 = "b" * 64
    monkeypatch.setenv("GH_TOKEN", "github-read-only-token")
    _use_example_github_origin(monkeypatch)
    responses = [
        _github_pull(preview_sha256),
        _github_approval(),
        *_github_file_responses(contents='acl = "public-read"\n'),
    ]
    monkeypatch.setattr(
        remediation.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(responses.pop(0)), stderr=""
        ),
    )

    assert not remediation._verify_github_review(
        {
            "reviewer": "security-lead",
            "reference": "https://github.com/example/auditor/pull/42",
        },
        _github_preview(preview_sha256),
        Path("."),
    )


def test_github_review_verification_uses_the_reviewers_latest_decision(monkeypatch):
    preview_sha256 = "d" * 64
    monkeypatch.setenv("GH_TOKEN", "github-read-only-token")
    _use_example_github_origin(monkeypatch)
    responses = [
        {
            "state": "OPEN",
            "reviewDecision": "APPROVED",
            "body": f"Remediation Preview SHA-256: {preview_sha256}",
            "headRefOid": "c" * 40,
        },
        [[
            {
                "user": {"login": "security-lead"},
                "state": "APPROVED",
                "submitted_at": "2026-11-02T09:00:00Z",
                "commit_id": "c" * 40,
            },
            {
                "user": {"login": "security-lead"},
                "state": "CHANGES_REQUESTED",
                "submitted_at": "2026-11-02T10:00:00Z",
                "commit_id": "c" * 40,
            },
        ]],
    ]
    monkeypatch.setattr(
        remediation.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(responses.pop(0)), stderr=""
        ),
    )

    assert not remediation._verify_github_review(
        {
            "reviewer": "security-lead",
            "reference": "https://github.com/example/auditor/pull/42",
        },
        _github_preview(preview_sha256),
        Path("."),
    )


def test_github_review_verification_fails_closed_for_ambiguous_latest_reviews(monkeypatch):
    preview_sha256 = "f" * 64
    monkeypatch.setenv("GH_TOKEN", "github-read-only-token")
    _use_example_github_origin(monkeypatch)
    responses = [
        {
            "state": "OPEN",
            "reviewDecision": "APPROVED",
            "body": f"Remediation Preview SHA-256: {preview_sha256}",
            "headRefOid": "c" * 40,
        },
        [[
            {
                "user": {"login": "security-lead"},
                "state": "APPROVED",
                "submitted_at": "2026-11-02T10:00:00Z",
                "commit_id": "c" * 40,
            },
            {
                "user": {"login": "security-lead"},
                "state": "CHANGES_REQUESTED",
                "submitted_at": "2026-11-02T10:00:00Z",
                "commit_id": "c" * 40,
            },
        ]],
    ]
    monkeypatch.setattr(
        remediation.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(responses.pop(0)), stderr=""
        ),
    )

    assert not remediation._verify_github_review(
        {
            "reviewer": "security-lead",
            "reference": "https://github.com/example/auditor/pull/42",
        },
        _github_preview(preview_sha256),
        Path("."),
    )


def test_github_review_verification_rejects_approval_for_stale_head(monkeypatch):
    preview_sha256 = "e" * 64
    monkeypatch.setenv("GH_TOKEN", "github-read-only-token")
    _use_example_github_origin(monkeypatch)
    responses = [
        {
            "state": "OPEN",
            "reviewDecision": "APPROVED",
            "body": f"Remediation Preview SHA-256: {preview_sha256}",
            "headRefOid": "d" * 40,
        },
        [[
            {
                "user": {"login": "security-lead"},
                "state": "APPROVED",
                "submitted_at": "2026-11-02T10:00:00Z",
                "commit_id": "e" * 40,
            }
        ]],
    ]
    monkeypatch.setattr(
        remediation.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(responses.pop(0)), stderr=""
        ),
    )

    assert not remediation._verify_github_review(
        {
            "reviewer": "security-lead",
            "reference": "https://github.com/example/auditor/pull/42",
        },
        _github_preview(preview_sha256),
        Path("."),
    )


def test_local_patch_proposal_returns_rescan_attestation_without_modifying_source(tmp_path):
    source = _source(tmp_path)
    original = (source / "main.tf").read_text()
    result = remediation.rescan_local_patch_proposal(
        source_dir=source,
        target_fingerprint="a1b2c3d4e5f60718",
        operations=_pending_plan()["operations"],
        rescan=lambda _sandbox, threshold: _scan_result(),
    )

    assert result["status"] == "RESCANNED"
    assert result["rescan_status"] == "PASS"
    assert result["rescan_gate_status"] == "PASS"
    assert result["patch"]
    assert result["patch_sha256"] == hashlib.sha256(result["patch"].encode()).hexdigest()
    assert (source / "main.tf").read_text() == original


@pytest.mark.parametrize(
    ("case", "reason_code"),
    [
        ("rescan_raises", "RescanFailed"),
        ("rescan_not_dict", "InvalidRescanOutput"),
        ("invalid_report", "InvalidRescanOutput"),
        ("unsafe_source", "UnsafeRescanSource"),
        ("target_remains", "TargetFindingRemains"),
        ("gate_fails", "RescanDidNotPass"),
        ("source_changes", "SourceChangedDuringRescan"),
    ],
)
def test_local_patch_proposal_blocks_nonpassing_rescans(tmp_path, case, reason_code):
    source = _source(tmp_path)

    def rescan(_sandbox, _threshold):
        if case == "rescan_raises":
            raise RuntimeError("scanner failure")
        if case == "rescan_not_dict":
            return None
        if case == "invalid_report":
            return {"metadata": {}, "summary": [], "findings": [], "contract": {}}
        report = _scan_result(
            status="FAIL" if case == "gate_fails" else "PASS",
            gate_status="FAIL" if case == "gate_fails" else "PASS",
            fingerprints=["a1b2c3d4e5f60718"] if case == "target_remains" else [],
        )
        if case == "unsafe_source":
            report["metadata"]["aws_accessed"] = True
        if case == "source_changes":
            (source / "main.tf").write_text("source changed during scan")
        return report

    result = remediation.rescan_local_patch_proposal(
        source_dir=source,
        target_fingerprint="a1b2c3d4e5f60718",
        operations=_pending_plan()["operations"],
        rescan=rescan,
    )

    assert result["status"] == "BLOCKED"
    assert result["reason_code"] == reason_code


def test_sandbox_refuses_a_shared_output_directory(tmp_path):
    source = _source(tmp_path)
    plan = _approved_plan(source)
    output = tmp_path / "release"
    output.mkdir(mode=0o755)
    output.chmod(0o755)

    with pytest.raises(remediation.RemediationError, match="must deny group and other access"):
        remediation.run_sandbox_remediation(
            source_dir=source,
            plan=plan,
            output_dir=output,
            rescan=lambda *_args: _scan_result(),
        )


def test_cli_sandbox_path_never_creates_an_aws_session(monkeypatch, capsys, tmp_path):
    from auditor import cli

    def forbidden_aws_session(**_kwargs):
        raise AssertionError("remediation sandbox must never create AWS sessions")

    monkeypatch.setattr(cli, "build_session", forbidden_aws_session)
    monkeypatch.setattr(
        remediation,
        "run_sandbox_remediation",
        lambda **_kwargs: {"status": "PASS", "rescan_status": "PASS"},
    )

    code = cli.main(
        [
            "remediation-sandbox",
            "--source",
            str(tmp_path),
            "--plan",
            "plan.json",
            "--output-dir",
            str(tmp_path / "output"),
            "--confirm-sandbox",
        ]
    )

    assert code == cli.EXIT_OK
    assert '"status": "PASS"' in capsys.readouterr().out


def test_cli_reports_blocked_sandbox_as_a_gate_failure(monkeypatch, capsys, tmp_path):
    from auditor import cli

    monkeypatch.setattr(
        remediation,
        "run_sandbox_remediation",
        lambda **_kwargs: {"status": "BLOCKED", "reason_code": "ReviewNotApproved"},
    )

    code = cli.main(
        [
            "remediation-sandbox",
            "--source",
            str(tmp_path),
            "--plan",
            "plan.json",
            "--output-dir",
            str(tmp_path / "output"),
            "--confirm-sandbox",
        ]
    )

    assert code == cli.EXIT_FINDINGS
    assert '"status": "BLOCKED"' in capsys.readouterr().out


def test_remediation_pr_workflow_is_manual_and_has_no_aws_permissions():
    workflow = (Path(__file__).parents[1] / ".github/workflows/remediation-pr.yml").read_text()

    assert "workflow_dispatch:" in workflow
    assert "contents: write" in workflow
    assert "pull-requests: write" in workflow
    assert "github.event.repository.default_branch" in workflow
    assert "aws-actions/configure-aws-credentials" not in workflow
    assert "aws-access-key-id" not in workflow
