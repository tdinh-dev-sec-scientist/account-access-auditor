"""Versioned finding and scan-run contracts shared by scanner adapters."""

from __future__ import annotations

import json
import pathlib

import pytest

import auditor.models.contracts as contract_models
from auditor.models.contracts import (
    CONTRACT_VERSION,
    EXIT_CODE_BY_STATUS,
    GateStatus,
    ScanRun,
    ScanStatus,
    classify_scan,
    finding_record,
    scanner_finding_record,
)
from auditor.models.finding import Finding
from auditor.models.report import build_report

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_finding_contract_preserves_control_and_scanner_rule_identity():
    finding = Finding.build("IAM-001", "user:operator", "MFA is missing")

    record = finding_record(finding)

    assert record["schema_version"] == CONTRACT_VERSION == "1.0.0"
    assert record["control_id"] == "IAM-001"
    assert record["scanner"] == "account-access-auditor"
    assert record["scanner_rule_id"] == "IAM-001"
    assert record["source_type"] == "aws"
    assert record["resource_reference"] == "user:operator"
    assert record["source_location"] is None
    assert record["lifecycle_state"] == "open"
    assert record["severity"] == "HIGH"
    assert record["remediation"]
    assert isinstance(record["references"], list)
    assert len(record["fingerprint"]) == 16

    mapped = finding_record(Finding.build("IAM-004", "user:operator/policy", "Wildcard policy"))
    assert mapped["references"][0]["type"] == "compliance"
    assert mapped["references"][0]["title"]


def test_fingerprint_uses_control_source_and_stable_resource_identity():
    first = Finding.build("IAM-001", "user:operator", "First description")
    changed_copy = Finding.build("IAM-001", "user:operator", "Updated description", title="Updated title")

    assert finding_record(first)["fingerprint"] == finding_record(changed_copy)["fingerprint"]
    assert (
        finding_record(first, source_type="terraform")["fingerprint"] != finding_record(first)["fingerprint"]
    )
    assert (
        finding_record(first, resource_reference="user:other")["fingerprint"]
        != finding_record(first)["fingerprint"]
    )


def test_finding_contract_rejects_malformed_external_source_locations():
    finding = Finding.build("IAM-001", "user:operator", "MFA is missing")

    with pytest.raises(ValueError, match="source_location"):
        finding_record(
            finding,
            resource_reference="",
            source_location={"file": "main.tf", "line": 0},
        )


@pytest.mark.parametrize(
    "source_location",
    [
        {"file": "main.tf", "line": True},
        {"file": "main.tf", "line": 0},
        {"file": "", "line": 1},
        {"file": "main.tf", "extra": "unexpected"},
    ],
)
def test_scanner_contract_rejects_malformed_external_source_locations(source_location):
    with pytest.raises(ValueError, match="source_location"):
        scanner_finding_record(
            control_id="IAC-TEST-001",
            scanner="conftest",
            scanner_rule_id="data.main.deny",
            source_type="kubernetes",
            severity="HIGH",
            title="Invalid fixture",
            description="",
            evidence={},
            source_location=source_location,
        )


def test_finding_contract_rejects_missing_resource_and_location():
    finding = Finding.build("IAM-001", "unstable-id", "MFA is missing")

    with pytest.raises(ValueError, match="stable resource_reference or source_location"):
        finding_record(finding, resource_reference_is_stable=False)


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"control_id": " "}, "control_id"),
        ({"resource_reference": ["invalid"]}, "resource_reference"),
    ],
)
def test_finding_contract_rejects_invalid_identity_fields(kwargs, message):
    finding = Finding.build("IAM-001", "user:operator", "MFA is missing")

    with pytest.raises(ValueError, match=message):
        finding_record(finding, **kwargs)


def test_fingerprint_uses_file_and_line_when_resource_reference_is_unstable():
    finding = Finding.build("IAM-001", "generated-resource-id", "MFA is missing")

    first = finding_record(
        finding,
        source_type="terraform",
        resource_reference_is_stable=False,
        source_location={"file": "main.tf", "line": 12},
    )
    same_line = finding_record(
        finding,
        source_type="terraform",
        resource_reference_is_stable=False,
        source_location={"file": "main.tf", "line": 12},
    )
    moved = finding_record(
        finding,
        source_type="terraform",
        resource_reference_is_stable=False,
        source_location={"file": "main.tf", "line": 13},
    )

    assert first["resource_reference"] is None
    assert first["fingerprint"] == same_line["fingerprint"]
    assert first["fingerprint"] != moved["fingerprint"]


@pytest.mark.parametrize(
    "errors,gate_status,expected_status,expected_exit",
    [
        ([], GateStatus.NOT_CONFIGURED, ScanStatus.PASS, 0),
        ([], GateStatus.FAIL, ScanStatus.FAIL, 1),
        (
            [{"operation": "s3:GetBucketAcl", "category": "access_denied"}],
            GateStatus.PASS,
            ScanStatus.UNKNOWN,
            3,
        ),
        ([{"operation": "collect", "category": "error"}], GateStatus.PASS, ScanStatus.ERROR, 2),
    ],
)
def test_scan_status_and_exit_code_distinguish_complete_partial_and_failed_runs(
    errors, gate_status, expected_status, expected_exit
):
    outcome = classify_scan(errors, gate_status)

    assert outcome.status is expected_status
    assert outcome.exit_code == expected_exit


def test_partial_collection_remains_unknown_even_when_gate_would_fail():
    outcome = classify_scan([{"operation": "iam:ListUsers", "category": "access_denied"}], GateStatus.FAIL)

    assert outcome.status is ScanStatus.UNKNOWN
    assert outcome.gate_status is GateStatus.FAIL
    assert outcome.exit_code == 3


def test_report_embeds_contract_and_keeps_legacy_report_fields():
    finding = Finding.build("IAM-001", "user:operator", "MFA is missing")

    report = build_report(
        account_id="123456789012",
        region="us-east-1",
        findings=[finding],
        run_id="run-1",
        tool_version="1.2.3",
        services_scanned=["IAM"],
        scan_source="cli",
        gate_status=GateStatus.NOT_CONFIGURED,
    )

    assert {"metadata", "summary", "collection_errors", "findings"} <= set(report)
    assert report["findings"][0]["rule_id"] == "IAM-001"
    contract = report["contract"]
    assert contract["schema_version"] == CONTRACT_VERSION
    assert contract["findings"][0]["control_id"] == report["findings"][0]["rule_id"]
    assert contract["scan_run"]["run_id"] == "run-1"
    assert contract["scan_run"]["scan_source"] == "cli"
    assert contract["scan_run"]["account_refs"] == [{"provider": "aws", "id": "123456789012"}]
    assert contract["scan_run"]["regions"] == ["us-east-1"]
    assert contract["scan_run"]["status"] == "PASS"


def test_contract_schemas_describe_the_emitted_records():
    finding_schema = json.loads((ROOT / "schemas/finding-v1.schema.json").read_text())
    scan_run_schema = json.loads((ROOT / "schemas/scan-run-v1.schema.json").read_text())
    artifact_schema = json.loads((ROOT / "schemas/artifact-result-v1.schema.json").read_text())
    finding = finding_record(Finding.build("IAM-001", "user:operator", "MFA is missing"))

    assert finding_schema["properties"]["schema_version"]["const"] == CONTRACT_VERSION
    assert set(finding_schema["required"]) <= finding.keys()
    assert "gate" in finding_schema["properties"]
    assert "exceptions" in finding_schema["properties"]
    assert scan_run_schema["properties"]["status"]["enum"] == [
        "PASS",
        "FAIL",
        "UNKNOWN",
        "ERROR",
    ]
    assert scan_run_schema["properties"]["gate_threshold"]["enum"] == [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]
    artifact = contract_models.ArtifactResult(
        schema_version=CONTRACT_VERSION,
        artifact_type="SBOM",
        location="source.sbom.cdx.json",
        format="CycloneDX JSON",
        sha256="a" * 64,
        scanner="syft",
        scanner_version="1.55.0",
    ).to_dict()
    assert artifact_schema["properties"]["schema_version"]["const"] == CONTRACT_VERSION
    assert set(artifact_schema["required"]) <= artifact.keys()


def test_artifact_result_preserves_database_signature_and_provenance_status():
    record = contract_models.ArtifactResult(
        schema_version=CONTRACT_VERSION,
        artifact_type="VULNERABILITY_REPORT",
        location="image.vulnerabilities.json",
        format="Grype JSON",
        sha256="b" * 64,
        scanner="grype",
        scanner_version="0.121.0",
        database_provenance={
            "schema_version": "6.0.0",
            "built_at": "2026-11-02T11:00:00+00:00",
            "checksum": "sha256:db",
        },
        signature_identity="sha256:public-key",
        signature_verified=True,
        provenance_verified=None,
    ).to_dict()

    assert record["database_provenance"] == {
        "schema_version": "6.0.0",
        "built_at": "2026-11-02T11:00:00+00:00",
        "checksum": "sha256:db",
    }
    assert record["signature_identity"] == "sha256:public-key"
    assert record["signature_verified"] is True
    assert record["provenance_verified"] is None


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"schema_version": "2.0.0"}, "unsupported contract version"),
        ({"location": "../outside.json"}, "location must be a safe relative path"),
        ({"sha256": "not-a-digest"}, "sha256 must be 64 lowercase hexadecimal characters"),
        ({"scanner_version": ""}, "must be non-empty"),
        ({"signature_verified": True}, "verified signature requires a signature identity"),
        ({"signature_verified": 1}, "signature_verified must be a boolean or None"),
        ({"database_provenance": {"schema_version": "6.0.0"}}, "database_provenance fields"),
    ],
)
def test_artifact_result_rejects_invalid_contract_values(overrides, message):
    fields = {
        "schema_version": CONTRACT_VERSION,
        "artifact_type": "SBOM",
        "location": "source.sbom.cdx.json",
        "format": "CycloneDX JSON",
        "sha256": "a" * 64,
        "scanner": "syft",
        "scanner_version": "1.55.0",
    }
    fields.update(overrides)

    with pytest.raises(ValueError, match=message):
        contract_models.ArtifactResult(**fields)


def test_artifact_result_contract_record_type_exists():
    assert hasattr(contract_models, "ArtifactResult")


def _valid_scan_run(**overrides):
    fields = {
        "schema_version": CONTRACT_VERSION,
        "run_id": "run-1",
        "scan_source": "cli",
        "commit_ref": None,
        "workflow_ref": None,
        "account_refs": [],
        "regions": [],
        "scanner_versions": {"account-access-auditor": "1.0.0"},
        "policy_pack_version": None,
        "started_at": "2026-01-01T00:00:00+00:00",
        "completed_at": "2026-01-01T00:00:01+00:00",
        "status": ScanStatus.PASS,
        "gate_status": GateStatus.NOT_CONFIGURED,
        "exit_code": EXIT_CODE_BY_STATUS[ScanStatus.PASS],
        "finding_count": 0,
        "collection_error_count": 0,
    }
    fields.update(overrides)
    return ScanRun(**fields)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"schema_version": "2.0.0"}, "unsupported contract version"),
        ({"run_id": ""}, "run_id and scan_source"),
        ({"scan_source": ""}, "run_id and scan_source"),
        ({"exit_code": 3}, "exit_code does not match"),
        ({"completed_at": "2025-12-31T23:59:59+00:00"}, "must not precede"),
        ({"finding_count": -1}, "must not be negative"),
        ({"started_at": "not-a-timestamp"}, "ISO 8601 timestamp"),
        ({"started_at": "2026-01-01T00:00:00"}, "must include a timezone"),
    ],
)
def test_scan_run_rejects_invalid_contract_values(overrides, message):
    with pytest.raises(ValueError, match=message):
        _valid_scan_run(**overrides)
