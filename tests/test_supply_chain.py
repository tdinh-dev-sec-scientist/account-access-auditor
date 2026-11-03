from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from auditor import supply_chain
from auditor.models.contracts import CONTRACT_VERSION


def _cyclonedx() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "metadata": {"timestamp": "2026-11-01T12:00:00Z"},
        "components": [{"type": "library", "name": "example", "version": "1.0"}],
    }


def _db_status(*, built: str = "2026-11-02T11:00:00Z") -> dict:
    return {
        "status": "valid",
        "schemaVersion": "6.0.0",
        "built": built,
        "checksum": "sha256:db-checksum",
    }


def _grype_report(severities: list[str], *, built: str | None = None) -> dict:
    database_built = built or (datetime.now(UTC) - timedelta(hours=1)).isoformat(timespec="seconds")
    return {
        "descriptor": {
            "name": "grype",
            "version": supply_chain.PINNED_TOOL_VERSIONS["grype"],
            "db": {
                "built": database_built,
                "schemaVersion": "6.0.0",
                "checksum": "sha256:db-checksum",
            },
        },
        "matches": [
            {
                "artifact": {
                    "name": "example",
                    "version": "1.0.0",
                    "type": "python",
                    "purl": "pkg:pypi/example@1.0.0",
                },
                "vulnerability": {"id": f"CVE-2026-{i}", "severity": severity},
            }
            for i, severity in enumerate(severities, start=1)
        ],
    }


def test_canonical_sbom_digest_ignores_generated_serial_and_timestamp():
    first = _cyclonedx()
    second = _cyclonedx()
    second["serialNumber"] = "urn:uuid:22222222-2222-4222-8222-222222222222"
    second["metadata"]["timestamp"] = "2026-11-02T12:00:00Z"

    assert supply_chain.canonical_sbom_digest(first) == supply_chain.canonical_sbom_digest(second)


@pytest.mark.parametrize(
    ("severities", "threshold", "expected"),
    [
        (["Low", "Medium"], "HIGH", "PASS"),
        (["Critical"], "HIGH", "FAIL"),
        (["High"], "HIGH", "FAIL"),
        (["Negligible"], "LOW", "PASS"),
    ],
)
def test_grype_results_apply_explicit_severity_gate(severities, threshold, expected):
    result = supply_chain.assess_grype_report(_grype_report(severities), fail_on=threshold)

    assert result["gate_status"] == expected
    assert result["finding_count"] == len(severities)
    assert len(result["findings"]) == len(severities)
    assert [finding["source_severity"] for finding in result["findings"]] == severities
    assert [finding["severity"] for finding in result["findings"]] == [
        "INFO" if severity.upper() == "NEGLIGIBLE" else severity.upper()
        for severity in severities
    ]


def test_grype_match_normalizes_into_shared_finding_contract():
    report = _grype_report(["Negligible"])
    report["matches"][0]["artifact"]["purl"] = (
        "pkg:pypi/example@1.0.0?repository_url=https%3A%2F%2Fuser%3Atest-secret%40registry"
    )
    result = supply_chain.assess_grype_report(report, fail_on="HIGH")

    finding = result["findings"][0]
    assert finding["schema_version"] == CONTRACT_VERSION
    assert finding["control_id"] == "VULN-CVE-2026-1"
    assert finding["scanner"] == "grype"
    assert finding["scanner_rule_id"] == "CVE-2026-1"
    assert finding["source_type"] == "supply-chain-dependency"
    assert finding["severity"] == "INFO"
    assert finding["source_severity"] == "Negligible"
    assert finding["resource_reference"].startswith("dependency:sha256:")
    assert "test-secret" not in json.dumps(finding)
    assert finding["evidence"]["package"] == {
        "name": "example",
        "version": "1.0.0",
        "type": "python",
    }


def test_grype_match_without_stable_package_identity_is_rejected():
    report = _grype_report(["High"])
    report["matches"][0]["artifact"]["version"] = ""

    with pytest.raises(supply_chain.SupplyChainError, match="stable package identity") as exc_info:
        supply_chain.assess_grype_report(report, fail_on="HIGH")

    assert exc_info.value.code == "InvalidGrypeReport"


def test_grype_report_unknown_severity_is_not_treated_as_clean():
    with pytest.raises(supply_chain.SupplyChainError, match="unrecognized severity"):
        supply_chain.assess_grype_report(_grype_report(["unrated"]), fail_on="HIGH")


def test_grype_report_missing_matches_is_rejected():
    with pytest.raises(supply_chain.SupplyChainError, match="matches array"):
        supply_chain.assess_grype_report({"descriptor": {"name": "grype"}}, fail_on="HIGH")


def test_database_metadata_records_build_and_rejects_stale_data():
    current = supply_chain.normalize_database_status(
        _db_status(), now=supply_chain.parse_utc("2026-11-02T12:00:00Z")
    )
    assert current["schema_version"] == "6.0.0"
    assert current["built_at"] == "2026-11-02T11:00:00+00:00"
    assert current["age_hours"] == 1

    with pytest.raises(supply_chain.SupplyChainError, match="stale"):
        supply_chain.normalize_database_status(
            _db_status(built="2026-10-27T11:59:00Z"),
            now=supply_chain.parse_utc("2026-11-02T12:00:00Z"),
        )


def test_database_status_accepts_grype_0121_valid_field_shape():
    status = supply_chain.normalize_database_status(
        {
            "schemaVersion": "v6.1.10",
            "built": "2026-11-02T06:26:52Z",
            "path": "/tmp/vulnerability.db",
            "valid": True,
        },
        now=supply_chain.parse_utc("2026-11-02T12:00:00Z"),
    )

    assert status == {
        "status": "valid",
        "schema_version": "v6.1.10",
        "built_at": "2026-11-02T06:26:52+00:00",
        "age_hours": 5,
        "checksum": None,
    }


def test_database_status_rejects_false_grype_valid_flag():
    with pytest.raises(supply_chain.SupplyChainError) as exc_info:
        supply_chain.normalize_database_status(
            {
                "schemaVersion": "v6.1.10",
                "built": "2026-11-02T06:26:52Z",
                "valid": False,
            }
        )

    assert exc_info.value.code == "VulnerabilityDatabaseUnavailable"


def test_database_status_missing_build_time_is_not_accepted():
    status = _db_status()
    del status["built"]
    with pytest.raises(supply_chain.SupplyChainError, match="build timestamp"):
        supply_chain.normalize_database_status(status)


@pytest.mark.parametrize("built", ["not-a-timestamp", "2026-11-02T11:00:00"])
def test_database_status_invalid_or_timezone_free_timestamp_is_unknown(built):
    with pytest.raises(supply_chain.SupplyChainError) as exc_info:
        supply_chain.normalize_database_status(_db_status(built=built))

    assert exc_info.value.code == "VulnerabilityDatabaseUnavailable"


def test_grype_report_must_identify_the_scanner_database():
    report = _grype_report([])
    del report["descriptor"]["db"]

    with pytest.raises(supply_chain.SupplyChainError) as exc_info:
        supply_chain._grype_database_provenance(report)

    assert exc_info.value.code == "VulnerabilityDatabaseUnavailable"


def test_grype_report_accepts_nested_grype_0121_database_provenance():
    report = _grype_report([])
    report["descriptor"]["db"] = {
        "status": {
            "schemaVersion": "v6.1.10",
            "built": "2026-11-02T06:26:52Z",
            "path": "/tmp/vulnerability.db",
            "valid": True,
        },
        "providers": {},
    }

    assert supply_chain._grype_database_provenance(report) == {
        "schema_version": "v6.1.10",
        "built_at": "2026-11-02T06:26:52+00:00",
        "checksum": None,
    }


def test_grype_report_rejects_invalid_nested_database_status():
    report = _grype_report([])
    report["descriptor"]["db"] = {
        "status": {
            "schemaVersion": "v6.1.10",
            "built": "2026-11-02T06:26:52Z",
            "valid": False,
        },
        "providers": {},
    }

    with pytest.raises(supply_chain.SupplyChainError) as exc_info:
        supply_chain._grype_database_provenance(report)

    assert exc_info.value.code == "VulnerabilityDatabaseUnavailable"


@pytest.mark.parametrize(
    "database_used",
    [
        {"schema_version": "5.0.0", "built_at": "2026-11-02T11:00:00+00:00", "checksum": "sha256:db-checksum"},
        {"schema_version": "6.0.0", "built_at": "2026-11-02T10:00:00+00:00", "checksum": "sha256:db-checksum"},
        {"schema_version": "6.0.0", "built_at": "2026-11-02T11:00:00+00:00", "checksum": "sha256:other"},
    ],
)
def test_scan_cannot_pass_when_report_uses_a_different_database(database_used):
    with pytest.raises(supply_chain.SupplyChainError) as exc_info:
        supply_chain._validate_scan_database_provenance(
            {"source": {"database_used": database_used}},
            {
                "schema_version": "6.0.0",
                "built_at": "2026-11-02T11:00:00+00:00",
                "checksum": "sha256:db-checksum",
            },
        )

    assert exc_info.value.code == "VulnerabilityDatabaseUnavailable"


def test_source_digest_excludes_local_aws_credentials_and_agent_context(tmp_path):
    (tmp_path / "package.py").write_text("print('release')\n")
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    credentials = aws_dir / "credentials"
    credentials.write_text("secret-one")
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    private_key = ssh / "id_ed25519"
    private_key.write_text("ssh-secret-one")
    npm_config = tmp_path / ".npmrc"
    npm_config.write_text("//registry.example/:_authToken=token-one")
    (tmp_path / "AGENTS.md").write_text("private instructions")
    results = tmp_path / "results"
    results.mkdir()
    coverage = results / "coverage.json"
    coverage.write_text('{"run":1}')
    before = supply_chain._tree_digest(tmp_path)

    credentials.write_text("secret-two")
    private_key.write_text("ssh-secret-two")
    npm_config.write_text("//registry.example/:_authToken=token-two")
    (tmp_path / "AGENTS.md").write_text("different private instructions")
    coverage.write_text('{"run":2}')
    after_secret_change = supply_chain._tree_digest(tmp_path)
    (tmp_path / "package.py").write_text("print('changed release')\n")

    assert before == after_secret_change
    assert after_secret_change != supply_chain._tree_digest(tmp_path)


@pytest.mark.parametrize(
    ("severities", "expected_status", "expected_signed"),
    [([], "PASS", 5), (["Critical"], "FAIL", 0)],
)
def test_run_release_applies_gate_and_signs_only_a_passing_release(
    monkeypatch, tmp_path, severities, expected_status, expected_signed
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "requirements.txt").write_text("example==1.0\n")
    image_archive = tmp_path / "image.tar"
    image_archive.write_bytes(b"container-image-data")
    private_key = tmp_path / "cosign.key"
    public_key = tmp_path / "cosign.pub"
    private_key.write_text("private-key-placeholder")
    private_key.chmod(0o600)
    public_key.write_text("public-key-placeholder")
    output = tmp_path / "release"
    calls = []
    environments = []
    database_built = (datetime.now(UTC) - timedelta(hours=1)).isoformat(timespec="seconds")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "aws-test-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "github-test-secret")
    monkeypatch.setenv("COSIGN_PASSWORD", "cosign-test-password")
    monkeypatch.setenv("GRYPE_FAIL_ON_SEVERITY", "critical")
    monkeypatch.setenv("SYFT_EXCLUDE", "**/*")
    monkeypatch.setenv("COSIGN_EXPERIMENTAL", "1")

    def fake_run(command, **kwargs):
        command = [str(part) for part in command]
        calls.append(command)
        environments.append((command, kwargs.get("env")))
        if command[0] in {"syft", "grype", "cosign"} and command[1] == "version":
            versions = {
                "syft": supply_chain.PINNED_TOOL_VERSIONS["syft"],
                "grype": supply_chain.PINNED_TOOL_VERSIONS["grype"],
                "cosign": supply_chain.PINNED_TOOL_VERSIONS["cosign"],
            }
            return SimpleNamespace(returncode=0, stdout=f"Version: {versions[command[0]]}\n", stderr="")
        if command[0] == "syft":
            config_path = Path(command[command.index("--config") + 1])
            assert config_path.suffix == ".yaml"
            assert json.loads(config_path.read_text(encoding="utf-8")) == {
                "check-for-app-update": False,
                "cache": {"dir": "", "ttl": 0},
            }
            if command[1].startswith("dir:"):
                exclude_patterns = [
                    command[index + 1]
                    for index, argument in enumerate(command[:-1])
                    if argument == "--exclude"
                ]
                assert exclude_patterns
                assert all(pattern.startswith(("./", "*/", "**/")) for pattern in exclude_patterns)
            destination = Path(command[-1].split("=", 1)[1])
            destination.write_text(json.dumps(_cyclonedx()))
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[:3] == ["grype", "db", "status"]:
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(_db_status(built=database_built)),
                stderr="",
            )
        if command[0] == "grype":
            config_path = Path(command[command.index("--config") + 1])
            assert config_path.suffix == ".yaml"
            assert json.loads(config_path.read_text(encoding="utf-8")) == {"check-for-app-update": False}
            destination = Path(command[command.index("--file") + 1])
            destination.write_text(json.dumps(_grype_report(severities, built=database_built)))
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[:2] == ["cosign", "sign-blob"]:
            signature = Path(command[command.index("--output-signature") + 1])
            signature.write_text("base64-signature")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[:2] == ["cosign", "verify-blob"]:
            return SimpleNamespace(returncode=0, stdout="Verified OK\n", stderr="")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(supply_chain.subprocess, "run", fake_run)
    result = supply_chain.run_release(
        source_dir=source,
        image_archive=image_archive,
        image_format="docker-archive",
        output_dir=output,
        signing_key=private_key,
        public_key=public_key,
        fail_on="HIGH",
    )

    assert result["status"] == expected_status
    contract = result["contract"]
    scan_run = contract["scan_run"]
    assert contract["schema_version"] == CONTRACT_VERSION
    assert scan_run["schema_version"] == CONTRACT_VERSION
    assert scan_run["status"] == expected_status
    assert scan_run["gate_status"] == ("FAIL" if severities else "PASS")
    assert scan_run["finding_count"] == 2 * len(severities)
    assert len(contract["findings"]) == scan_run["finding_count"]
    assert {
        finding["source_type"] for finding in contract["findings"]
    } == ({"supply-chain-source", "supply-chain-image"} if severities else set())
    assert all(finding["run_id"] == scan_run["run_id"] for finding in contract["findings"])
    assert scan_run["scanner_versions"]["syft"] == supply_chain.PINNED_TOOL_VERSIONS["syft"]
    artifact_results = contract["artifact_results"]
    expected_artifact_types = {
        "SBOM",
        "VULNERABILITY_REPORT",
    }
    if expected_status == "PASS":
        expected_artifact_types.add("CONTAINER_ARCHIVE")
    assert {item["artifact_type"] for item in artifact_results} == expected_artifact_types
    assert all(item["schema_version"] == CONTRACT_VERSION for item in artifact_results)
    assert all(item["provenance_verified"] is None for item in artifact_results)
    if expected_status == "PASS":
        assert all(item["signature_verified"] is True for item in artifact_results)
        assert all(item["signature_identity"].startswith("sha256:") for item in artifact_results)
    else:
        assert all(item["signature_verified"] is False for item in artifact_results)
        assert all(item["signature_identity"] is None for item in artifact_results)
    assert result["vulnerability_database"]["schema_version"] == "6.0.0"
    assert all(
        scan["database_used"]["checksum"] == "sha256:db-checksum"
        for scan in result["scans"].values()
    )
    expected_gate = "FAIL" if severities else "PASS"
    assert result["scans"]["source"]["gate_status"] == expected_gate
    assert result["scans"]["image"]["gate_status"] == expected_gate
    signed = result["signed_artifacts"]
    assert len(signed) == expected_signed
    assert all(item["verified"] is True for item in signed)
    assert (output / "release-manifest.json").exists()
    saved_manifest = json.loads((output / "release-manifest.json").read_text())
    assert saved_manifest["contract"] == contract
    assert not (output / private_key.name).exists()
    if expected_status == "PASS":
        assert (output / "release-image.tar").read_bytes() == image_archive.read_bytes()
        assert (output / "release.pub").exists()
    else:
        assert not (output / "release-image.tar").exists()
        assert not (output / "release.pub").exists()
    assert sum(command[:2] == ["cosign", "verify-blob"] for command in calls) == expected_signed
    assert all(
        {"--tlog-upload=false", "--use-signing-config=false", "--new-bundle-format=false"}.issubset(command)
        for command in calls
        if command[:2] == ["cosign", "sign-blob"]
    )
    verify_commands = [command for command in calls if command[:2] == ["cosign", "verify-blob"]]
    assert all("--use-signing-config=false" not in command for command in verify_commands)
    source_scan = next(command for command in calls if command[0] == "syft" and command[1].startswith("dir:"))
    assert "--base-path" in source_scan
    assert "**/.aws/**" in source_scan
    assert "**/.ssh/**" in source_scan
    assert "**/.npmrc" in source_scan
    assert "**/*.pem" in source_scan
    image_scan = next(command for command in calls if command[0] == "syft" and command[1].startswith("docker-archive:"))
    for command, tool_env in environments:
        tool = command[0]
        assert "AWS_ACCESS_KEY_ID" not in tool_env
        assert "GITHUB_TOKEN" not in tool_env
        assert "GRYPE_FAIL_ON_SEVERITY" not in tool_env
        assert "SYFT_EXCLUDE" not in tool_env
        assert tool_env["AWS_EC2_METADATA_DISABLED"] == "true"
        if tuple(command[:2]) in {("cosign", "sign-blob"), ("cosign", "verify-blob")}:
            assert tool_env["COSIGN_PASSWORD"] == "cosign-test-password"
        else:
            assert "COSIGN_PASSWORD" not in tool_env
        assert "COSIGN_EXPERIMENTAL" not in tool_env


def test_run_release_returns_unknown_for_stale_vulnerability_database(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    image_archive = tmp_path / "image.tar"
    image_archive.write_bytes(b"image")
    private_key = tmp_path / "cosign.key"
    public_key = tmp_path / "cosign.pub"
    private_key.write_text("private")
    private_key.chmod(0o600)
    public_key.write_text("public")

    def fake_run(command, **kwargs):
        command = [str(part) for part in command]
        if command[1] == "version":
            version = supply_chain.PINNED_TOOL_VERSIONS[command[0]]
            return SimpleNamespace(returncode=0, stdout=f"Version: {version}\n", stderr="")
        if command[0] == "syft":
            Path(command[-1].split("=", 1)[1]).write_text(json.dumps(_cyclonedx()))
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[0] == "grype" and command[1] == "db":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(_db_status(built="2026-10-27T11:00:00Z")),
                stderr="",
            )
        if command[0] == "grype":
            return SimpleNamespace(returncode=1, stdout="", stderr="database is stale")
        raise AssertionError(f"scans must not use stale database: {command}")

    monkeypatch.setattr(supply_chain.subprocess, "run", fake_run)
    output = tmp_path / "release"
    result = supply_chain.run_release(
        source_dir=source,
        image_archive=image_archive,
        image_format="docker-archive",
        output_dir=output,
        signing_key=private_key,
        public_key=public_key,
        fail_on="HIGH",
    )

    assert result["status"] == "UNKNOWN"
    status_record = json.loads((output / "supply-chain-status.json").read_text())
    assert status_record["contract"]["scan_run"]["status"] == "UNKNOWN"
    assert status_record["contract"]["scan_run"]["exit_code"] == 3
    assert status_record["contract"]["scan_run"]["gate_status"] == "NOT_CONFIGURED"
    assert len(status_record["contract"]["artifact_results"]) == 2
    assert {item["artifact_type"] for item in status_record["contract"]["artifact_results"]} == {"SBOM"}
    assert result["failure"]["code"] == "VulnerabilityDatabaseUnavailable"
    assert "stale" in result["failure"]["message"]
    assert not list(output.glob("*.sig"))
    assert status_record["status"] == "UNKNOWN"


def test_run_release_records_tool_unavailability_as_contract_error(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    image_archive = tmp_path / "image.tar"
    image_archive.write_bytes(b"image")
    private_key = tmp_path / "cosign.key"
    public_key = tmp_path / "cosign.pub"
    private_key.write_text("private")
    private_key.chmod(0o600)
    public_key.write_text("public")

    def missing_tool(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(supply_chain.subprocess, "run", missing_tool)
    output = tmp_path / "release"
    result = supply_chain.run_release(
        source_dir=source,
        image_archive=image_archive,
        image_format="docker-archive",
        output_dir=output,
        signing_key=private_key,
        public_key=public_key,
    )

    contract_run = result["contract"]["scan_run"]
    assert contract_run["status"] == "ERROR"
    assert contract_run["exit_code"] == 2
    assert contract_run["gate_status"] == "NOT_CONFIGURED"
    assert result["contract"]["artifact_results"] == []
    assert json.loads((output / "supply-chain-status.json").read_text())["contract"] == result[
        "contract"
    ]


def test_run_release_refuses_to_overwrite_existing_artifacts(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    image_archive = tmp_path / "image.tar"
    image_archive.write_bytes(b"image")
    private_key = tmp_path / "cosign.key"
    public_key = tmp_path / "cosign.pub"
    private_key.write_text("private")
    private_key.chmod(0o600)
    public_key.write_text("public")
    output = tmp_path / "release"
    output.mkdir()
    existing = output / "source.sbom.cdx.json"
    existing.write_text("keep this")

    with pytest.raises(supply_chain.SupplyChainError, match="already exists"):
        supply_chain.run_release(
            source_dir=source,
            image_archive=image_archive,
            image_format="docker-archive",
            output_dir=output,
            signing_key=private_key,
            public_key=public_key,
            fail_on="HIGH",
        )

    assert existing.read_text() == "keep this"


def test_run_release_refuses_dangling_symlink_output(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    image_archive = tmp_path / "image.tar"
    image_archive.write_bytes(b"image")
    private_key = tmp_path / "cosign.key"
    public_key = tmp_path / "cosign.pub"
    private_key.write_text("private")
    private_key.chmod(0o600)
    public_key.write_text("public")
    output = tmp_path / "release"
    output.mkdir()
    redirected = tmp_path / "redirected-output.json"
    (output / "source.sbom.cdx.json").symlink_to(redirected)

    with pytest.raises(supply_chain.SupplyChainError, match="already exists"):
        supply_chain.run_release(
            source_dir=source,
            image_archive=image_archive,
            image_format="docker-archive",
            output_dir=output,
            signing_key=private_key,
            public_key=public_key,
        )

    assert not redirected.exists()


def test_run_release_rejects_group_or_world_readable_private_key(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    image_archive = tmp_path / "image.tar"
    image_archive.write_bytes(b"image")
    private_key = tmp_path / "cosign.key"
    public_key = tmp_path / "cosign.pub"
    private_key.write_text("private")
    private_key.chmod(0o644)
    public_key.write_text("public")

    with pytest.raises(supply_chain.SupplyChainError, match="deny group and other access"):
        supply_chain.run_release(
            source_dir=source,
            image_archive=image_archive,
            image_format="docker-archive",
            output_dir=tmp_path / "release",
            signing_key=private_key,
            public_key=public_key,
        )


def test_run_release_rejects_same_file_for_public_and_private_keys(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    image_archive = tmp_path / "image.tar"
    image_archive.write_bytes(b"image")
    key = tmp_path / "cosign.key"
    key.write_text("private")
    key.chmod(0o600)

    with pytest.raises(supply_chain.SupplyChainError, match="must be different files"):
        supply_chain.run_release(
            source_dir=source,
            image_archive=image_archive,
            image_format="docker-archive",
            output_dir=tmp_path / "release",
            signing_key=key,
            public_key=key,
        )


def test_atomic_status_write_preserves_a_preexisting_temporary_file(tmp_path):
    destination = tmp_path / "supply-chain-status.json"
    temporary = tmp_path / ".supply-chain-status.json.tmp"
    temporary.write_text("keep this")

    with pytest.raises(supply_chain.SupplyChainError, match="temporary output file already exists"):
        supply_chain._write_json(destination, {"status": "UNKNOWN"})

    assert temporary.read_text() == "keep this"


def test_cli_exposes_supply_chain_release_without_aws_options(capsys):
    from auditor import cli

    with pytest.raises(SystemExit) as exit_info:
        cli.main(["supply-chain-release", "--help"])

    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "--image-archive" in help_text
    assert "--signing-key" in help_text
    assert "--profile" not in help_text


def test_cli_supply_chain_release_does_not_create_an_aws_session(monkeypatch, capsys):
    from auditor import cli

    def forbidden_aws_session(**kwargs):
        raise AssertionError("supply-chain release must not create AWS sessions")

    monkeypatch.setattr(cli, "build_session", forbidden_aws_session)
    monkeypatch.setattr(
        supply_chain,
        "run_release",
        lambda **kwargs: {"status": "PASS", "signed_artifacts": []},
    )

    code = cli.main(
        [
            "supply-chain-release",
            "--image-archive",
            "/tmp/image.tar",
            "--output-dir",
            "/tmp/release",
            "--signing-key",
            "/tmp/cosign.key",
            "--public-key",
            "/tmp/cosign.pub",
        ]
    )

    assert code == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"
