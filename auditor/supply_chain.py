"""Local, fail-closed release checks for source and container artifacts.

This module invokes pinned Syft, Grype, and Cosign CLIs. It never creates an
AWS session and does not upload artifacts or signatures to a registry.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .models.contracts import (
    CONTRACT_VERSION,
    EXIT_CODE_BY_STATUS,
    ArtifactResult,
    GateStatus,
    ScanRun,
    ScanStatus,
    scanner_finding_record,
)
from .severity import Severity
from .utils.process import credential_safe_environment

SCHEMA_VERSION = "1.0.0"
PINNED_TOOL_VERSIONS = {"syft": "1.55.0", "grype": "0.121.0", "cosign": "3.1.4"}
DB_MAX_AGE = timedelta(hours=120)
VULNERABILITY_SEVERITIES = ("NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(VULNERABILITY_SEVERITIES)}
PROJECT_SEVERITY = {
    "NEGLIGIBLE": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}
_GRYPE_VULNERABILITY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_GRYPE_PACKAGE_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+~:@-]{0,255}\Z")
_SEMVER = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+)(?![\w.])")
SOURCE_EXCLUDES = (
    "./.aws/**",
    "**/.aws/**",
    "./.ssh/**",
    "**/.ssh/**",
    "./.kube/**",
    "**/.kube/**",
    "./.docker/**",
    "**/.docker/**",
    "./.env",
    "**/.env",
    "./.env.*",
    "**/.env.*",
    "./.git/**",
    "**/credentials",
    "./.netrc",
    "**/.netrc",
    "./.npmrc",
    "**/.npmrc",
    "./.pypirc",
    "**/.pypirc",
    "./.git-credentials",
    "**/.git-credentials",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.p8",
    "**/*.jks",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "./AGENTS.md",
    "./CLAUDE.md",
    "**/*.docx",
    "**/.git/**",
    "./.venv/**",
    "**/.venv/**",
    "./venv/**",
    "**/venv/**",
    "./__pycache__/**",
    "**/__pycache__/**",
    "./reports/**",
    "**/reports/**",
    "./results/coverage.json",
    "./.coverage",
)
_PRIVATE_DIRECTORIES = {".aws", ".ssh", ".kube", ".docker"}
_PRIVATE_FILE_NAMES = {
    "credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}
_PRIVATE_FILE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".p8", ".jks")

ARTIFACT_NAMES = (
    "source.sbom.cdx.json",
    "image.sbom.cdx.json",
    "source.vulnerabilities.json",
    "image.vulnerabilities.json",
    "release-image.tar",
    "release.pub",
)


class SupplyChainError(ValueError):
    """Invalid input or unusable tool output; details never include secrets."""

    def __init__(self, message: str, *, code: str = "SupplyChainError") -> None:
        super().__init__(message)
        self.code = code


def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and require an explicit timezone."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise SupplyChainError(
            "invalid timestamp in vulnerability database metadata",
            code="VulnerabilityDatabaseUnavailable",
        ) from None
    if parsed.tzinfo is None:
        raise SupplyChainError(
            "vulnerability database timestamp has no timezone",
            code="VulnerabilityDatabaseUnavailable",
        )
    return parsed.astimezone(UTC)


def canonical_sbom_digest(document: dict[str, Any]) -> str:
    """Hash CycloneDX content while excluding generator-assigned metadata.

    Syft assigns a fresh serial number and generation timestamp for each run.
    Those fields do not describe package inventory, so excluding them gives a
    stable semantic digest while preserving the original, standards-compliant
    SBOM as the signed artifact.
    """
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise SupplyChainError("Syft output is not a CycloneDX SBOM", code="InvalidSbom")
    canonical = json.loads(json.dumps(document))
    canonical.pop("serialNumber", None)
    metadata = canonical.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("timestamp", None)
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _normalize_grype_match(match: Any, *, artifact_scope: str) -> tuple[dict[str, Any], str]:
    """Adapt one untrusted Grype match into a stable, scanner-neutral finding."""
    if artifact_scope not in {"dependency", "source", "image"}:
        raise SupplyChainError("Grype report has an unsupported artifact scope", code="InvalidGrypeReport")
    if not isinstance(match, dict):
        raise SupplyChainError("Grype report contains an invalid match", code="InvalidGrypeReport")

    vulnerability = match.get("vulnerability")
    artifact = match.get("artifact")
    if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
        raise SupplyChainError(
            "Grype report match is missing a stable package identity or vulnerability",
            code="InvalidGrypeReport",
        )

    vulnerability_id = vulnerability.get("id")
    if not isinstance(vulnerability_id, str) or not _GRYPE_VULNERABILITY_ID.fullmatch(vulnerability_id):
        raise SupplyChainError("Grype report contains an invalid vulnerability ID", code="InvalidGrypeReport")

    source_severity = vulnerability.get("severity")
    if not isinstance(source_severity, str) or source_severity.strip().upper() not in SEVERITY_RANK:
        raise SupplyChainError(
            "Grype report contains an unrecognized severity; scan cannot pass",
            code="InvalidGrypeReport",
        )
    normalized_source_severity = source_severity.strip()
    severity_key = normalized_source_severity.upper()

    package_name = artifact.get("name")
    package_version = artifact.get("version")
    package_type = artifact.get("type")
    if any(
        not isinstance(value, str) or not _GRYPE_PACKAGE_PART.fullmatch(value)
        for value in (package_name, package_version, package_type)
    ):
        raise SupplyChainError(
            "Grype report match is missing a stable package identity",
            code="InvalidGrypeReport",
        )

    package_url = artifact.get("purl")
    if package_url is None:
        package_identity = f"pkg:{package_type}/{package_name}@{package_version}"
    elif (
        isinstance(package_url, str)
        and package_url.startswith("pkg:")
        and len(package_url) <= 4096
        and not any(ord(character) < 32 for character in package_url)
    ):
        # Hash the optional PURL for identity; do not copy arbitrary qualifiers
        # into reports, where they could contain private repository metadata.
        package_identity = package_url
    else:
        raise SupplyChainError("Grype report contains an invalid package URL", code="InvalidGrypeReport")

    resource_digest = hashlib.sha256(package_identity.encode("utf-8")).hexdigest()[:32]
    record = scanner_finding_record(
        control_id=f"VULN-{vulnerability_id}",
        scanner="grype",
        scanner_rule_id=vulnerability_id,
        source_type=f"supply-chain-{artifact_scope}",
        severity=PROJECT_SEVERITY[severity_key],
        source_severity=normalized_source_severity,
        title=f"{vulnerability_id} affects {package_name} {package_version}",
        description=(
            f"Grype reported {vulnerability_id} for {package_type} package {package_name}@{package_version}."
        ),
        remediation=f"Update {package_name} to a non-vulnerable version when available.",
        evidence={
            "vulnerability_id": vulnerability_id,
            "package": {
                "name": package_name,
                "version": package_version,
                "type": package_type,
            },
        },
        resource_reference=f"{artifact_scope}:sha256:{resource_digest}:{vulnerability_id}",
    )
    return record, severity_key


def assess_grype_report(
    document: dict[str, Any], *, fail_on: str, artifact_scope: str = "dependency"
) -> dict[str, Any]:
    """Validate a Grype report, normalize its matches, and apply the severity threshold."""
    threshold = fail_on.upper()
    if threshold not in SEVERITY_RANK:
        raise SupplyChainError("unsupported vulnerability severity threshold")
    matches = document.get("matches") if isinstance(document, dict) else None
    if not isinstance(matches, list):
        raise SupplyChainError("Grype report must contain a matches array", code="InvalidGrypeReport")

    counts = dict.fromkeys(VULNERABILITY_SEVERITIES, 0)
    findings = []
    for match in matches:
        finding, severity = _normalize_grype_match(match, artifact_scope=artifact_scope)
        findings.append(finding)
        counts[severity] += 1

    failing = sum(
        count for severity, count in counts.items() if SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]
    )
    return {
        "finding_count": len(matches),
        "severity_counts": counts,
        "fail_on": threshold,
        "gate_status": "FAIL" if failing else "PASS",
        "threshold_findings": failing,
        "findings": findings,
    }


def _grype_database_provenance(document: dict[str, Any]) -> dict[str, Any]:
    descriptor = document.get("descriptor")
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("name") != "grype"
        or descriptor.get("version") != PINNED_TOOL_VERSIONS["grype"]
    ):
        raise SupplyChainError(
            "Grype report descriptor is missing or does not match the pinned scanner",
            code="InvalidGrypeReport",
        )
    database = descriptor.get("db")
    if not isinstance(database, dict):
        raise SupplyChainError(
            "Grype report does not identify the vulnerability database used",
            code="VulnerabilityDatabaseUnavailable",
        )
    nested_status = database.get("status")
    status_fields = nested_status if isinstance(nested_status, dict) else database
    if _database_status_value(status_fields, allow_unmarked=not isinstance(nested_status, dict)) is None:
        raise SupplyChainError(
            "Grype report identifies an invalid vulnerability database",
            code="VulnerabilityDatabaseUnavailable",
        )
    built = status_fields.get("built") or status_fields.get("builtAt")
    schema = status_fields.get("schemaVersion") or status_fields.get("schema_version")
    if not isinstance(built, str) or schema is None:
        raise SupplyChainError(
            "Grype report has incomplete vulnerability database provenance",
            code="VulnerabilityDatabaseUnavailable",
        )
    checksum = status_fields.get("checksum") or database.get("checksum")
    return {
        "schema_version": str(schema),
        "built_at": parse_utc(built).isoformat(),
        "checksum": checksum if isinstance(checksum, str) else None,
    }


def _database_status_value(document: dict[str, Any], *, allow_unmarked: bool) -> str | None:
    raw_status = document.get("status")
    if "valid" in document:
        if type(document["valid"]) is not bool or not document["valid"]:
            return None
        if raw_status is not None and (
            not isinstance(raw_status, str) or raw_status.lower() not in {"valid", "ok"}
        ):
            return None
        return "valid"
    if isinstance(raw_status, str) and raw_status.lower() in {"valid", "ok"}:
        return "valid"
    if allow_unmarked and raw_status is None:
        return "valid"
    return None


def normalize_database_status(document: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Validate Grype DB status and return provenance with a strict 120h age cap."""
    if not isinstance(document, dict):
        raise SupplyChainError(
            "Grype database status is not a JSON object", code="VulnerabilityDatabaseUnavailable"
        )
    normalized_status = _database_status_value(document, allow_unmarked=False)
    if normalized_status is None:
        raise SupplyChainError(
            "Grype vulnerability database is unavailable or invalid",
            code="VulnerabilityDatabaseUnavailable",
        )

    built = document.get("built") or document.get("builtAt") or document.get("buildDate")
    if not isinstance(built, str):
        raise SupplyChainError(
            "Grype database status is missing its build timestamp",
            code="VulnerabilityDatabaseUnavailable",
        )
    built_at = parse_utc(built)
    now_utc = now.astimezone(UTC) if now else datetime.now(UTC)
    age = now_utc - built_at
    if age < timedelta(minutes=-5):
        raise SupplyChainError(
            "Grype vulnerability database has a future build timestamp",
            code="VulnerabilityDatabaseUnavailable",
        )
    if age > DB_MAX_AGE:
        raise SupplyChainError(
            "Grype vulnerability database is stale (older than 120 hours)",
            code="VulnerabilityDatabaseUnavailable",
        )

    schema = document.get("schemaVersion") or document.get("schema_version")
    if schema is None:
        raise SupplyChainError(
            "Grype database status is missing its schema version",
            code="VulnerabilityDatabaseUnavailable",
        )
    checksum = document.get("checksum")
    return {
        "status": normalized_status,
        "schema_version": str(schema),
        "built_at": built_at.isoformat(),
        "age_hours": max(0, int(age.total_seconds() // 3600)),
        "checksum": checksum if isinstance(checksum, str) else None,
    }


def _validate_scan_database_provenance(scans: dict[str, Any], database: dict[str, Any]) -> None:
    """Require every scan to identify the fresh database whose status was checked."""
    for scan in scans.values():
        used = scan.get("database_used") if isinstance(scan, dict) else None
        if not isinstance(used, dict) or (
            used.get("schema_version") != database["schema_version"]
            or used.get("built_at") != database["built_at"]
            or (used.get("checksum") is not None and used.get("checksum") != database["checksum"])
        ):
            raise SupplyChainError(
                "Grype reports do not agree on the vulnerability database used",
                code="VulnerabilityDatabaseUnavailable",
            )


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        parts = relative.split("/")
        if relative in {".coverage", "results/coverage.json"} or any(
            part in _PRIVATE_DIRECTORIES | {".git", ".venv", "venv", "__pycache__", "reports"}
            or part == ".env"
            or part.startswith(".env.")
            or part in _PRIVATE_FILE_NAMES
            or part in {"AGENTS.md", "CLAUDE.md"}
            or part.endswith(".docx")
            or part.endswith(_PRIVATE_FILE_SUFFIXES)
            for part in parts
        ):
            continue
        if path.is_symlink():
            digest.update(b"L\0" + relative.encode("utf-8") + b"\0")
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
            digest.update(b"\0")
        elif path.is_file():
            digest.update(b"F\0" + relative.encode("utf-8") + b"\0")
            digest.update(_file_digest(path).encode("ascii"))
            digest.update(b"\0")
    return digest.hexdigest()


def _run(command: list[str], *, timeout: int = 900, env: dict[str, str] | None = None):
    """Run a pinned tool without a shell, interactive stdin, or echoed output."""
    environment = env if env is not None else _tool_environment()
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
    except FileNotFoundError:
        raise SupplyChainError(
            f"required tool is unavailable: {Path(command[0]).name}", code="ToolUnavailable"
        ) from None
    except subprocess.TimeoutExpired:
        raise SupplyChainError(f"tool timed out: {Path(command[0]).name}", code="ToolTimeout") from None
    if result.returncode:
        raise SupplyChainError(
            f"{Path(command[0]).name} exited with status {result.returncode}", code="ToolExecutionFailed"
        )
    return result


def _tool_environment(*, allow: set[str] | None = None) -> dict[str, str]:
    allowed = allow or set()
    environment = credential_safe_environment(allow=allowed)
    # Caller-owned scanner overrides could add ignored findings, change scan
    # sources, or enable ambient identity. Keep only the one Cosign key password.
    for key in tuple(environment):
        if key.startswith(("SYFT_", "GRYPE_", "COSIGN_")) and key not in allowed:
            del environment[key]
    return environment


def _extract_version(output: str, tool: str) -> str:
    match = _SEMVER.search(output)
    if not match:
        raise SupplyChainError(f"could not parse {tool} version", code="InvalidToolVersion")
    return match.group(1)


def _check_tool_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for tool, pinned in PINNED_TOOL_VERSIONS.items():
        result = _run([tool, "version"])
        actual = _extract_version(result.stdout + "\n" + result.stderr, tool)
        if actual != pinned:
            raise SupplyChainError(
                f"{tool} version {actual} does not match pinned version {pinned}",
                code="ToolVersionMismatch",
            )
        versions[tool] = actual
    return versions


def _read_json(path: Path, *, purpose: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SupplyChainError(f"{purpose} did not produce valid JSON", code="InvalidToolOutput") from None
    if not isinstance(document, dict):
        raise SupplyChainError(f"{purpose} output must be a JSON object", code="InvalidToolOutput")
    return document


def _write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    created_temporary = False
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            created_temporary = True
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    except FileExistsError:
        if created_temporary:
            raise SupplyChainError(f"refusing to overwrite existing output: {path.name}") from None
        raise SupplyChainError(f"temporary output file already exists: {temporary.name}") from None
    finally:
        if created_temporary:
            temporary.unlink(missing_ok=True)


def _validate_input_file(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise SupplyChainError(f"{label} must be an existing regular file")
    return path.resolve()


def _validate_directory(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise SupplyChainError(f"{label} must be an existing directory")
    return path.resolve()


def _under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _tool_error_report(
    *,
    started_at: str,
    tool_versions: dict[str, str],
    exc: SupplyChainError,
    database: dict[str, Any] | None = None,
    scans: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status = "UNKNOWN" if exc.code == "VulnerabilityDatabaseUnavailable" else "ERROR"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "started_at": started_at,
        "status": status,
        "tool_versions": tool_versions,
        "vulnerability_database": database,
        "scans": scans or {},
        "signed_artifacts": [],
        "failure": {"code": exc.code, "message": str(exc)},
    }


def _artifact_results(
    output: Path,
    *,
    image_format: str,
    tool_versions: dict[str, str],
    scans: dict[str, Any],
    signed_artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize available release files into the shared artifact contract."""
    verified_by_file = {
        item.get("file"): item
        for item in signed_artifacts
        if isinstance(item, dict) and isinstance(item.get("file"), str)
    }
    specifications = (
        ("source.sbom.cdx.json", "SBOM", "CycloneDX JSON", "syft", None),
        ("image.sbom.cdx.json", "SBOM", "CycloneDX JSON", "syft", None),
        (
            "source.vulnerabilities.json",
            "VULNERABILITY_REPORT",
            "Grype JSON",
            "grype",
            "source",
        ),
        (
            "image.vulnerabilities.json",
            "VULNERABILITY_REPORT",
            "Grype JSON",
            "grype",
            "image",
        ),
        (
            "release-image.tar",
            "CONTAINER_ARCHIVE",
            {"docker-archive": "Docker archive", "oci-archive": "OCI archive"}.get(
                image_format, "Container archive"
            ),
            "account-access-auditor",
            None,
        ),
    )
    public_key = output / "release.pub"
    signature_identity = f"sha256:{_file_digest(public_key)}" if public_key.is_file() else None
    records: list[dict[str, Any]] = []
    for name, artifact_type, artifact_format, scanner, scan_name in specifications:
        path = output / name
        if not path.is_file():
            continue
        digest = _file_digest(path)
        signature = verified_by_file.get(name)
        verified = bool(
            signature
            and signature.get("verified") is True
            and signature.get("sha256") == digest
            and signature_identity is not None
        )
        scan = scans.get(scan_name, {}) if scan_name else {}
        database_provenance = scan.get("database_used") if isinstance(scan, dict) else None
        record = ArtifactResult(
            schema_version=CONTRACT_VERSION,
            artifact_type=artifact_type,
            location=name,
            format=artifact_format,
            sha256=digest,
            scanner=scanner,
            scanner_version=tool_versions.get(
                scanner, __version__ if scanner == "account-access-auditor" else "unknown"
            ),
            database_provenance=database_provenance,
            signature_identity=signature_identity if verified else None,
            signature_verified=verified,
            # This local release flow has no build attestation or trusted builder identity.
            provenance_verified=None,
        )
        records.append(record.to_dict())
    return records


def _contract_record(
    output: Path,
    *,
    started_at: str,
    completed_at: str,
    status: str,
    gate_threshold: str,
    image_format: str,
    tool_versions: dict[str, str],
    scans: dict[str, Any],
    signed_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    scan_status = ScanStatus(status)
    gate_evaluated = (
        status != ScanStatus.UNKNOWN.value
        and len(scans) == 2
        and all(isinstance(scan, dict) and "gate_status" in scan for scan in scans.values())
    )
    if gate_evaluated:
        gate_status = (
            GateStatus.FAIL
            if any(scan.get("gate_status") == "FAIL" for scan in scans.values())
            else GateStatus.PASS
        )
    else:
        gate_status = GateStatus.NOT_CONFIGURED
    finding_count = sum(
        scan.get("finding_count", 0)
        for scan in scans.values()
        if isinstance(scan, dict)
        and isinstance(scan.get("finding_count", 0), int)
        and not isinstance(scan.get("finding_count", 0), bool)
    )
    versions = {"account-access-auditor": __version__, **tool_versions}
    run_id = f"supply-chain-{uuid.uuid4().hex}"
    contract_findings = [
        {**finding, "run_id": run_id}
        for scan in scans.values()
        if isinstance(scan, dict) and isinstance(scan.get("findings"), list)
        for finding in scan["findings"]
        if isinstance(finding, dict)
    ]
    scan_run = ScanRun(
        schema_version=CONTRACT_VERSION,
        run_id=run_id,
        scan_source="supply-chain-release",
        commit_ref=None,
        workflow_ref=None,
        account_refs=[],
        regions=[],
        scanner_versions=versions,
        policy_pack_version=None,
        started_at=started_at,
        completed_at=completed_at,
        status=scan_status,
        gate_status=gate_status,
        exit_code=EXIT_CODE_BY_STATUS[scan_status],
        finding_count=finding_count,
        collection_error_count=0 if scan_status in {ScanStatus.PASS, ScanStatus.FAIL} else 1,
        gate_threshold=gate_threshold if gate_status is not GateStatus.NOT_CONFIGURED else None,
    )
    return {
        "schema_version": CONTRACT_VERSION,
        "scan_run": scan_run.to_dict(),
        "findings": contract_findings,
        "artifact_results": _artifact_results(
            output,
            image_format=image_format,
            tool_versions=tool_versions,
            scans=scans,
            signed_artifacts=signed_artifacts,
        ),
    }


def _database_provenance(document: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(document, dict):
        return None
    nested_status = document.get("status")
    status_fields = nested_status if isinstance(nested_status, dict) else document
    built = status_fields.get("built") or status_fields.get("builtAt") or status_fields.get("buildDate")
    schema = status_fields.get("schemaVersion") or status_fields.get("schema_version")
    provenance: dict[str, Any] = {
        "status": _database_status_value(status_fields, allow_unmarked=False) or "unknown",
        "schema_version": str(schema) if schema is not None else None,
        "built_at": None,
        "checksum": status_fields.get("checksum") if isinstance(status_fields.get("checksum"), str) else None,
    }
    if isinstance(built, str):
        try:
            provenance["built_at"] = parse_utc(built).isoformat()
        except SupplyChainError:
            provenance["built_at"] = built[:100]
    return provenance


def _db_status() -> dict[str, Any]:
    try:
        result = _run(["grype", "db", "status", "-o", "json"])
    except SupplyChainError:
        raise SupplyChainError(
            "Grype vulnerability database status is unavailable; scan result is UNKNOWN",
            code="VulnerabilityDatabaseUnavailable",
        ) from None
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise SupplyChainError(
            "Grype database status did not return valid JSON", code="VulnerabilityDatabaseUnavailable"
        ) from None
    if not isinstance(document, dict):
        raise SupplyChainError(
            "Grype database status is not a JSON object", code="VulnerabilityDatabaseUnavailable"
        )
    return document


def _scan_sbom(
    sbom: Path, report_path: Path, *, fail_on: str, artifact_scope: str, config_path: Path
) -> dict[str, Any]:
    try:
        _run(
            [
                "grype",
                f"sbom:{sbom}",
                "--config",
                str(config_path),
                "-o",
                "json",
                "--file",
                str(report_path),
            ]
        )
    except SupplyChainError as exc:
        if exc.code == "ToolUnavailable":
            raise
        raise SupplyChainError(
            "Grype could not complete the vulnerability scan",
            code="ScannerExecutionFailed",
        ) from None
    report = _read_json(report_path, purpose="Grype")
    assessment = assess_grype_report(report, fail_on=fail_on, artifact_scope=artifact_scope)
    assessment["database_used"] = _grype_database_provenance(report)
    assessment["report"] = report_path.name
    assessment["report_sha256"] = _file_digest(report_path)
    assessment["sbom"] = sbom.name
    return assessment


def _save_runtime_failure(
    output: Path,
    *,
    started_at: str,
    tool_versions: dict[str, str],
    exc: SupplyChainError,
    database: dict[str, Any] | None,
    scans: dict[str, Any],
    gate_threshold: str,
    image_format: str,
) -> dict[str, Any]:
    status = _tool_error_report(
        started_at=started_at,
        tool_versions=tool_versions,
        exc=exc,
        database=database,
        scans=scans,
    )
    status["contract"] = _contract_record(
        output,
        started_at=started_at,
        completed_at=status["generated_at"],
        status=status["status"],
        gate_threshold=gate_threshold,
        image_format=image_format,
        tool_versions=tool_versions,
        scans=scans,
        signed_artifacts=status["signed_artifacts"],
    )
    _write_json(output / "supply-chain-status.json", status)
    return status


def run_release(
    *,
    source_dir: str | Path,
    image_archive: str | Path,
    image_format: str,
    output_dir: str | Path,
    signing_key: str | Path,
    public_key: str | Path,
    fail_on: str = "HIGH",
) -> dict[str, Any]:
    """Create a local SBOM, vulnerability report, and verified signed release.

    Output files are immutable per run: this command refuses to overwrite any
    existing output. Cosign uses a local key and disables transparency-log
    upload, making the demo self-contained and requiring no AWS or registry.
    """
    threshold = fail_on.upper()
    if threshold not in SEVERITY_RANK:
        raise SupplyChainError("unsupported vulnerability severity threshold")
    if image_format not in {"docker-archive", "oci-archive"}:
        raise SupplyChainError("image format must be docker-archive or oci-archive")

    source = _validate_directory(Path(source_dir), label="source")
    archive = _validate_input_file(Path(image_archive), label="image archive")
    key = _validate_input_file(Path(signing_key), label="Cosign private key")
    pub = _validate_input_file(Path(public_key), label="Cosign public key")
    if os.name == "posix" and key.stat().st_mode & 0o077:
        raise SupplyChainError("Cosign private key permissions must deny group and other access")
    output_argument = Path(output_dir)
    if output_argument.is_symlink():
        raise SupplyChainError("output directory must not be a symbolic link")
    output = output_argument.resolve()
    if _under(output, source):
        raise SupplyChainError("output directory must be outside the source directory")
    if key.samefile(pub):
        raise SupplyChainError("Cosign public and private key must be different files")
    if _under(key, source) or _under(key, output):
        raise SupplyChainError("Cosign private key must be stored outside source and release directories")

    output.mkdir(parents=True, exist_ok=True)
    output_names = set(ARTIFACT_NAMES) | {
        "release-manifest.json",
        "supply-chain-status.json",
        *(f"{name}.sig" for name in ARTIFACT_NAMES if name != "release.pub"),
    }
    existing = sorted(name for name in output_names if os.path.lexists(output / name))
    if existing:
        raise SupplyChainError(f"output file already exists and will not be overwritten: {existing[0]}")

    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    input_source_sha256 = _tree_digest(source)
    tool_versions: dict[str, str] = {}
    scans: dict[str, Any] = {}
    database: dict[str, Any] | None = None
    try:
        tool_versions = _check_tool_versions()
        source_sbom = output / "source.sbom.cdx.json"
        image_sbom = output / "image.sbom.cdx.json"
        source_report = output / "source.vulnerabilities.json"
        image_report = output / "image.vulnerabilities.json"

        with tempfile.TemporaryDirectory(prefix="account-access-auditor-syft-") as config_directory:
            syft_config = Path(config_directory) / "syft-config.yaml"
            syft_config.write_text(
                json.dumps(
                    {"check-for-app-update": False, "cache": {"dir": "", "ttl": 0}},
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            source_command = [
                "syft",
                f"dir:{source}",
                "--base-path",
                str(source),
                "--config",
                str(syft_config),
            ]
            for pattern in SOURCE_EXCLUDES:
                source_command.extend(["--exclude", pattern])
            source_command.extend(["-o", f"cyclonedx-json={source_sbom}"])
            _run(source_command)
            source_document = _read_json(source_sbom, purpose="Syft")
            source_reproducible_digest = canonical_sbom_digest(source_document)

            image_target = f"{image_format}:{archive}"
            _run(
                [
                    "syft",
                    image_target,
                    "--config",
                    str(syft_config),
                    "-o",
                    f"cyclonedx-json={image_sbom}",
                ]
            )
            image_document = _read_json(image_sbom, purpose="Syft")
            image_reproducible_digest = canonical_sbom_digest(image_document)

        with tempfile.TemporaryDirectory(prefix="account-access-auditor-grype-") as config_directory:
            grype_config = Path(config_directory) / "grype-config.yaml"
            grype_config.write_text(
                json.dumps({"check-for-app-update": False}) + "\n",
                encoding="utf-8",
            )
            scans["source"] = _scan_sbom(
                source_sbom,
                source_report,
                fail_on=threshold,
                artifact_scope="source",
                config_path=grype_config,
            )
            scans["image"] = _scan_sbom(
                image_sbom,
                image_report,
                fail_on=threshold,
                artifact_scope="image",
                config_path=grype_config,
            )

        raw_database = _db_status()
        try:
            database = normalize_database_status(raw_database)
        except SupplyChainError as exc:
            if exc.code != "VulnerabilityDatabaseUnavailable":
                raise
            return _save_runtime_failure(
                output,
                started_at=started_at,
                tool_versions=tool_versions,
                exc=exc,
                database=_database_provenance(raw_database),
                scans=scans,
                gate_threshold=threshold,
                image_format=image_format,
            )
        _validate_scan_database_provenance(scans, database)

        manifest: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "started_at": started_at,
            "status": "FAIL" if any(scan["gate_status"] == "FAIL" for scan in scans.values()) else "PASS",
            "gate_threshold": threshold,
            "tool_versions": tool_versions,
            "vulnerability_database": database,
            "inputs": {
                "source_directory_sha256": input_source_sha256,
                "image_archive_sha256": _file_digest(archive),
                "image_format": image_format,
            },
            "sboms": {
                "source": {
                    "file": source_sbom.name,
                    "format": "CycloneDX JSON",
                    "sha256": _file_digest(source_sbom),
                    "reproducible_sha256": source_reproducible_digest,
                },
                "image": {
                    "file": image_sbom.name,
                    "format": "CycloneDX JSON",
                    "sha256": _file_digest(image_sbom),
                    "reproducible_sha256": image_reproducible_digest,
                },
            },
            "scans": scans,
            "signed_artifacts": [],
        }
        if manifest["status"] == "FAIL":
            manifest["contract"] = _contract_record(
                output,
                started_at=started_at,
                completed_at=manifest["generated_at"],
                status=manifest["status"],
                gate_threshold=threshold,
                image_format=image_format,
                tool_versions=tool_versions,
                scans=scans,
                signed_artifacts=manifest["signed_artifacts"],
            )
            _write_json(output / "release-manifest.json", manifest)
            return manifest

        # Only a passing scan copies the image into the release directory.
        release_image = output / "release-image.tar"
        with archive.open("rb") as source_handle, release_image.open("xb") as release_handle:
            shutil.copyfileobj(source_handle, release_handle)
        shutil.copystat(archive, release_image, follow_symlinks=False)
        with pub.open("rb") as public_handle, (output / "release.pub").open("xb") as exported_key:
            shutil.copyfileobj(public_handle, exported_key)

        artifacts = [
            release_image,
            source_sbom,
            image_sbom,
            source_report,
            image_report,
        ]
        cosign_env = _tool_environment(allow={"COSIGN_PASSWORD"})
        for artifact in artifacts:
            signature = output / f"{artifact.name}.sig"
            _run(
                [
                    "cosign",
                    "sign-blob",
                    "--yes",
                    "--new-bundle-format=false",
                    "--use-signing-config=false",
                    "--tlog-upload=false",
                    "--key",
                    str(key),
                    "--output-signature",
                    str(signature),
                    str(artifact),
                ],
                env=cosign_env,
            )
            if not signature.is_file() or signature.stat().st_size == 0:
                raise SupplyChainError("Cosign did not create a signature", code="SignatureFailed")
            _run(
                [
                    "cosign",
                    "verify-blob",
                    "--new-bundle-format=false",
                    "--insecure-ignore-tlog",
                    "--key",
                    str(output / "release.pub"),
                    "--signature",
                    str(signature),
                    str(artifact),
                ],
                env=cosign_env,
            )
            manifest["signed_artifacts"].append(
                {
                    "file": artifact.name,
                    "sha256": _file_digest(artifact),
                    "signature": signature.name,
                    "verified": True,
                    "verification": "cosign verify-blob with release.pub; transparency log skipped",
                }
            )

        manifest["contract"] = _contract_record(
            output,
            started_at=started_at,
            completed_at=manifest["generated_at"],
            status=manifest["status"],
            gate_threshold=threshold,
            image_format=image_format,
            tool_versions=tool_versions,
            scans=scans,
            signed_artifacts=manifest["signed_artifacts"],
        )
        _write_json(output / "release-manifest.json", manifest)
        return manifest
    except SupplyChainError as exc:
        if exc.code in {"VulnerabilityDatabaseUnavailable", "ScannerExecutionFailed"} and database is None:
            try:
                raw_database = _db_status()
                database = _database_provenance(raw_database)
                try:
                    normalize_database_status(raw_database)
                except SupplyChainError as database_error:
                    if database_error.code == "VulnerabilityDatabaseUnavailable":
                        exc = database_error
            except SupplyChainError:
                database = None
                exc = SupplyChainError(
                    "Grype vulnerability database status is unavailable; scan result is UNKNOWN",
                    code="VulnerabilityDatabaseUnavailable",
                )
        return _save_runtime_failure(
            output,
            started_at=started_at,
            tool_versions=tool_versions,
            exc=exc,
            database=database,
            scans=scans,
            gate_threshold=threshold,
            image_format=image_format,
        )
