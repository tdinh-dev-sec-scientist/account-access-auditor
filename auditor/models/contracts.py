"""Versioned records shared by current and future scanner adapters.

The existing report shape remains available for v1 consumers.  These records
provide a stable, scanner-neutral contract beside that legacy representation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ..severity import Severity
from .finding import Finding

CONTRACT_VERSION = "1.0.0"


class ScanStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class GateStatus(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    PASS = "PASS"
    FAIL = "FAIL"


EXIT_CODE_BY_STATUS = {
    ScanStatus.PASS: 0,
    ScanStatus.FAIL: 1,
    ScanStatus.ERROR: 2,
    ScanStatus.UNKNOWN: 3,
}


@dataclass(frozen=True)
class ScanOutcome:
    status: ScanStatus
    gate_status: GateStatus
    exit_code: int


def classify_scan(
    collection_errors: list[dict[str, Any]], gate_status: GateStatus | str | None = None
) -> ScanOutcome:
    """Classify a completed scan without treating missing data as a pass.

    A collector crash is an error.  AWS/API collection failures make coverage
    unknown.  A complete scan can fail only when a configured gate fails.
    """
    gate = GateStatus.NOT_CONFIGURED if gate_status is None else GateStatus(gate_status)

    if any(
        error.get("operation") == "collect" or error.get("category") == "scanner_error"
        for error in collection_errors
    ):
        status = ScanStatus.ERROR
    elif collection_errors:
        status = ScanStatus.UNKNOWN
    elif gate is GateStatus.FAIL:
        status = ScanStatus.FAIL
    else:
        status = ScanStatus.PASS

    return ScanOutcome(status, gate, EXIT_CODE_BY_STATUS[status])


def _compliance_references(compliance: dict[str, Any]) -> list[dict[str, str]]:
    control_id = compliance.get("control_id")
    if not control_id:
        return []
    reference = {
        "type": "compliance",
        "framework": str(compliance.get("framework") or ""),
        "id": str(control_id),
    }
    if compliance.get("control_title"):
        reference["title"] = str(compliance["control_title"])
    return [reference]


def _validate_source_location(source_location: Any) -> None:
    message = "source_location must contain a non-empty file and optional positive integer line"
    if not isinstance(source_location, dict) or set(source_location) not in (
        {"file"},
        {"file", "line"},
    ):
        raise ValueError(message)
    if not isinstance(source_location["file"], str) or not source_location["file"].strip():
        raise ValueError(message)
    if "line" in source_location and (
        not isinstance(source_location["line"], int)
        or isinstance(source_location["line"], bool)
        or source_location["line"] < 1
    ):
        raise ValueError(message)


def _validate_account_ref(account_ref: Any) -> None:
    if account_ref is not None and (
        not isinstance(account_ref, dict)
        or set(account_ref) != {"provider", "id"}
        or account_ref.get("provider") != "aws"
        or not isinstance(account_ref.get("id"), str)
        or not account_ref["id"].isdigit()
        or len(account_ref["id"]) != 12
    ):
        raise ValueError("account_ref must identify one 12-digit AWS account")


def finding_record(
    finding: Finding,
    *,
    source_type: str = "aws",
    scanner: str = "account-access-auditor",
    control_id: str | None = None,
    scanner_rule_id: str | None = None,
    resource_reference: str | None = None,
    resource_reference_is_stable: bool = True,
    source_location: dict[str, Any] | None = None,
    account_ref: dict[str, str] | None = None,
    region: str | None = None,
    service: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Adapt a v1 finding into the stable, versioned finding contract.

    Fingerprints use the canonical control, source type, and stable resource
    reference.  Source file and line identify findings that have no stable
    resource identifier.  Titles and evidence are deliberately excluded.
    """
    canonical_control = control_id or finding.rule_id
    source_rule = scanner_rule_id or finding.rule_id
    resource = finding.resource if resource_reference is None else resource_reference
    if not all(
        isinstance(value, str) and value.strip()
        for value in (canonical_control, source_rule, scanner, source_type)
    ):
        raise ValueError("control_id, scanner, and source_type must be non-empty")
    if resource is not None and not isinstance(resource, str):
        raise ValueError("resource_reference must be a string or None")
    if not resource_reference_is_stable:
        resource = None
    if source_location is not None:
        _validate_source_location(source_location)
    _validate_account_ref(account_ref)
    if region is not None and (not isinstance(region, str) or not region.strip()):
        raise ValueError("region must be non-empty text or None")
    if service is not None and (not isinstance(service, str) or not service.strip()):
        raise ValueError("service must be non-empty text or None")

    if resource:
        identity = {"resource_reference": resource}
    elif source_location:
        identity = {"source_location": source_location}
    else:
        raise ValueError("a stable resource_reference or source_location is required")

    fingerprint_input = {
        "control_id": canonical_control,
        "source_type": source_type,
        **identity,
    }
    if account_ref is not None:
        fingerprint_input["account_ref"] = account_ref
    if region is not None:
        fingerprint_input["region"] = region
    fingerprint_payload = json.dumps(fingerprint_input, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(fingerprint_payload.encode("utf-8")).hexdigest()[:16]

    record = {
        "schema_version": CONTRACT_VERSION,
        "control_id": canonical_control,
        "scanner": scanner,
        "scanner_rule_id": source_rule,
        "source_type": source_type,
        "resource_reference": resource or None,
        "source_location": source_location,
        "severity": finding.severity.value,
        "source_severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "references": _compliance_references(finding.compliance),
        "fingerprint": fingerprint,
        "lifecycle_state": str(finding.status or "OPEN").lower(),
        "detected_at": finding.detected_at,
        "run_id": run_id or finding.run_id,
    }
    if account_ref is not None:
        record["account_ref"] = dict(account_ref)
    if region is not None:
        record["region"] = region
    if service is not None:
        record["service"] = service
    return record


def scanner_finding_record(
    *,
    control_id: str,
    scanner: str,
    scanner_rule_id: str,
    source_type: str,
    severity: Severity | str,
    title: str,
    description: str,
    evidence: dict[str, Any],
    remediation: str = "",
    source_severity: str | None = None,
    resource_reference: str | None = None,
    source_location: dict[str, Any] | None = None,
    references: list[dict[str, str]] | None = None,
    account_ref: dict[str, str] | None = None,
    region: str | None = None,
    service: str | None = None,
    run_id: str | None = None,
    detected_at: str | None = None,
) -> dict[str, Any]:
    """Build a contract finding from a non-AWS scanner without using the AWS registry."""
    normalized_severity = Severity(severity).value
    values = (control_id, scanner, scanner_rule_id, source_type, title)
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise ValueError("control_id, scanner, scanner_rule_id, source_type, and title must be non-empty")
    if resource_reference is not None and (
        not isinstance(resource_reference, str) or not resource_reference.strip()
    ):
        raise ValueError("resource_reference must be a non-empty string or None")
    if source_location is not None:
        _validate_source_location(source_location)
    _validate_account_ref(account_ref)
    if region is not None and (not isinstance(region, str) or not region.strip()):
        raise ValueError("region must be non-empty text or None")
    if service is not None and (not isinstance(service, str) or not service.strip()):
        raise ValueError("service must be non-empty text or None")
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be an object")

    identity = (
        {"resource_reference": resource_reference}
        if resource_reference is not None
        else {"source_location": source_location}
    )
    if resource_reference is None and source_location is None:
        raise ValueError("a resource_reference or source_location is required")
    fingerprint_input = {"control_id": control_id, "source_type": source_type, **identity}
    if account_ref is not None:
        fingerprint_input["account_ref"] = account_ref
    if region is not None:
        fingerprint_input["region"] = region
    fingerprint_payload = json.dumps(fingerprint_input, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(fingerprint_payload.encode("utf-8")).hexdigest()[:16]

    record = {
        "schema_version": CONTRACT_VERSION,
        "control_id": control_id,
        "scanner": scanner,
        "scanner_rule_id": scanner_rule_id,
        "source_type": source_type,
        "resource_reference": resource_reference,
        "source_location": source_location,
        "severity": normalized_severity,
        "source_severity": source_severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "references": references or [],
        "fingerprint": fingerprint,
        "lifecycle_state": "open",
        "detected_at": detected_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "run_id": run_id,
    }
    if account_ref is not None:
        record["account_ref"] = dict(account_ref)
    if region is not None:
        record["region"] = region
    if service is not None:
        record["service"] = service
    return record


@dataclass(frozen=True)
class ScanRun:
    schema_version: str
    run_id: str
    scan_source: str
    commit_ref: str | None
    workflow_ref: str | None
    account_refs: list[dict[str, str]]
    regions: list[str]
    scanner_versions: dict[str, str]
    policy_pack_version: str | None
    started_at: str
    completed_at: str
    status: ScanStatus
    gate_status: GateStatus
    exit_code: int
    finding_count: int
    collection_error_count: int
    gate_threshold: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != CONTRACT_VERSION:
            raise ValueError(f"unsupported contract version: {self.schema_version}")
        if not self.run_id.strip() or not self.scan_source.strip():
            raise ValueError("run_id and scan_source must be non-empty")
        if self.exit_code != EXIT_CODE_BY_STATUS[self.status]:
            raise ValueError("exit_code does not match scan status")
        start = _parse_timestamp(self.started_at, "started_at")
        end = _parse_timestamp(self.completed_at, "completed_at")
        if end < start:
            raise ValueError("completed_at must not precede started_at")
        if min(self.finding_count, self.collection_error_count) < 0:
            raise ValueError("record counts must not be negative")
        if (
            self.gate_threshold is not None
            and Severity.from_string(self.gate_threshold).value != self.gate_threshold
        ):
            raise ValueError("gate_threshold must use a canonical uppercase severity")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["gate_status"] = self.gate_status.value
        if self.gate_threshold is None:
            data.pop("gate_threshold")
        return data


def _parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class ArtifactResult:
    """Versioned provenance for one file emitted by a scanner or release step."""

    schema_version: str
    artifact_type: str
    location: str
    format: str
    sha256: str
    scanner: str
    scanner_version: str
    database_provenance: dict[str, Any] | None = None
    signature_identity: str | None = None
    signature_verified: bool | None = None
    provenance_verified: bool | None = None

    def __post_init__(self) -> None:
        if self.schema_version != CONTRACT_VERSION:
            raise ValueError(f"unsupported contract version: {self.schema_version}")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.artifact_type,
                self.location,
                self.format,
                self.scanner,
                self.scanner_version,
            )
        ):
            raise ValueError(
                "artifact_type, location, format, scanner, and scanner_version must be non-empty"
            )
        if (
            self.location.startswith("/")
            or "\\" in self.location
            or any(part in {"", ".", ".."} for part in self.location.split("/"))
        ):
            raise ValueError("location must be a safe relative path")
        if (
            not isinstance(self.sha256, str)
            or len(self.sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.sha256)
        ):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        if self.database_provenance is not None:
            provenance = self.database_provenance
            if not isinstance(provenance, dict) or set(provenance) != {
                "schema_version",
                "built_at",
                "checksum",
            }:
                raise ValueError("database_provenance fields must be schema_version, built_at, and checksum")
            if not isinstance(provenance["schema_version"], str) or not provenance["schema_version"].strip():
                raise ValueError("database_provenance schema_version must be non-empty text")
            _parse_timestamp(provenance["built_at"], "database_provenance built_at")
            if provenance["checksum"] is not None and (
                not isinstance(provenance["checksum"], str) or not provenance["checksum"].strip()
            ):
                raise ValueError("database_provenance checksum must be non-empty text or None")
        if self.signature_identity is not None and (
            not isinstance(self.signature_identity, str) or not self.signature_identity.strip()
        ):
            raise ValueError("signature_identity must be non-empty text or None")
        if self.signature_verified is not None and not isinstance(self.signature_verified, bool):
            raise ValueError("signature_verified must be a boolean or None")
        if self.provenance_verified is not None and not isinstance(self.provenance_verified, bool):
            raise ValueError("provenance_verified must be a boolean or None")
        if self.signature_verified is True and self.signature_identity is None:
            raise ValueError("verified signature requires a signature identity")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
