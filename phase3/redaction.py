"""Strict allowlist redaction for the public Phase 3 snapshot contract."""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import UTC, datetime
from typing import Any

from auditor.history import HistoryError, _validate_report

PUBLIC_SCHEMA_VERSION = "1.0.0"
MAX_PUBLIC_FINDINGS = 2000
_STATUSES = {"PASS", "FAIL", "UNKNOWN", "ERROR"}
_GATES = {"NOT_CONFIGURED", "PASS", "FAIL"}
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_DRIFT_STATES = {"new", "persistent", "changed", "resolved", "unknown"}
_SERVICES = {"iam", "s3", "cloudtrail"}
_ACCOUNT_ID = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
_ARN = re.compile(r"\barn:(?:aws|aws-us-gov|aws-cn):[^\s\"'`,;]+", re.IGNORECASE)
_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:aws_)?(?:secret[_-]?access[_-]?key|access[_-]?key[_-]?id|api[_-]?key|"
    r"password|passwd|token|client[_-]?secret)\b\s*[:=]\s*[^\s,;]+"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}")
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_URL = re.compile(r"\b(?:https?|wss?)://\S+", re.IGNORECASE)
_HOST = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|cloud|internal|local|amazonaws)\b",
    re.IGNORECASE,
)
_PRINCIPAL = re.compile(r"\b(?:user|role|group|principal)\s*[:=]\s*[^\s,;]+", re.IGNORECASE)
_CONTROL_ID = re.compile(r"^[A-Z0-9][A-Z0-9._:-]{0,63}$")
_REGION = re.compile(r"^(?:aws-global|[a-z]{2,}(?:-[a-z0-9]+)+-[0-9]+)$")
_FINGERPRINT = re.compile(r"^[a-f0-9]{16}$")
_PRIVATE_NAME_KEY = re.compile(
    r"(?:account|arn|principal|resource|bucket|user|role|group|policy|trail|access.?key|identity|session|owner|email|ip|endpoint|name)",
    re.IGNORECASE,
)
_QUOTED_RESOURCE_NAME = re.compile(
    r"(?i)(\b(?:iam\s+)?(?:user|role|group|bucket|policy|trail|access key|key)\s+)(['\"`])"
    r"([A-Za-z0-9][A-Za-z0-9_.:/+=,@-]{2,})\2"
)
_GENERIC_PRIVATE_VALUES = {"user", "role", "group", "bucket", "policy", "trail", "aws", "s3", "iam", "cloudtrail", "root", "public", "private", "none", "unknown", "true", "false"}


class PublicSnapshotError(ValueError):
    """A report cannot safely cross the private-to-public boundary."""


def _contains_sensitive(value: str) -> bool:
    return any(
        pattern.search(value)
        for pattern in (
            _ACCOUNT_ID,
            _ARN,
            _ACCESS_KEY,
            _SECRET_ASSIGNMENT,
            _PRIVATE_KEY,
            _BEARER,
            _EMAIL,
            _IPV4,
            _URL,
            _HOST,
            _PRINCIPAL,
        )
    )


def _safe_text(
    value: Any,
    *,
    field: str,
    max_length: int = 2000,
    private_values: set[str] | None = None,
) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise PublicSnapshotError(f"public {field} is invalid")
    for private_value in sorted(private_values or (), key=len, reverse=True):
        if len(private_value) < 4:
            continue
        pattern = re.compile(
            rf"(?<![A-Za-z0-9]){re.escape(private_value)}(?![A-Za-z0-9])",
            re.IGNORECASE,
        )
        value = pattern.sub("[redacted]", value)
    value = _QUOTED_RESOURCE_NAME.sub(lambda match: f"{match.group(1)}[redacted]", value)
    if _contains_sensitive(value):
        raise PublicSnapshotError(f"public {field} contains a sensitive pattern")
    return value.strip()


def _private_values(finding: dict[str, Any]) -> set[str]:
    """Collect resource and identity values so prose cannot leak their names."""
    values: set[str] = set()
    resource = finding.get("resource_reference")
    if isinstance(resource, str):
        values.add(resource)
        values.update(
            part for part in re.split(r"[/:=]", resource)
            if len(part) >= 4 and part.lower() not in _GENERIC_PRIVATE_VALUES
        )

    account_ref = finding.get("account_ref")
    if isinstance(account_ref, dict) and isinstance(account_ref.get("id"), str):
        values.add(account_ref["id"])

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key))
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif isinstance(value, str) and _PRIVATE_NAME_KEY.search(key):
            if len(value) >= 4 and value.lower() not in _GENERIC_PRIVATE_VALUES:
                values.add(value)

    visit(finding.get("evidence", {}))
    return values


def _safe_datetime(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise PublicSnapshotError(f"public {field} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PublicSnapshotError(f"public {field} timestamp is invalid") from None
    if parsed.tzinfo is None:
        raise PublicSnapshotError(f"public {field} timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat()


def _pseudonym(key: bytes, namespace: str, value: str) -> str:
    digest = hmac.new(key, f"phase3:{namespace}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:24]


def _public_finding(finding: dict[str, Any], *, key: bytes) -> dict[str, Any]:
    fingerprint = finding.get("fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise PublicSnapshotError("private finding fingerprint is invalid")
    control_id = finding.get("control_id")
    if not isinstance(control_id, str) or not _CONTROL_ID.fullmatch(control_id):
        raise PublicSnapshotError("public control identifier is invalid")
    severity = finding.get("severity")
    service = finding.get("service")
    region = finding.get("region")
    if severity not in _SEVERITIES or service not in _SERVICES:
        raise PublicSnapshotError("public finding classification is invalid")
    if not isinstance(region, str) or not _REGION.fullmatch(region):
        raise PublicSnapshotError("public finding region is invalid")
    lifecycle = finding.get("lifecycle_state", "open")
    lifecycle = _safe_text(lifecycle, field="finding lifecycle", max_length=32).lower()
    if lifecycle not in {"open", "resolved", "suppressed", "accepted", "unknown"}:
        lifecycle = "unknown"
    raw_resource = finding.get("resource_reference")
    if raw_resource is not None and (not isinstance(raw_resource, str) or len(raw_resource) > 1024):
        raise PublicSnapshotError("private finding resource reference is invalid")
    resource_token = _pseudonym(key, "resource", raw_resource or fingerprint)
    private_values = _private_values(finding)
    references = []
    raw_references = finding.get("references", [])
    if not isinstance(raw_references, list):
        raise PublicSnapshotError("public references are invalid")
    for reference in raw_references[:10]:
        if not isinstance(reference, dict) or reference.get("type") != "compliance":
            continue
        framework = _safe_text(reference.get("framework"), field="reference framework", max_length=120, private_values=private_values)
        ref_id = _safe_text(reference.get("id"), field="reference ID", max_length=64, private_values=private_values)
        title_value = reference.get("title")
        safe_reference = {
            "framework": framework,
            "id": ref_id,
        }
        if isinstance(title_value, str) and title_value.strip():
            safe_reference["title"] = _safe_text(title_value, field="reference title", max_length=200, private_values=private_values)
        references.append(safe_reference)
    detected = finding.get("detected_at")
    return {
        "id": _pseudonym(key, "finding", fingerprint),
        "control_id": control_id,
        "severity": severity,
        "title": _safe_text(finding.get("title"), field="finding title", private_values=private_values),
        "description": _safe_text(finding.get("description"), field="finding description", private_values=private_values),
        "remediation": _safe_text(finding.get("remediation"), field="finding remediation", private_values=private_values),
        "lifecycle_state": lifecycle,
        "service": service,
        "region": region,
        "resource_ref": f"resource-{resource_token}",
        "detected_at": _safe_datetime(detected, field="finding detected-at") if detected else None,
        "references": references,
    }


def redact_snapshot(report: Any, hmac_key: bytes) -> dict[str, Any]:
    """Build a schema-versioned allowlist snapshot without raw report data."""
    if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
        raise PublicSnapshotError("public pseudonym HMAC key must contain at least 32 bytes")
    try:
        run, coverage, findings = _validate_report(report)
    except (AttributeError, HistoryError, KeyError, TypeError, ValueError):
        raise PublicSnapshotError("private scan report does not match the fleet contract") from None
    if len(findings) > MAX_PUBLIC_FINDINGS:
        raise PublicSnapshotError("private scan report has too many findings for public release")
    status = run.get("status")
    gate_status = run.get("gate_status", report.get("summary", {}).get("gate_status", "NOT_CONFIGURED"))
    if status not in _STATUSES or gate_status not in _GATES:
        raise PublicSnapshotError("private scan status is invalid")
    completed_at = _safe_datetime(run.get("completed_at"), field="scan completed-at")
    started_at = _safe_datetime(run.get("started_at", run.get("completed_at")), field="scan started-at")
    public_findings = [_public_finding(item, key=hmac_key) for item in findings]
    severity_counts = {level: 0 for level in sorted(_SEVERITIES)}
    drift_counts = {state: 0 for state in sorted(_DRIFT_STATES)}
    for finding in public_findings:
        severity_counts[finding["severity"]] += 1

    transitions = report.get("drift", [])
    if not isinstance(transitions, list) or len(transitions) > MAX_PUBLIC_FINDINGS * 2:
        raise PublicSnapshotError("private drift history is invalid")
    public_drift = []
    seen: set[tuple[str, str]] = set()
    for transition in transitions:
        if not isinstance(transition, dict) or transition.get("state") not in _DRIFT_STATES:
            raise PublicSnapshotError("private drift history contains an invalid state")
        private_finding = transition.get("finding")
        if not isinstance(private_finding, dict):
            raise PublicSnapshotError("private drift history contains an invalid finding")
        public_finding = _public_finding(private_finding, key=hmac_key)
        state = transition["state"]
        identity = (public_finding["id"], state)
        if identity in seen:
            continue
        seen.add(identity)
        drift_counts[state] += 1
        public_drift.append({"finding_id": public_finding["id"], "state": state, "finding": public_finding})

    regions = run.get("regions", [])
    if not isinstance(regions, list) or any(not isinstance(region, str) or not _REGION.fullmatch(region) for region in regions):
        raise PublicSnapshotError("public scan regions are invalid")
    services = sorted({entry["service"] for entry in coverage})
    snapshot = {
        "schema_version": PUBLIC_SCHEMA_VERSION,
        "snapshot_id": _pseudonym(hmac_key, "run", run["run_id"]),
        "generated_at": completed_at,
        "scan": {
            "status": status,
            "gate_status": gate_status,
            "started_at": started_at,
            "completed_at": completed_at,
            "regions": sorted(set(regions)),
            "services": services,
            "complete_scopes": sum(1 for item in coverage if item["complete"]),
            "incomplete_scopes": sum(1 for item in coverage if not item["complete"]),
            "scanner_version": _safe_text(
                (run.get("scanner_versions") or {}).get("account-access-auditor", "unknown"),
                field="scanner version",
                max_length=64,
            ),
        },
        "summary": {
            "total_findings": len(public_findings),
            "severity_counts": severity_counts,
            "drift_counts": drift_counts,
        },
        "findings": public_findings,
        "drift": public_drift,
    }
    validate_public_snapshot(snapshot)
    return snapshot


def validate_public_snapshot(snapshot: Any) -> None:
    """Validate the independent public schema and re-scan every output string."""
    root_fields = {"schema_version", "snapshot_id", "generated_at", "scan", "summary", "findings", "drift"}
    if not isinstance(snapshot, dict) or set(snapshot) != root_fields:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    if snapshot.get("schema_version") != PUBLIC_SCHEMA_VERSION:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    if not isinstance(snapshot.get("snapshot_id"), str) or not re.fullmatch(r"[a-f0-9]{24}", snapshot["snapshot_id"]):
        raise PublicSnapshotError("public snapshot does not match schema v1")
    _safe_datetime(snapshot.get("generated_at"), field="generated-at")
    scan_fields = {
        "status", "gate_status", "started_at", "completed_at", "regions", "services",
        "complete_scopes", "incomplete_scopes", "scanner_version",
    }
    scan = snapshot.get("scan")
    summary = snapshot.get("summary")
    if not isinstance(scan, dict) or set(scan) != scan_fields:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    if scan.get("status") not in _STATUSES or scan.get("gate_status") not in _GATES:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    _safe_datetime(scan.get("started_at"), field="scan started-at")
    _safe_datetime(scan.get("completed_at"), field="scan completed-at")
    if not isinstance(scan.get("regions"), list) or any(
        not isinstance(region, str) or not _REGION.fullmatch(region) for region in scan["regions"]
    ):
        raise PublicSnapshotError("public snapshot does not match schema v1")
    if not isinstance(scan.get("services"), list) or any(service not in _SERVICES for service in scan["services"]):
        raise PublicSnapshotError("public snapshot does not match schema v1")
    for key in ("complete_scopes", "incomplete_scopes"):
        if not isinstance(scan.get(key), int) or isinstance(scan[key], bool) or scan[key] < 0:
            raise PublicSnapshotError("public snapshot does not match schema v1")
    _safe_text(scan.get("scanner_version"), field="scanner version", max_length=64)
    if not isinstance(summary, dict) or set(summary) != {"total_findings", "severity_counts", "drift_counts"}:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    findings = snapshot.get("findings")
    drift = snapshot.get("drift")
    if not isinstance(findings, list) or len(findings) > MAX_PUBLIC_FINDINGS or not isinstance(drift, list):
        raise PublicSnapshotError("public snapshot does not match schema v1")
    if summary.get("total_findings") != len(findings):
        raise PublicSnapshotError("public snapshot does not match schema v1")
    severity_counts = summary.get("severity_counts")
    drift_counts = summary.get("drift_counts")
    if not isinstance(severity_counts, dict) or set(severity_counts) != _SEVERITIES:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    if not isinstance(drift_counts, dict) or set(drift_counts) != _DRIFT_STATES:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    if any(not isinstance(count, int) or isinstance(count, bool) or count < 0 for count in severity_counts.values()):
        raise PublicSnapshotError("public snapshot does not match schema v1")
    if any(not isinstance(count, int) or isinstance(count, bool) or count < 0 for count in drift_counts.values()):
        raise PublicSnapshotError("public snapshot does not match schema v1")
    finding_fields = {
        "id", "control_id", "severity", "title", "description", "remediation", "lifecycle_state",
        "service", "region", "resource_ref", "detected_at", "references",
    }

    all_findings = list(findings)
    for transition in drift:
        if not isinstance(transition, dict) or set(transition) != {"finding_id", "state", "finding"}:
            raise PublicSnapshotError("public snapshot does not match schema v1")
        if transition.get("state") not in _DRIFT_STATES or not isinstance(transition.get("finding"), dict):
            raise PublicSnapshotError("public snapshot does not match schema v1")
        if transition.get("finding_id") != transition["finding"].get("id"):
            raise PublicSnapshotError("public snapshot does not match schema v1")
        all_findings.append(transition["finding"])

    for finding in all_findings:
        if not isinstance(finding, dict) or set(finding) != finding_fields:
            raise PublicSnapshotError("public snapshot does not match schema v1")
        if not re.fullmatch(r"[a-f0-9]{24}", str(finding.get("id", ""))):
            raise PublicSnapshotError("public snapshot does not match schema v1")
        if finding.get("severity") not in _SEVERITIES or finding.get("service") not in _SERVICES:
            raise PublicSnapshotError("public snapshot does not match schema v1")
        if not isinstance(finding.get("region"), str) or not _REGION.fullmatch(finding["region"]):
            raise PublicSnapshotError("public snapshot does not match schema v1")
        if not isinstance(finding.get("control_id"), str) or not _CONTROL_ID.fullmatch(finding["control_id"]):
            raise PublicSnapshotError("public snapshot does not match schema v1")
        if not isinstance(finding.get("resource_ref"), str) or not re.fullmatch(
            r"resource-[a-f0-9]{24}", finding["resource_ref"]
        ):
            raise PublicSnapshotError("public snapshot does not match schema v1")
        for text_field in ("title", "description", "remediation"):
            _safe_text(finding.get(text_field), field=text_field)
        if finding["detected_at"] is not None:
            _safe_datetime(finding["detected_at"], field="finding detected-at")
        if not isinstance(finding.get("references"), list) or len(finding["references"]) > 10:
            raise PublicSnapshotError("public snapshot does not match schema v1")
        for reference in finding["references"]:
            if not isinstance(reference, dict) or set(reference) - {"framework", "id", "title"} or not {"framework", "id"}.issubset(reference):
                raise PublicSnapshotError("public snapshot does not match schema v1")
            for field, value in reference.items():
                _safe_text(value, field=f"reference {field}", max_length=200)
    expected_severity_counts = {severity: 0 for severity in _SEVERITIES}
    for finding in findings:
        expected_severity_counts[finding["severity"]] += 1
    if severity_counts != expected_severity_counts:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    expected_drift_counts = {state: 0 for state in _DRIFT_STATES}
    for transition in drift:
        expected_drift_counts[transition["state"]] += 1
    if drift_counts != expected_drift_counts:
        raise PublicSnapshotError("public snapshot does not match schema v1")
    serialized_strings = _walk_strings(snapshot)
    if any(_contains_sensitive(value) for value in serialized_strings):
        raise PublicSnapshotError("public snapshot contains a sensitive pattern")


def _walk_strings(value: Any):
    """Scan public prose while trusting only separately schema-checked pseudonym fields."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            if (
                key in {"snapshot_id", "finding_id", "id"}
                and isinstance(item, str)
                and re.fullmatch(r"[a-f0-9]{24}", item)
            ) or (
                key == "resource_ref"
                and isinstance(item, str)
                and re.fullmatch(r"resource-[a-f0-9]{24}", item)
            ):
                # Valid HMAC pseudonyms are hexadecimal and can coincidentally
                # contain twelve decimal digits without being AWS account IDs.
                continue
            yield from _walk_strings(item)
