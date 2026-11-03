"""SARIF 2.1.0 export for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _safe_uri(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return quote(path.as_posix(), safe="/-._~")


def _level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Convert a normalized scan report to a SARIF 2.1.0 document."""
    findings = report.get("findings", [])
    errors = report.get("collection_errors", [])
    metadata = report.get("metadata", {})
    scan_run = report.get("contract", {}).get("scan_run", {})

    rule_ids = sorted(
        {finding.get("control_id") for finding in findings if isinstance(finding.get("control_id"), str)}
    )
    rule_indices = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    title_by_id = {
        finding["control_id"]: str(finding.get("title") or finding["control_id"])
        for finding in findings
        if isinstance(finding.get("control_id"), str)
    }
    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": title_by_id[rule_id][:1024]},
            "help": {
                "text": next(
                    str(finding.get("remediation") or finding.get("description") or "Review this finding.")[
                        :4000
                    ]
                    for finding in findings
                    if finding.get("control_id") == rule_id
                )
            },
        }
        for rule_id in rule_ids
    ]

    results = []
    for finding in findings:
        rule_id = finding.get("control_id")
        if not isinstance(rule_id, str) or rule_id not in rule_indices:
            continue
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_indices[rule_id],
            "level": _level(str(finding.get("severity", "MEDIUM"))),
            "message": {"text": str(finding.get("description") or finding.get("title") or rule_id)[:4000]},
            "properties": {
                "severity": finding.get("severity"),
                "scanner": finding.get("scanner"),
                "scanner_rule_id": finding.get("scanner_rule_id"),
                "gate": bool(finding.get("gate", False)),
                "exceptions": finding.get("exceptions", []),
            },
        }
        fingerprint = finding.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            result["partialFingerprints"] = {"account-access-auditor/v1": fingerprint}
        location = finding.get("source_location")
        if isinstance(location, dict):
            uri = _safe_uri(location.get("file"))
            if uri:
                physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
                line = location.get("line")
                if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                    physical["region"] = {"startLine": line}
                result["locations"] = [{"physicalLocation": physical}]
        results.append(result)

    notifications = []
    for error in errors:
        operation = str(error.get("operation") or "scan")
        message = str(error.get("message") or "scan failed")
        notifications.append(
            {
                "level": "error",
                "message": {"text": f"{operation}: {message}"[:4000]},
            }
        )

    driver: dict[str, Any] = {"name": "AWS Account & Access Configuration Auditor", "rules": rules}
    version = metadata.get("tool_version")
    if isinstance(version, str) and version:
        driver["version"] = version
    invocation: dict[str, Any] = {
        "executionSuccessful": scan_run.get("status") not in {"ERROR", "UNKNOWN"},
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": driver},
                "invocations": [invocation],
                "results": results,
            }
        ],
    }
