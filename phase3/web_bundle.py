"""Build safe, fixture-only fallback profiles for the Phase 3 static console."""

from __future__ import annotations

from typing import Any

from .redaction import redact_snapshot


_SERVICE_NAMES = {"iam": "IAM", "s3": "S3", "cloudtrail": "CloudTrail"}


def safe_fixture_profile(report: Any, *, key: str, label: str, pseudonym_key: bytes) -> dict[str, Any]:
    """Convert a Phase 2 benchmark report through the Phase 3 public allowlist."""
    if not isinstance(report, dict) or not isinstance(report.get("metadata"), dict):
        raise ValueError("fixture report is invalid")
    metadata = report["metadata"]
    account_id = metadata.get("account_id")
    region = metadata.get("region")
    run = (report.get("contract") or {}).get("scan_run")
    legacy_findings = report.get("findings")
    if (
        not isinstance(account_id, str)
        or len(account_id) != 12
        or not account_id.isascii()
        or not account_id.isdigit()
        or not isinstance(region, str)
        or not isinstance(run, dict)
        or not isinstance(legacy_findings, list)
    ):
        raise ValueError("fixture report is invalid")

    coverage = []
    for service_name in metadata.get("services_scanned", []):
        service = service_name.lower()
        if service not in _SERVICE_NAMES:
            raise ValueError("fixture contains an unsupported service")
        coverage.append({
            "account_id": account_id,
            "service": service,
            "region": region,
            "complete": not bool(report.get("collection_errors")),
        })

    contract_findings = []
    for finding in legacy_findings:
        if not isinstance(finding, dict):
            raise ValueError("fixture finding is invalid")
        service_name = finding.get("service")
        service = service_name.lower() if isinstance(service_name, str) else ""
        compliance = finding.get("compliance") or {}
        control_id = compliance.get("control_id") or finding.get("rule_id")
        framework = compliance.get("framework")
        reference_id = compliance.get("control_id")
        references = []
        if isinstance(framework, str) and isinstance(reference_id, str):
            references.append({
                "type": "compliance",
                "framework": framework,
                "id": reference_id,
                **({"title": compliance["control_title"]} if isinstance(compliance.get("control_title"), str) else {}),
            })
        contract_findings.append({
            "fingerprint": finding.get("fingerprint"),
            "control_id": control_id,
            "scanner_rule_id": finding.get("rule_id"),
            "source_type": "aws",
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "description": finding.get("description"),
            "evidence": {},
            "remediation": finding.get("remediation"),
            "references": references,
            "lifecycle_state": str(finding.get("status") or "open").lower(),
            "detected_at": finding.get("detected_at") or run.get("completed_at"),
            "account_ref": {"provider": "aws", "id": account_id},
            "service": service,
            "region": region,
            "resource_reference": finding.get("resource"),
        })

    sanitized_input = {
        "metadata": {
            "scan_source": "aws-fleet",
            "scan_coverage": coverage,
        },
        "summary": {"gate_status": run.get("gate_status", "NOT_CONFIGURED")},
        "contract": {"scan_run": run, "findings": contract_findings},
        "drift": [],
    }
    snapshot = redact_snapshot(sanitized_input, pseudonym_key)
    public_findings = snapshot["findings"]
    return {
        "key": key,
        "label": label,
        "environment": "Saved Moto fixture · not a live AWS account",
        "generatedAt": snapshot["generated_at"],
        "region": ", ".join(snapshot["scan"]["regions"]) or "Not recorded",
        "accountIdSuffix": "",
        "readOnly": True,
        "servicesScanned": snapshot["scan"]["services"],
        "resourcesScanned": {},
        "findingCount": len(public_findings),
        "openFindingCount": sum(item["lifecycle_state"] == "open" for item in public_findings),
        "severityCounts": snapshot["summary"]["severity_counts"],
        "collectionErrorCount": snapshot["scan"]["incomplete_scopes"],
        "run": {
            "runId": snapshot["snapshot_id"],
            "scanSource": "Saved Moto fixture",
            "startedAt": snapshot["scan"]["started_at"],
            "completedAt": snapshot["scan"]["completed_at"],
            "executionStatus": snapshot["scan"]["status"],
            "gateStatus": snapshot["scan"]["gate_status"],
            "exitCode": None,
            "findingCount": len(public_findings),
            "collectionErrorCount": snapshot["scan"]["incomplete_scopes"],
            "durationSeconds": None,
            "apiCallCount": None,
            "scannerVersions": {"account-access-auditor": snapshot["scan"]["scanner_version"]},
            "policyPackVersion": None,
        },
        "findings": [
            {
                "severity": item["severity"],
                "title": item["title"],
                "ruleId": item["control_id"],
                "service": item["service"],
                "resource": item["resource_ref"],
                "resourceType": item["service"],
                "status": item["lifecycle_state"].upper(),
                "controlId": item["control_id"],
                "controlTitle": item["control_id"],
                "description": item["description"],
                "rationale": item["description"],
                "remediation": item["remediation"],
                "evidence": {},
                "fingerprint": item["id"],
                "detectedAt": item["detected_at"] or "",
                "publicId": item["id"],
            }
            for item in public_findings
        ],
        "drift": [],
    }
