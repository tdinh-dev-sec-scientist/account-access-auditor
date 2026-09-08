"""Ticket reporter.

Turns each finding into a body an analyst can paste into a service desk without
rewriting it. The fields are the ones a ticket triager asks for: what is wrong,
how urgent, which resource, what proves it, what to do, and which control it
maps to.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ..severity import Severity

log = logging.getLogger(__name__)

CATEGORY_BY_SERVICE = {
    "IAM": "Access Management",
    "S3": "Data Storage Configuration",
    "CloudTrail": "Audit Logging",
}

SEPARATOR = "-" * 68


def ticket_id(finding: dict[str, Any], sequence: int, stamp: str | None = None) -> str:
    """Stable within a run, unique across findings, greppable in a tracker."""
    stamp = stamp or (finding.get("detected_at") or "")[:10].replace("-", "") or "00000000"
    return f"AUTO-{finding['rule_id']}-{stamp}-{sequence:03d}"


def _priority(finding: dict[str, Any]) -> str:
    try:
        return Severity.from_string(finding["severity"]).label
    except (KeyError, ValueError):  # pragma: no cover - defensive
        return str(finding.get("severity", "Unknown"))


def _evidence_lines(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    if not evidence:
        return "  (none recorded)"
    return "\n".join(f"  {key}: {value}" for key, value in evidence.items())


def _compliance_line(finding: dict[str, Any]) -> str:
    compliance = finding.get("compliance") or {}
    control = compliance.get("control_id")
    if not control:
        return "No mapped control in the referenced benchmark version."
    return f"{compliance.get('framework')} control {control} - {compliance.get('control_title')}"


def format_ticket(finding: dict[str, Any], sequence: int, account_id: str | None = None) -> str:
    sections = [
        f"Ticket ID: {ticket_id(finding, sequence)}",
        "",
        f"Category:\n{CATEGORY_BY_SERVICE.get(finding['service'], finding['service'])}",
        "",
        f"Priority:\n{_priority(finding)}",
        "",
        f"AWS Account:\n{account_id or 'unknown'}",
        "",
        f"Affected Resource:\n{finding['resource']} ({finding.get('resource_type', 'unknown')})",
        "",
        f"Issue:\n{finding['title']}",
        "",
        f"Detail:\n{finding['description']}",
        "",
        f"Why It Matters:\n{finding.get('rationale', '(not recorded)')}",
        "",
        f"Evidence:\n{_evidence_lines(finding)}",
        "",
        f"Recommended Action:\n{finding['remediation']}",
        "",
        f"Compliance Reference:\n{_compliance_line(finding)}",
        "",
        f"Detected At:\n{finding['detected_at']}",
        "",
        f"Detection Rule:\n{finding['rule_id']}  (fingerprint {finding.get('fingerprint', 'n/a')})",
        "",
        f"Status:\n{finding['status']}",
        "",
        SEPARATOR,
        "",
    ]
    return "\n".join(sections)


def render(report: dict[str, Any]) -> str:
    account_id = report.get("metadata", {}).get("account_id")
    blocks: list[str] = [
        format_ticket(finding, index, account_id)
        for index, finding in enumerate(report.get("findings", []), start=1)
    ]
    if not blocks:
        return "No findings at or above the selected severity threshold.\n"
    return "\n".join(blocks)


def write(report: dict[str, Any], path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(report))
    log.info("Wrote ticket export: %s", path)
    return path
