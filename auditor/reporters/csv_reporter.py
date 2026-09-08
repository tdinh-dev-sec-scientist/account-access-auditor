"""CSV reporter: one row per finding, for spreadsheets and ticket imports.

Nested fields (evidence, compliance) are flattened rather than dropped: a CSV
that loses the evidence is a CSV nobody can act on. Evidence is serialised as
compact JSON in a single column, and the compliance block is split into the two
columns a reviewer actually filters on.
"""

from __future__ import annotations

import csv
import json
import logging
import os
from typing import Any

log = logging.getLogger(__name__)

COLUMNS = [
    "rule_id",
    "severity",
    "service",
    "resource_type",
    "resource",
    "title",
    "description",
    "remediation",
    "compliance_framework",
    "compliance_control",
    "compliance_status",
    "evidence",
    "detected_at",
    "run_id",
    "status",
    "fingerprint",
]


def rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        compliance = finding.get("compliance") or {}
        row = {column: finding.get(column, "") for column in COLUMNS}
        row["compliance_framework"] = compliance.get("framework") or ""
        row["compliance_control"] = compliance.get("control_id") or ""
        row["compliance_status"] = compliance.get("status") or ""
        row["evidence"] = json.dumps(finding.get("evidence", {}), sort_keys=True, default=str)
        result.append(row)
    return result


def write(report: dict[str, Any], path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows(report))
    log.info("Wrote CSV report: %s", path)
    return path
