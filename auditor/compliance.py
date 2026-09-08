"""CIS AWS Foundations Benchmark mapping.

The mapping lives in ``compliance/cis_mapping.json`` so it can be reviewed and
diffed as data rather than buried in Python. This module loads it, validates its
shape, and exposes it to the rule registry and reporters.

Counting rule: only entries with ``status == "mapped"`` count towards the
"CIS-mapped rules" metric. Entries marked ``partial`` are documented because
they share a control's rationale, but their audit condition is not equivalent,
and counting them would overstate coverage.
"""

from __future__ import annotations

import functools
import json
import os
from typing import Any

MAPPING_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "compliance",
    "cis_mapping.json",
)

MAPPED = "mapped"
PARTIAL = "partial"
UNMAPPED = "unmapped"
VALID_STATUSES = {MAPPED, PARTIAL, UNMAPPED}

_REQUIRED_KEYS = {"rule_id", "finding", "control_id", "control_title", "status", "rationale"}


class ComplianceMappingError(RuntimeError):
    """The mapping file is missing or structurally invalid."""


@functools.cache
def load_mapping(path: str | None = None) -> dict[str, Any]:
    """Load and validate the CIS mapping document."""
    target = path or MAPPING_PATH
    try:
        with open(target, encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError as exc:
        raise ComplianceMappingError(f"CIS mapping file not found: {target}") from exc
    except ValueError as exc:
        raise ComplianceMappingError(f"CIS mapping file is not valid JSON: {target}") from exc

    if not isinstance(document, dict) or "rules" not in document:
        raise ComplianceMappingError("CIS mapping file must be an object with a 'rules' array")

    seen = set()
    for entry in document["rules"]:
        missing = _REQUIRED_KEYS - set(entry)
        if missing:
            raise ComplianceMappingError(
                f"CIS mapping entry {entry.get('rule_id')} is missing keys: {sorted(missing)}"
            )
        if entry["status"] not in VALID_STATUSES:
            raise ComplianceMappingError(
                f"CIS mapping entry {entry['rule_id']} has unknown status '{entry['status']}'"
            )
        if entry["status"] == MAPPED and not entry["control_id"]:
            raise ComplianceMappingError(
                f"CIS mapping entry {entry['rule_id']} is marked mapped but has no control_id"
            )
        if entry["rule_id"] in seen:
            raise ComplianceMappingError(f"Duplicate CIS mapping entry for {entry['rule_id']}")
        seen.add(entry["rule_id"])

    return document


def benchmark_version(path: str | None = None) -> str:
    return load_mapping(path)["benchmark"]["version"]


def entries(path: str | None = None) -> list[dict[str, Any]]:
    return list(load_mapping(path)["rules"])


def entry_for(rule_id: str, path: str | None = None) -> dict[str, Any] | None:
    for item in entries(path):
        if item["rule_id"] == rule_id:
            return item
    return None


def compliance_block(rule_id: str, path: str | None = None) -> dict[str, Any]:
    """The compliance sub-document embedded in every emitted finding."""
    document = load_mapping(path)
    item = entry_for(rule_id, path)
    if item is None:
        return {"framework": None, "control_id": None, "control_title": None, "status": UNMAPPED}
    return {
        "framework": f"{document['benchmark']['name']} v{document['benchmark']['version']}",
        "control_id": item["control_id"],
        "control_title": item["control_title"],
        "status": item["status"],
    }


def mapped_rule_ids(path: str | None = None) -> list[str]:
    """Rule IDs counted by the 'CIS-mapped rules' metric."""
    return [item["rule_id"] for item in entries(path) if item["status"] == MAPPED]


def mapped_count(path: str | None = None) -> int:
    return len(mapped_rule_ids(path))


def status_counts(path: str | None = None) -> dict[str, int]:
    result = dict.fromkeys(sorted(VALID_STATUSES), 0)
    for item in entries(path):
        result[item["status"]] += 1
    return result
