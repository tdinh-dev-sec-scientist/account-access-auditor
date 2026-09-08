"""JSON reporter: the machine-readable output other tools consume.

Serialisation is deterministic apart from the timestamps in the report itself,
so two scans of an unchanged account produce a diffable file rather than a
reshuffled one.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

log = logging.getLogger(__name__)


def render(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False, default=str) + "\n"


def write(report: dict[str, Any], path: str) -> str:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(report))
    log.info("Wrote JSON report: %s", path)
    return path
