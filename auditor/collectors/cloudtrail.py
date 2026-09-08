"""CloudTrail collector: trail configuration AND live logging status.

These are two different questions. A trail can exist and be misconfigured, and a
correctly configured trail can be stopped or failing delivery, so the collector
makes both calls and keeps the answers in separate fields.
"""

from __future__ import annotations

import logging
from typing import Any

from ..normalize import cloudtrail as normalize
from ._common import AWS_EXCEPTIONS, OK, record_error, safe_call

log = logging.getLogger(__name__)

SERVICE = "CloudTrail"

REQUIRED_PERMISSIONS = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]


def collect(session, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return normalized CloudTrail state.

    ``trails_readable`` is the important field: when DescribeTrails fails, the
    rules must not conclude "no trail exists". Absence of data is not evidence
    of absence of a trail.
    """
    client = session.client("cloudtrail")
    errors: list[dict[str, Any]] = []
    trails: list[dict[str, Any]] = []
    region = getattr(session, "region_name", None)

    log.info("Starting CloudTrail collection")
    try:
        # Shadow trails are replicas of multi-region trails from other regions;
        # including them would double-count one trail as several.
        response = client.describe_trails(includeShadowTrails=False)
    except AWS_EXCEPTIONS as exc:
        record_error(
            errors,
            SERVICE,
            "cloudtrail:DescribeTrails",
            exc,
            required_permissions=["cloudtrail:DescribeTrails"],
        )
        return {"trails": [], "errors": errors, "trails_readable": False, "region": region}

    for raw in response.get("trailList", []):
        trails.append(_collect_trail(client, raw, errors))

    log.info("CloudTrail collection complete: %d trails", len(trails))
    return {"trails": trails, "errors": errors, "trails_readable": True, "region": region}


def _collect_trail(client, raw: dict[str, Any], errors) -> dict[str, Any]:
    trail = normalize.trail(raw)
    identifier = trail["arn"] or trail["name"]

    status, outcome = safe_call(
        errors,
        trail["collection_errors"],
        SERVICE,
        "cloudtrail:GetTrailStatus",
        lambda: client.get_trail_status(Name=identifier),
        trail["name"],
        ["cloudtrail:GetTrailStatus"],
    )
    if outcome == OK:
        normalize.apply_status(trail, status)
    return trail
