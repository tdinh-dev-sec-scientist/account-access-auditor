"""CloudTrail rules.

  CT-001  No trail configured                     HIGH
  CT-002  No multi-region trail                    MEDIUM
  CT-003  Log file validation disabled             MEDIUM
  CT-004  Trail not logging / delivery failing     HIGH

CT-001/CT-002 are account-level: they describe the trail estate as a whole.
CT-003/CT-004 are per-trail. The split matters because remediation differs --
one is "create a trail", the other is "fix this trail".
"""

from __future__ import annotations

from typing import Any

from ..models.finding import Finding

SERVICE = "CloudTrail"
ACCOUNT_RESOURCE = "aws-account"


def evaluate(data: dict[str, Any], config: dict[str, Any], run_id: str | None = None) -> list[Finding]:
    settings = (config or {}).get("cloudtrail", {})

    # If DescribeTrails could not be read, absence of data is not evidence of
    # absence of a trail. Emit nothing; the collection error stands on its own.
    if not data.get("trails_readable", True):
        return []

    trails = data.get("trails", []) or []
    findings: list[Finding] = []

    if not trails:
        if settings.get("require_trail", True):
            findings.append(
                Finding.build(
                    "CT-001",
                    resource=ACCOUNT_RESOURCE,
                    description=(
                        "DescribeTrails returned no trails for this account and region. "
                        "Management-event history is therefore not being retained in a "
                        "durable, tamper-evident form; the console Event history view keeps "
                        "only 90 days and is not usable as incident evidence."
                    ),
                    evidence={"trail_count": 0, "region": data.get("region")},
                    run_id=run_id,
                )
            )
        return findings

    findings.extend(_multi_region_rule(trails, settings, data, run_id))

    for trail in trails:
        findings.extend(_log_validation_rule(trail, settings, run_id))
        findings.extend(_logging_status_rule(trail, settings, run_id))

    return findings


def _multi_region_rule(trails, settings, data, run_id) -> list[Finding]:
    if not settings.get("require_multi_region", True):
        return []
    if any(trail.get("is_multi_region") for trail in trails):
        return []

    return [
        Finding.build(
            "CT-002",
            resource=ACCOUNT_RESOURCE,
            description=(
                f"All {len(trails)} configured trail(s) are single-region, so activity in "
                "any other region is not captured. Regions an organisation does not use "
                "are exactly where unmonitored activity tends to occur."
            ),
            evidence={
                "trail_count": len(trails),
                "region": data.get("region"),
                "trails": [
                    {
                        "name": trail.get("name"),
                        "home_region": trail.get("home_region"),
                        "is_multi_region": trail.get("is_multi_region"),
                    }
                    for trail in trails
                ],
            },
            run_id=run_id,
        )
    ]


def _log_validation_rule(trail, settings, run_id) -> list[Finding]:
    if not settings.get("require_log_validation", True):
        return []
    if trail.get("log_file_validation_enabled"):
        return []

    name = trail.get("name")
    return [
        Finding.build(
            "CT-003",
            resource=name,
            description=(
                f"Log file validation is disabled for trail '{name}', so CloudTrail is not "
                "producing the signed digest files needed to prove that delivered logs have "
                "not been modified or deleted."
            ),
            evidence={
                "trail": name,
                "trail_arn": trail.get("arn"),
                "log_file_validation_enabled": False,
                "s3_bucket_name": trail.get("s3_bucket_name"),
            },
            run_id=run_id,
        )
    ]


def _logging_status_rule(trail, settings, run_id) -> list[Finding]:
    if not settings.get("check_logging_status", True):
        return []

    name = trail.get("name")
    is_logging = trail.get("is_logging")
    delivery_error = trail.get("latest_delivery_error")

    # None means GetTrailStatus was denied or unavailable: unknown, not stopped.
    if is_logging is False:
        return [
            Finding.build(
                "CT-004",
                title="CloudTrail trail exists but is not currently logging",
                resource=name,
                description=(
                    f"Trail '{name}' is configured but GetTrailStatus reports that logging is "
                    "stopped. It appears correctly configured in any configuration-only "
                    "review while recording nothing."
                ),
                evidence={
                    "trail": name,
                    "trail_arn": trail.get("arn"),
                    "is_logging": False,
                    "latest_delivery_time": trail.get("latest_delivery_time"),
                },
                run_id=run_id,
            )
        ]

    if is_logging and delivery_error:
        return [
            Finding.build(
                "CT-004",
                title="CloudTrail trail is logging but reports a delivery error",
                resource=name,
                description=(
                    f"Trail '{name}' is enabled but the most recent delivery attempt reported "
                    f"an error ({delivery_error}), so events may not be reaching the "
                    "destination bucket."
                ),
                evidence={
                    "trail": name,
                    "trail_arn": trail.get("arn"),
                    "is_logging": True,
                    "latest_delivery_error": delivery_error,
                    "latest_delivery_time": trail.get("latest_delivery_time"),
                    "s3_bucket_name": trail.get("s3_bucket_name"),
                },
                run_id=run_id,
            )
        ]

    return []
