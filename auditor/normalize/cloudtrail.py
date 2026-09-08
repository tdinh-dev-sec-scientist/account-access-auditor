"""Normalize raw CloudTrail responses into the internal model."""

from __future__ import annotations

from typing import Any

from ..utils.dates import isoformat


def trail(raw: dict[str, Any]) -> dict[str, Any]:
    """Configuration state from DescribeTrails.

    Operational state (``is_logging`` and the delivery fields) stays None until
    ``apply_status`` merges in GetTrailStatus, because a trail that exists is
    not necessarily a trail that runs.
    """
    return {
        "name": raw.get("Name"),
        "arn": raw.get("TrailARN"),
        "home_region": raw.get("HomeRegion"),
        "is_multi_region": bool(raw.get("IsMultiRegionTrail", False)),
        "is_organization_trail": bool(raw.get("IsOrganizationTrail", False)),
        "include_global_service_events": raw.get("IncludeGlobalServiceEvents"),
        "log_file_validation_enabled": bool(raw.get("LogFileValidationEnabled", False)),
        "s3_bucket_name": raw.get("S3BucketName"),
        "s3_key_prefix": raw.get("S3KeyPrefix"),
        "kms_key_id": raw.get("KmsKeyId"),
        "cloudwatch_logs_group_arn": raw.get("CloudWatchLogsLogGroupArn"),
        "is_logging": None,
        "logging_status_known": False,
        "latest_delivery_time": None,
        "latest_delivery_error": None,
        "collection_errors": [],
    }


def apply_status(normalized: dict[str, Any], status: dict[str, Any] | None) -> dict[str, Any]:
    """Merge GetTrailStatus into a normalized trail.

    Empty strings are how the API reports "no such event yet"; they are mapped
    to None so a rule never treats "" as a delivery error.
    """
    if not status:
        return normalized

    error = status.get("LatestDeliveryError") or None
    normalized.update(
        {
            "is_logging": status.get("IsLogging"),
            "logging_status_known": True,
            "latest_delivery_time": isoformat(status.get("LatestDeliveryTime")),
            "latest_delivery_error": error,
            "time_logging_started": status.get("TimeLoggingStarted") or None,
            "time_logging_stopped": status.get("TimeLoggingStopped") or None,
        }
    )
    return normalized
