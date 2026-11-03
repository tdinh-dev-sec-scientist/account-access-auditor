"""Read-only Phase 3 scan Lambda; it has no snapshot or publication access."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from typing import Any

from auditor.aws_session import build_session
from auditor.config import defaults
from auditor.fleet import FleetConfig, FleetConfigError, parse_fleet_config
from auditor.fleet_scan import run_fleet_scan
from auditor.severity import Severity

_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_ROLE_ARN = re.compile(r"^arn:aws:iam::([0-9]{12}):role/AccountAccessAuditorReadOnly$")
_REGION = re.compile(r"^[a-z]{2,}(?:-[a-z0-9]+)+-[0-9]+$")
MAX_WORKFLOW_REPORT_BYTES = 200 * 1024


class ScanWorkerError(ValueError):
    """The read-only scan could not be configured or completed."""


def configured_fleet(environ: Mapping[str, str]) -> FleetConfig:
    """Build a fixed single-account fleet; never accept targets from an event."""
    account_id = environ.get("PHASE3_TARGET_ACCOUNT_ID", "").strip()
    role_arn = environ.get("PHASE3_TARGET_ROLE_ARN", "").strip()
    source_region = (environ.get("PHASE3_SCAN_REGION") or environ.get("AWS_REGION") or "").strip()
    if not account_id or not role_arn or not source_region:
        raise ScanWorkerError("demo account and AWS region must be configured")
    if not _ACCOUNT_ID.fullmatch(account_id):
        raise ScanWorkerError("configured demo account ID is invalid")
    role_match = _ROLE_ARN.fullmatch(role_arn)
    if not role_match or role_match.group(1) != account_id:
        raise ScanWorkerError("target role must be the named read-only role in the demo account")
    if not _REGION.fullmatch(source_region):
        raise ScanWorkerError("configured AWS region is invalid")
    raw_regions = environ.get("PHASE3_SCAN_REGIONS", source_region)
    regions = [item.strip() for item in raw_regions.split(",") if item.strip()]
    document = {
        "accounts": [{"account_id": account_id, "role_arn": role_arn}],
        "regions": regions,
        "services": ["iam", "s3", "cloudtrail"],
    }
    try:
        fleet = parse_fleet_config(json.dumps(document))
    except FleetConfigError:
        raise ScanWorkerError("configured demo target is invalid") from None
    if len(fleet.accounts) != 1 or fleet.accounts[0].account_id != account_id:
        raise ScanWorkerError("scheduled scans must target exactly one configured demo account")
    return fleet


def run_scan(
    environ: Mapping[str, str] | None = None,
    *,
    session_factory: Callable[..., tuple[Any, Any]] | None = None,
    scanner: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a full scan report; this Lambda does not persist or publish it."""
    values = os.environ if environ is None else environ
    fleet = configured_fleet(values)
    try:
        threshold = Severity.from_string(values.get("PHASE3_FAIL_ON", "MEDIUM").strip()).value
    except ValueError:
        raise ScanWorkerError("configured finding threshold is invalid") from None
    make_session = session_factory or build_session
    try:
        source_session, source_guard = make_session(profile=None, region=fleet.regions[0])
    except Exception:
        raise ScanWorkerError("scan source session is unavailable") from None
    scan = scanner or run_fleet_scan
    try:
        report = scan(
            fleet,
            defaults(),
            source_session,
            source_guard=source_guard,
            fail_on=threshold,
        )
    except Exception:
        raise ScanWorkerError("read-only fleet scan failed") from None
    try:
        encoded = json.dumps(report, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ScanWorkerError("read-only fleet scan returned invalid report data") from None
    if len(encoded) > MAX_WORKFLOW_REPORT_BYTES:
        raise ScanWorkerError("scan report exceeds the 200 KiB workflow handoff limit")
    return report


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    """Lambda entry point. Event content cannot change the configured target."""
    del event, context
    return run_scan()
