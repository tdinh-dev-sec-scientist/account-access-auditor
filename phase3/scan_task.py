"""Scheduled Fargate scan entry point for the Phase 3 demo account."""

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
_SCAN_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
MAX_SNAPSHOT_WRITER_PAYLOAD_BYTES = 5 * 1024 * 1024
_DRIFT_STATES = {"new", "persistent", "changed", "resolved", "unknown"}


class ScanTaskError(ValueError):
    """The scheduled scan could not be configured or persisted safely."""


def configured_fleet(environ: Mapping[str, str]) -> FleetConfig:
    """Build a one-account fleet from deployment config, never from an event."""
    account_id = environ.get("PHASE3_TARGET_ACCOUNT_ID", "").strip()
    role_arn = environ.get("PHASE3_TARGET_ROLE_ARN", "").strip()
    source_region = (environ.get("PHASE3_SCAN_REGION") or environ.get("AWS_REGION") or "").strip()
    if not account_id or not role_arn or not source_region:
        raise ScanTaskError("demo account and AWS region must be configured")
    if not _ACCOUNT_ID.fullmatch(account_id):
        raise ScanTaskError("configured demo account ID is invalid")
    role_match = _ROLE_ARN.fullmatch(role_arn)
    if not role_match:
        raise ScanTaskError("target role must be the named read-only role in the demo account")
    if role_match.group(1) != account_id:
        raise ScanTaskError("target role must belong to the configured demo account")
    if not _REGION.fullmatch(source_region):
        raise ScanTaskError("configured AWS region is invalid")

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
        raise ScanTaskError("configured demo target is invalid") from None
    if len(fleet.accounts) != 1 or fleet.accounts[0].account_id != account_id:
        raise ScanTaskError("scheduled scans must target exactly one configured demo account")
    return fleet


def run_scan_task(
    environ: Mapping[str, str] | None = None,
    *,
    session_factory: Callable[..., tuple[Any, Any]] | None = None,
    scanner: Callable[..., dict[str, Any]] | None = None,
    snapshot_writer: Any = None,
) -> dict[str, Any]:
    """Run the read-only scan and hand its result to the scoped private writer."""
    values = os.environ if environ is None else environ
    fleet = configured_fleet(values)
    scan_run_id = values.get("PHASE3_SCAN_RUN_ID", "").strip()
    if not _SCAN_RUN_ID.fullmatch(scan_run_id):
        raise ScanTaskError("scheduled scan run ID is invalid")
    threshold = values.get("PHASE3_FAIL_ON", "MEDIUM").strip().upper()
    try:
        threshold = Severity.from_string(threshold).value
    except ValueError:
        raise ScanTaskError("configured finding threshold is invalid") from None

    make_session = session_factory or build_session
    try:
        source_session, source_guard = make_session(profile=None, region=fleet.regions[0])
    except Exception:
        raise ScanTaskError("scan source session is unavailable") from None
    scan = scanner or run_fleet_scan
    try:
        report = scan(
            fleet,
            defaults(),
            source_session,
            source_guard=source_guard,
            run_id=scan_run_id,
            fail_on=threshold,
        )
    except Exception:
        raise ScanTaskError("read-only fleet scan failed") from None

    try:
        encoded = json.dumps({"report": report}, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ScanTaskError("read-only fleet scan returned invalid report data") from None
    if len(encoded) > MAX_SNAPSHOT_WRITER_PAYLOAD_BYTES:
        raise ScanTaskError("scan report exceeds the private writer handoff limit")

    function_name = values.get("PHASE3_SNAPSHOT_WRITER_FUNCTION", "").strip()
    if not function_name:
        raise ScanTaskError("private snapshot writer is not configured")
    try:
        writer = snapshot_writer or source_session.client("lambda")
        response = writer.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=encoded,
        )
        if response.get("StatusCode") != 200 or response.get("FunctionError"):
            raise ValueError
        payload = response.get("Payload")
        if payload is None:
            raise ValueError
        receipt_body = payload.read(64 * 1024 + 1)
        if len(receipt_body) > 64 * 1024:
            raise ValueError
        receipt = json.loads(receipt_body)
    except Exception:
        raise ScanTaskError("private scan snapshot could not be persisted") from None
    if not _valid_receipt(receipt, account_id=fleet.accounts[0].account_id, run_id=scan_run_id):
        raise ScanTaskError("private snapshot writer returned an invalid receipt")
    return receipt


def _valid_receipt(value: Any, *, account_id: str, run_id: str) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "run_id", "status", "finding_count", "snapshot_key", "drift_counts"
    }:
        return False
    if value["run_id"] != run_id or value["status"] not in {"PASS", "FAIL", "UNKNOWN", "ERROR"}:
        return False
    if not isinstance(value["finding_count"], int) or isinstance(value["finding_count"], bool) or value["finding_count"] < 0:
        return False
    key = value["snapshot_key"]
    if not isinstance(key, str) or not key.startswith(f"snapshots/{account_id}/") or ".." in key.split("/"):
        return False
    drift = value["drift_counts"]
    return (
        isinstance(drift, dict)
        and set(drift) == _DRIFT_STATES
        and all(isinstance(count, int) and not isinstance(count, bool) and count >= 0 for count in drift.values())
    )


def main() -> int:
    try:
        result = run_scan_task()
    except ScanTaskError as exc:
        print(json.dumps({"status": "ERROR", "code": "Phase3ScanTaskError", "message": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
