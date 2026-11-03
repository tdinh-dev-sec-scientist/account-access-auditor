"""Private-only snapshot-writer Lambda for validated Phase 3 scan reports."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

import boto3

from .private_snapshot_store import PrivateSnapshotError, PrivateSnapshotStore


class SnapshotWriterError(ValueError):
    """A scan report could not be safely written to private history."""


def persist_report(
    report: Any,
    environ: Mapping[str, str] | None = None,
    *,
    store: Any = None,
    session_factory: Any = None,
) -> dict[str, Any]:
    values = os.environ if environ is None else environ
    account_id = values.get("PHASE3_TARGET_ACCOUNT_ID", "").strip()
    region = (values.get("PHASE3_SCAN_REGION") or values.get("AWS_REGION") or "").strip()
    bucket = values.get("PHASE3_PRIVATE_SNAPSHOT_BUCKET", "").strip()
    table_name = values.get("PHASE3_PRIVATE_RUN_INDEX_TABLE", "").strip()
    if not isinstance(report, dict):
        raise SnapshotWriterError("scan report must be an object")
    store = _configured_store(
        account_id=account_id,
        region=region,
        bucket=bucket,
        table_name=table_name,
        store=store,
        session_factory=session_factory,
    )
    try:
        return store.persist(report)
    except PrivateSnapshotError:
        raise SnapshotWriterError("private scan snapshot could not be persisted") from None


def get_scan_receipt(
    run_id: Any,
    environ: Mapping[str, str] | None = None,
    *,
    store: Any = None,
    session_factory: Any = None,
) -> dict[str, Any]:
    values = os.environ if environ is None else environ
    account_id = values.get("PHASE3_TARGET_ACCOUNT_ID", "").strip()
    region = (values.get("PHASE3_SCAN_REGION") or values.get("AWS_REGION") or "").strip()
    bucket = values.get("PHASE3_PRIVATE_SNAPSHOT_BUCKET", "").strip()
    table_name = values.get("PHASE3_PRIVATE_RUN_INDEX_TABLE", "").strip()
    store = _configured_store(
        account_id=account_id,
        region=region,
        bucket=bucket,
        table_name=table_name,
        store=store,
        session_factory=session_factory,
    )
    try:
        receipt = store.get_receipt(run_id)
    except (PrivateSnapshotError, KeyError, TypeError, ValueError):
        raise SnapshotWriterError("private scan receipt is unavailable") from None
    if not isinstance(receipt, dict):
        raise SnapshotWriterError("private scan receipt is invalid")
    return receipt


def record_scan_failure(
    run_id: Any,
    completed_at: Any,
    environ: Mapping[str, str] | None = None,
    *,
    store: Any = None,
    session_factory: Any = None,
) -> dict[str, Any]:
    values = os.environ if environ is None else environ
    account_id = values.get("PHASE3_TARGET_ACCOUNT_ID", "").strip()
    region = (values.get("PHASE3_SCAN_REGION") or values.get("AWS_REGION") or "").strip()
    bucket = values.get("PHASE3_PRIVATE_SNAPSHOT_BUCKET", "").strip()
    table_name = values.get("PHASE3_PRIVATE_RUN_INDEX_TABLE", "").strip()
    store = _configured_store(
        account_id=account_id,
        region=region,
        bucket=bucket,
        table_name=table_name,
        store=store,
        session_factory=session_factory,
    )
    try:
        return store.record_failure(run_id, completed_at)
    except (PrivateSnapshotError, KeyError, TypeError, ValueError):
        raise SnapshotWriterError("private scan failure could not be recorded") from None


def _configured_store(
    *,
    account_id: str,
    region: str,
    bucket: str,
    table_name: str,
    store: Any,
    session_factory: Any,
) -> Any:
    if store is not None:
        return store
    if not account_id or not region or not bucket or not table_name:
        raise SnapshotWriterError("private snapshot store is not configured")
    make_session = session_factory or boto3.session.Session
    try:
        aws = make_session(region_name=region)
        return PrivateSnapshotStore(
            bucket_name=bucket,
            account_id=account_id,
            s3_client=aws.client("s3"),
            run_index_table=aws.resource("dynamodb").Table(table_name),
        )
    except Exception:
        raise SnapshotWriterError("private snapshot store is unavailable") from None


def lambda_handler(event: Any, context: Any, *, store: Any = None) -> dict[str, Any]:
    """Persist the Step Functions scan result; return only a safe receipt."""
    del context
    if not isinstance(event, dict):
        raise SnapshotWriterError("scan workflow event is invalid")
    if event.get("kind") == "scan_failure":
        if set(event) != {"kind", "run_id", "completed_at"}:
            raise SnapshotWriterError("scan failure event is invalid")
        return record_scan_failure(event["run_id"], event["completed_at"], store=store)
    if event.get("kind") == "get_receipt":
        if set(event) != {"kind", "run_id"}:
            raise SnapshotWriterError("scan receipt event is invalid")
        return get_scan_receipt(event["run_id"], store=store)
    if set(event) != {"report"}:
        raise SnapshotWriterError("scan workflow event is invalid")
    return persist_report(event["report"], store=store)
