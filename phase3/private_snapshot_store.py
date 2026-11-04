"""Private immutable scan snapshots and coverage-aware drift reconstruction."""

from __future__ import annotations

import json
import re
import tempfile
import time
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import BotoCoreError, ClientError

from auditor.history import HistoryError, HistoryStore, _validate_report

MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024
MAX_HISTORY_RUNS = 100
LOCK_TTL_SECONDS = 3600
PRIVATE_HISTORY_RETENTION_SECONDS = 60 * 24 * 60 * 60
DRIFT_STATES = ("new", "persistent", "changed", "resolved", "unknown")
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class PrivateSnapshotError(ValueError):
    """A report or private-store operation is invalid."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PrivateSnapshotError("stored scan report contains duplicate JSON keys")
        result[key] = value
    return result


class PrivateSnapshotStore:
    """Persist raw scan reports privately; update the index only after S3 writes."""

    def __init__(
        self,
        *,
        bucket_name: str,
        account_id: str,
        s3_client,
        run_index_table,
        temporary_directory: str | Path | None = None,
    ):
        if not isinstance(bucket_name, str) or not bucket_name.strip():
            raise PrivateSnapshotError("private snapshot bucket is invalid")
        if not isinstance(account_id, str) or not _ACCOUNT_ID.fullmatch(account_id):
            raise PrivateSnapshotError("configured demo account ID is invalid")
        self.bucket_name = bucket_name
        self.account_id = account_id
        self.s3 = s3_client
        self.table = run_index_table
        self.temporary_directory = temporary_directory

    def persist(self, report: dict[str, Any]) -> dict[str, Any]:
        run, coverage, findings = self._validate_target_report(report)
        run_id = run["run_id"]
        completed_at = self._timestamp(run["completed_at"])
        sort_key = f"RUN#{completed_at.isoformat()}#{run_id}"
        lock_owner = uuid.uuid4().hex
        self._acquire_lock(lock_owner)

        try:
            try:
                history = self._rebuild_history(self._prior_reports())
                enriched = history.record_scan(report)
                payload = self._encode(enriched)
                snapshot_key = f"snapshots/{self.account_id}/{completed_at:%Y/%m/%d}/{run_id}.json"
                self.s3.put_object(
                    Bucket=self.bucket_name,
                    Key=snapshot_key,
                    Body=payload,
                    ContentType="application/json",
                    IfNoneMatch="*",
                )
                table_item = self._index_item(
                    enriched,
                    run_id=run_id,
                    sort_key=sort_key,
                    snapshot_key=snapshot_key,
                    coverage=coverage,
                    finding_count=len(findings),
                )
                self.table.put_item(
                    Item=table_item,
                    ConditionExpression="attribute_not_exists(account_id) AND attribute_not_exists(sort_key)",
                )
            except PrivateSnapshotError:
                raise
            except (ClientError, BotoCoreError, HistoryError, OSError, TypeError, ValueError):
                # The immutable object can be orphaned on an index failure, but the
                # old index remains authoritative and no public object is touched.
                raise PrivateSnapshotError("private snapshot operation failed") from None
        finally:
            self._release_lock(lock_owner)

        drift = enriched.get("summary", {}).get("drift") or {}
        return {
            "run_id": run_id,
            "status": run["status"],
            "finding_count": len(findings),
            "snapshot_key": snapshot_key,
            "drift_counts": {state: int(drift.get(state, 0)) for state in DRIFT_STATES},
        }

    def get_receipt(self, run_id: str) -> dict[str, Any]:
        """Read one completed run receipt after ECS has finished its task."""
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise PrivateSnapshotError("scan run ID is invalid")
        matches = []
        for attempt in range(5):
            try:
                response = self.table.query(
                    IndexName="scan-run-index",
                    KeyConditionExpression=Key("scan_run_id").eq(run_id),
                    Limit=2,
                )
                matches = [
                    item
                    for item in response.get("Items", [])
                    if item.get("account_id") == self.account_id and item.get("scan_run_id") == run_id
                ]
            except (ClientError, BotoCoreError, KeyError, TypeError, ValueError):
                raise PrivateSnapshotError("private scan receipt is unavailable") from None
            if matches or attempt == 4:
                break
            time.sleep(0.2)
        if len(matches) != 1:
            raise PrivateSnapshotError("private scan receipt is unavailable")
        item = matches[0]
        if item.get("status") == "ERROR" and item.get("attempt_only") is True:
            return {
                "run_id": run_id,
                "status": "ERROR",
                "completed_at": item["completed_at"],
            }
        receipt = {
            "run_id": item.get("run_id"),
            "status": item.get("status"),
            "finding_count": _dynamodb_count(item.get("finding_count")),
            "snapshot_key": item.get("snapshot_key"),
            "drift_counts": {
                state: _dynamodb_count(item.get("drift_counts", {}).get(state)) for state in DRIFT_STATES
            }
            if isinstance(item.get("drift_counts"), dict)
            else None,
        }
        if not _valid_receipt(receipt, account_id=self.account_id, run_id=run_id):
            raise PrivateSnapshotError("private scan receipt is invalid")
        return receipt

    def record_failure(self, run_id: str, completed_at: str) -> dict[str, Any]:
        """Record a failed attempt without retaining task error details or replacing history."""
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise PrivateSnapshotError("scan run ID is invalid")
        completed = self._timestamp(completed_at).isoformat()
        item = {
            "account_id": self.account_id,
            "sort_key": f"ATTEMPT#{completed}#{run_id}",
            "scan_run_id": run_id,
            "run_id": run_id,
            "completed_at": completed,
            "status": "ERROR",
            "status_pk": f"{self.account_id}#incomplete",
            "status_sk": f"ATTEMPT#{completed}#{run_id}",
            "attempt_only": True,
            "expires_at": int(self._timestamp(completed).timestamp()) + PRIVATE_HISTORY_RETENTION_SECONDS,
        }
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(account_id) AND attribute_not_exists(sort_key)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return {"run_id": run_id, "status": "ERROR", "completed_at": completed}
            raise PrivateSnapshotError("private scan failure could not be recorded") from None
        except (BotoCoreError, KeyError, TypeError, ValueError):
            raise PrivateSnapshotError("private scan failure could not be recorded") from None
        return {"run_id": run_id, "status": "ERROR", "completed_at": completed}

    def _validate_target_report(self, report: dict[str, Any]):
        try:
            run, coverage, findings = _validate_report(report)
        except (AttributeError, HistoryError, KeyError, TypeError, ValueError):
            raise PrivateSnapshotError("scan report does not match the fleet contract") from None
        covered_accounts = {item["account_id"] for item in coverage}
        finding_accounts = {item["account_ref"]["id"] for item in findings}
        if covered_accounts != {self.account_id} or not finding_accounts.issubset({self.account_id}):
            raise PrivateSnapshotError("scan report does not match the configured demo account")
        if not _RUN_ID.fullmatch(run["run_id"]):
            raise PrivateSnapshotError("scan report run ID is invalid")
        self._timestamp(run["completed_at"])
        return run, coverage, findings

    def _prior_reports(self) -> list[dict[str, Any]]:
        active_history = Attr("expires_at").not_exists() | Attr("expires_at").gt(int(time.time()))
        items = []
        next_key = None
        while len(items) < MAX_HISTORY_RUNS:
            query = {
                "KeyConditionExpression": (
                    Key("account_id").eq(self.account_id) & Key("sort_key").begins_with("RUN#")
                ),
                "FilterExpression": active_history,
                "ScanIndexForward": False,
                "Limit": MAX_HISTORY_RUNS,
                "ConsistentRead": True,
            }
            if next_key:
                query["ExclusiveStartKey"] = next_key
            response = self.table.query(**query)
            items.extend(response.get("Items", []))
            next_key = response.get("LastEvaluatedKey")
            if not next_key:
                break
        items = items[:MAX_HISTORY_RUNS]
        if not any(item.get("status") in {"PASS", "FAIL"} for item in items):
            complete = []
            next_key = None
            while not complete:
                query = {
                    "IndexName": "status-index",
                    "KeyConditionExpression": Key("status_pk").eq(f"{self.account_id}#complete"),
                    "FilterExpression": active_history,
                    "ScanIndexForward": False,
                    "Limit": MAX_HISTORY_RUNS,
                }
                if next_key:
                    query["ExclusiveStartKey"] = next_key
                response = self.table.query(**query)
                complete = response.get("Items", [])
                next_key = response.get("LastEvaluatedKey")
                if not next_key:
                    break
            if complete:
                seen = {item.get("sort_key") for item in items}
                if complete[0].get("sort_key") not in seen:
                    items.append(complete[0])
        reports = [self._load_report(item["snapshot_key"]) for item in items]
        return sorted(
            reports,
            key=lambda item: (
                item["contract"]["scan_run"]["completed_at"],
                item["contract"]["scan_run"]["run_id"],
            ),
        )

    def _acquire_lock(self, owner: str) -> None:
        now = int(time.time())
        try:
            self.table.update_item(
                Key={"account_id": self.account_id, "sort_key": "LOCK#SCAN"},
                UpdateExpression="SET lock_owner = :owner, expires_at = :expires",
                ConditionExpression="attribute_not_exists(expires_at) OR expires_at < :now",
                ExpressionAttributeValues={
                    ":owner": owner,
                    ":expires": now + LOCK_TTL_SECONDS,
                    ":now": now,
                },
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ConditionalCheckFailedException":
                raise PrivateSnapshotError("another scan is already recording this account") from None
            raise PrivateSnapshotError("private scan lock could not be acquired") from None
        except BotoCoreError:
            raise PrivateSnapshotError("private scan lock could not be acquired") from None

    def _release_lock(self, owner: str) -> None:
        try:
            self.table.delete_item(
                Key={"account_id": self.account_id, "sort_key": "LOCK#SCAN"},
                ConditionExpression="lock_owner = :owner",
                ExpressionAttributeValues={":owner": owner},
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                # An expired lock may have been claimed by a newer scan.
                return
            raise PrivateSnapshotError("private scan lock could not be released") from None
        except BotoCoreError:
            raise PrivateSnapshotError("private scan lock could not be released") from None

    def _load_report(self, key: str) -> dict[str, Any]:
        if (
            not isinstance(key, str)
            or not key.startswith(f"snapshots/{self.account_id}/")
            or ".." in key.split("/")
        ):
            raise PrivateSnapshotError("private run index contains an invalid snapshot key")
        response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
        body = response["Body"].read(MAX_SNAPSHOT_BYTES + 1)
        if len(body) > MAX_SNAPSHOT_BYTES:
            raise PrivateSnapshotError("stored scan report exceeds the size limit")
        try:
            report = json.loads(body, object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError):
            raise PrivateSnapshotError("stored scan report is not valid JSON") from None
        if not isinstance(report, dict):
            raise PrivateSnapshotError("stored scan report must be a JSON object")
        return report

    def _rebuild_history(self, reports: Iterable[dict[str, Any]]) -> HistoryStore:
        root = tempfile.TemporaryDirectory(
            prefix="phase3-private-history-",
            dir=self.temporary_directory,
        )
        # Keep the directory alive with the store until this invocation ends.
        self._temporary_history_root = root
        store = HistoryStore(Path(root.name) / "history")
        seen: set[str] = set()
        for previous in reports:
            run_id = previous.get("contract", {}).get("scan_run", {}).get("run_id")
            if run_id in seen:
                continue
            store.record_scan(previous)
            seen.add(run_id)
        return store

    @staticmethod
    def _encode(report: dict[str, Any]) -> bytes:
        try:
            payload = json.dumps(
                report,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise PrivateSnapshotError("scan report is not valid JSON data") from None
        if len(payload) > MAX_SNAPSHOT_BYTES:
            raise PrivateSnapshotError("scan report exceeds the 10 MiB private snapshot limit")
        return payload

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if not isinstance(value, str):
            raise PrivateSnapshotError("scan completion time is invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise PrivateSnapshotError("scan completion time is invalid") from None
        if parsed.tzinfo is None:
            raise PrivateSnapshotError("scan completion time must include a timezone")
        return parsed.astimezone(UTC)

    def _index_item(
        self,
        report: dict[str, Any],
        *,
        run_id: str,
        sort_key: str,
        snapshot_key: str,
        coverage: list[dict[str, Any]],
        finding_count: int,
    ) -> dict[str, Any]:
        run = report["contract"]["scan_run"]
        status = run["status"]
        completed = self._timestamp(run["completed_at"]).isoformat()
        complete = status in {"PASS", "FAIL"} and all(item["complete"] for item in coverage)
        return {
            "account_id": self.account_id,
            "sort_key": sort_key,
            "run_id": run_id,
            "scan_run_id": run_id,
            "completed_at": completed,
            "status": status,
            "status_pk": f"{self.account_id}#{'complete' if complete else 'incomplete'}",
            "status_sk": f"RUN#{completed}#{run_id}",
            "snapshot_key": snapshot_key,
            "finding_count": finding_count,
            "expires_at": int(self._timestamp(completed).timestamp()) + PRIVATE_HISTORY_RETENTION_SECONDS,
            "drift_counts": {
                state: int(report.get("summary", {}).get("drift", {}).get(state, 0)) for state in DRIFT_STATES
            },
        }


def _valid_receipt(value: Any, *, account_id: str, run_id: str) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "run_id",
        "status",
        "finding_count",
        "snapshot_key",
        "drift_counts",
    }:
        return False
    if value["run_id"] != run_id or value["status"] not in {"PASS", "FAIL", "UNKNOWN", "ERROR"}:
        return False
    if (
        not isinstance(value["finding_count"], int)
        or isinstance(value["finding_count"], bool)
        or value["finding_count"] < 0
    ):
        return False
    key = value["snapshot_key"]
    if not isinstance(key, str) or not key.startswith(f"snapshots/{account_id}/") or ".." in key.split("/"):
        return False
    drift = value["drift_counts"]
    return (
        isinstance(drift, dict)
        and set(drift) == set(DRIFT_STATES)
        and all(
            isinstance(count, int) and not isinstance(count, bool) and count >= 0 for count in drift.values()
        )
    )


def _dynamodb_count(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        count = value
    elif isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value():
        count = int(value)
    else:
        return None
    return count if count >= 0 else None
