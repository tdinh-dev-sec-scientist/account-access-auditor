"""Read-only public GET/HEAD API for redacted Phase 3 snapshots."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError

from .publisher import MAX_PUBLIC_SNAPSHOT_BYTES, _unique_object
from .redaction import PublicSnapshotError, validate_public_snapshot

MAX_API_PAGE_SIZE = 100
STALE_AFTER_SECONDS = 12 * 60 * 60
_PUBLIC_KEY = re.compile(r"^snapshots/[a-f0-9]{24}\.json$")
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_DRIFT_STATES = {"new", "persistent", "changed", "resolved", "unknown"}
_SECURITY_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "public, max-age=30, must-revalidate",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
}


class PublicApiError(ValueError):
    """A public API read failed validation or was unavailable."""


class AwsPublicReadStore:
    """Read only the isolated public-results bucket and index table."""

    def __init__(self, *, bucket_name: str, table: Any, s3_client: Any):
        self.bucket_name = bucket_name
        self.table = table
        self.s3 = s3_client

    def get_latest(self) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        latest = self._get_item("LATEST")
        attempt = self._get_item("LATEST_STATUS")
        if not latest:
            return None, self._safe_attempt(attempt)
        key = latest.get("snapshot_key")
        if not isinstance(key, str) or not _PUBLIC_KEY.fullmatch(key):
            raise PublicApiError("public latest pointer is invalid")
        try:
            body = self.s3.get_object(Bucket=self.bucket_name, Key=key)["Body"].read(
                MAX_PUBLIC_SNAPSHOT_BYTES + 1
            )
        except (ClientError, BotoCoreError, KeyError, OSError):
            raise PublicApiError("public snapshot is unavailable") from None
        if len(body) > MAX_PUBLIC_SNAPSHOT_BYTES:
            raise PublicApiError("public snapshot exceeds the size limit")
        try:
            snapshot = json.loads(body, object_pairs_hook=_unique_object)
            validate_public_snapshot(snapshot)
        except (UnicodeError, json.JSONDecodeError, PublicSnapshotError):
            raise PublicApiError("public snapshot failed schema validation") from None
        if latest.get("snapshot_id") != snapshot.get("snapshot_id"):
            raise PublicApiError("public latest pointer does not match its snapshot")
        return snapshot, self._safe_attempt(attempt)

    def list_runs(self, limit: int) -> list[dict[str, Any]]:
        try:
            response = self.table.query(
                KeyConditionExpression=Key("pk").eq("demo") & Key("sk").begins_with("RUN#"),
                ScanIndexForward=False,
                Limit=limit,
            )
        except (ClientError, BotoCoreError, KeyError, TypeError, ValueError):
            raise PublicApiError("public run index is unavailable") from None
        runs = []
        for item in response.get("Items", []):
            snapshot_id = item.get("snapshot_id")
            completed_at = item.get("completed_at")
            status = item.get("scan_status")
            count = item.get("finding_count")
            if (
                not isinstance(snapshot_id, str)
                or not re.fullmatch(r"[a-f0-9]{24}", snapshot_id)
                or not isinstance(completed_at, str)
                or status not in {"PASS", "FAIL"}
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count < 0
            ):
                continue
            runs.append(
                {
                    "snapshot_id": snapshot_id,
                    "completed_at": completed_at,
                    "status": status,
                    "finding_count": count,
                }
            )
        return runs

    def _get_item(self, sort_key: str) -> dict[str, Any] | None:
        try:
            return self.table.get_item(
                Key={"pk": "demo", "sk": sort_key},
                ConsistentRead=True,
            ).get("Item")
        except (ClientError, BotoCoreError, KeyError, TypeError, ValueError):
            raise PublicApiError("public result index is unavailable") from None

    @staticmethod
    def _safe_attempt(attempt: dict[str, Any] | None) -> dict[str, Any] | None:
        if not isinstance(attempt, dict):
            return None
        status = attempt.get("scan_status")
        completed_at = attempt.get("completed_at")
        if status not in {"PASS", "FAIL", "UNKNOWN", "ERROR"} or not isinstance(completed_at, str):
            return None
        try:
            parsed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        publication_status = attempt.get("publication_status", "READY")
        if publication_status not in {"READY", "PAUSED"}:
            publication_status = "READY"
        raw_affected = attempt.get("affected_services", [])
        affected_services = []
        if isinstance(raw_affected, list) and len(raw_affected) <= 3:
            seen_services = set()
            for item in raw_affected:
                if (
                    isinstance(item, dict)
                    and set(item) == {"service", "status"}
                    and item.get("service") in {"iam", "s3", "cloudtrail"}
                    and item.get("status") == status
                    and status in {"UNKNOWN", "ERROR"}
                    and item["service"] not in seen_services
                ):
                    seen_services.add(item["service"])
                    affected_services.append(dict(item))
        return {
            "status": status,
            "completed_at": parsed.astimezone(UTC).isoformat(),
            "publication_status": publication_status,
            "affected_services": affected_services,
        }


def public_response(
    event: Any,
    *,
    store: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(event, dict):
        return _response(400, {"error": "INVALID_REQUEST"})
    method = event.get("httpMethod", "")
    if method not in {"GET", "HEAD"}:
        return _response(405, None, method=method, headers={"Allow": "GET, HEAD"})
    path = event.get("path") or event.get("rawPath")
    if not isinstance(path, str):
        return _response(400, {"error": "INVALID_REQUEST"}, method=method)
    if path == "/api/latest":
        try:
            snapshot, attempt = store.get_latest()
        except Exception:
            return _response(503, {"error": "PUBLIC_DATA_UNAVAILABLE"}, method=method, no_store=True)
        if snapshot is None:
            return _response(
                503,
                {"error": "NO_SNAPSHOT", "latest_attempt_status": attempt.get("status") if attempt else None},
                method=method,
                no_store=True,
            )
        return _latest_response(snapshot, attempt, now=now, method=method)
    if path == "/api/runs":
        try:
            query = _query(event, allowed={"limit"})
            limit = _parse_limit(query.get("limit", "50"))
            runs = store.list_runs(limit)
        except ValueError:
            return _response(400, {"error": "INVALID_QUERY"}, method=method)
        except Exception:
            return _response(503, {"error": "PUBLIC_DATA_UNAVAILABLE"}, method=method, no_store=True)
        return _response(200, {"runs": runs}, method=method)
    if path in {"/api/findings", "/api/drift"}:
        try:
            query = _query(event, allowed={"limit", "severity", "state"})
            limit = _parse_limit(query.get("limit", "100"))
            snapshot, _attempt = store.get_latest()
        except ValueError:
            return _response(400, {"error": "INVALID_QUERY"}, method=method)
        except Exception:
            return _response(503, {"error": "PUBLIC_DATA_UNAVAILABLE"}, method=method, no_store=True)
        if snapshot is None:
            return _response(503, {"error": "NO_SNAPSHOT"}, method=method, no_store=True)
        if path == "/api/findings":
            severity = query.get("severity")
            if severity is not None and severity not in _SEVERITIES:
                return _response(400, {"error": "INVALID_QUERY"}, method=method)
            findings = [
                item for item in snapshot["findings"] if severity is None or item["severity"] == severity
            ]
            return _response(
                200,
                {"snapshot_id": snapshot["snapshot_id"], "findings": findings[:limit]},
                method=method,
            )
        state = query.get("state")
        if state is not None and state not in _DRIFT_STATES:
            return _response(400, {"error": "INVALID_QUERY"}, method=method)
        drift = [item for item in snapshot["drift"] if state is None or item["state"] == state]
        return _response(
            200,
            {"snapshot_id": snapshot["snapshot_id"], "drift": drift[:limit]},
            method=method,
        )
    return _response(404, {"error": "NOT_FOUND"}, method=method)


def _latest_response(
    snapshot: dict[str, Any],
    attempt: dict[str, str] | None,
    *,
    now: datetime | None,
    method: str,
) -> dict[str, Any]:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    completed = datetime.fromisoformat(snapshot["scan"]["completed_at"])
    age_seconds = max(0, int((current.astimezone(UTC) - completed.astimezone(UTC)).total_seconds()))
    newer_attempt = bool(
        attempt and datetime.fromisoformat(attempt["completed_at"]) > completed.astimezone(UTC)
    )
    attempt_status = attempt["status"] if newer_attempt and attempt else None
    publication_paused = bool(newer_attempt and attempt and attempt.get("publication_status") == "PAUSED")
    data = {
        "data": snapshot,
        "freshness": {
            "age_seconds": age_seconds,
            "stale": age_seconds > STALE_AFTER_SECONDS,
            "latest_attempt_status": attempt_status,
            "last_good_preserved": attempt_status in {"UNKNOWN", "ERROR"},
            "publication_paused": publication_paused,
            "affected_services": (attempt.get("affected_services", []) if newer_attempt and attempt else []),
        },
    }
    return _response(200, data, method=method)


def _query(event: dict[str, Any], *, allowed: set[str]) -> dict[str, str]:
    raw = event.get("queryStringParameters") or {}
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise ValueError("invalid query")
    result = {}
    for key, value in raw.items():
        if not isinstance(value, str) or len(value) > 32:
            raise ValueError("invalid query")
        result[key] = value
    return result


def _parse_limit(value: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise ValueError("invalid limit")
    limit = int(value)
    if not 1 <= limit <= MAX_API_PAGE_SIZE:
        raise ValueError("invalid limit")
    return limit


def _response(
    status_code: int,
    body: Any,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    no_store: bool = False,
) -> dict[str, Any]:
    response_headers = dict(_SECURITY_HEADERS)
    if no_store:
        response_headers["Cache-Control"] = "no-store"
    if headers:
        response_headers.update(headers)
    if body is None or method == "HEAD":
        encoded = ""
    else:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return {"statusCode": status_code, "headers": response_headers, "body": encoded, "isBase64Encoded": False}


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    """API Gateway proxy handler. The role only reads public-results resources."""
    del context
    bucket = os.environ.get("PHASE3_PUBLIC_RESULTS_BUCKET", "").strip()
    table_name = os.environ.get("PHASE3_PUBLIC_INDEX_TABLE", "").strip()
    feature_table_name = os.environ.get("PHASE3_FEATURE_TABLE", "").strip()
    region = os.environ.get("AWS_REGION", "").strip()
    if not bucket or not table_name or not region:
        return _response(503, {"error": "PUBLIC_DATA_UNAVAILABLE"}, no_store=True)
    try:
        aws = boto3.session.Session(region_name=region)
        dynamodb = aws.resource("dynamodb")
        store = AwsPublicReadStore(
            bucket_name=bucket,
            table=dynamodb.Table(table_name),
            s3_client=aws.client("s3"),
        )
        feature_table = dynamodb.Table(feature_table_name) if feature_table_name else None
        static_mode = _static_mode(feature_table) if feature_table is not None else False
    except Exception:
        return _response(503, {"error": "PUBLIC_DATA_UNAVAILABLE"}, no_store=True)
    response = public_response(event, store=store)
    response["headers"]["X-Phase3-Static-Mode"] = "true" if static_mode else "false"
    return response


def _static_mode(table: Any) -> bool:
    """Read the kill-switch flag without granting this API write access."""
    try:
        item = table.get_item(Key={"pk": "PLATFORM", "sk": "CONFIG"}, ConsistentRead=True).get("Item")
    except Exception:
        raise PublicApiError("static-mode state is unavailable") from None
    if not isinstance(item, dict) or not isinstance(item.get("static_mode"), bool):
        raise PublicApiError("static-mode state is invalid")
    return item["static_mode"]
