"""Failure-atomic publication from private snapshots to isolated public data."""

from __future__ import annotations

import base64
import json
import os
import re
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .redaction import PublicSnapshotError, validate_public_snapshot

MAX_PUBLIC_SNAPSHOT_BYTES = 5 * 1024 * 1024
MAX_DYNAMODB_ITEM_BYTES = 350 * 1024
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")


class PublicationError(ValueError):
    """A sanitized snapshot could not be published safely."""


def publish_snapshot(snapshot: Any, store: Any) -> dict[str, Any]:
    """Publish complete data or record an incomplete attempt without moving latest."""
    try:
        validate_public_snapshot(snapshot)
    except PublicSnapshotError as exc:
        raise PublicationError(str(exc)) from None
    status = snapshot["scan"]["status"]
    completed_at = snapshot["scan"]["completed_at"]
    complete = snapshot["scan"]["complete_scopes"] > 0 and snapshot["scan"]["incomplete_scopes"] == 0
    if status not in {"PASS", "FAIL"} or not complete:
        try:
            store.record_attempt(
                status,
                completed_at,
                publication_status="READY",
                affected_services=snapshot["scan"]["affected_services"],
            )
        except Exception:
            raise PublicationError("scan attempt status could not be recorded") from None
        return {"status": "RETAINED_LAST_GOOD", "attempt_status": status}
    try:
        advanced = store.publish(snapshot)
        store.record_attempt(
            status,
            completed_at,
            publication_status="READY",
            affected_services=snapshot["scan"]["affected_services"],
        )
    except PublicationError:
        raise
    except Exception:
        raise PublicationError("sanitized snapshot could not be published") from None
    if not advanced:
        return {"status": "STALE_IGNORED", "snapshot_id": snapshot["snapshot_id"]}
    return {"status": "PUBLISHED", "snapshot_id": snapshot["snapshot_id"]}


class S3DynamoPublicStore:
    """Private S3 result objects with a DynamoDB last-good pointer."""

    def __init__(self, *, bucket_name: str, table: Any, s3_client: Any, partition: str = "demo"):
        if not isinstance(bucket_name, str) or not bucket_name.strip():
            raise PublicationError("public result bucket is invalid")
        if not isinstance(partition, str) or not partition.strip() or len(partition) > 32:
            raise PublicationError("public result partition is invalid")
        self.bucket_name = bucket_name
        self.table = table
        self.s3 = s3_client
        self.partition = partition

    def publish(self, snapshot: dict[str, Any]) -> bool:
        try:
            body = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise PublicationError("sanitized snapshot is not valid JSON") from None
        if len(body) > MAX_PUBLIC_SNAPSHOT_BYTES:
            raise PublicationError("sanitized snapshot exceeds the public size limit")
        snapshot_id = snapshot["snapshot_id"]
        completed_at = snapshot["scan"]["completed_at"]
        key = f"snapshots/{snapshot_id}.json"
        self._put_immutable_object(key, body)
        self._put_run_index(snapshot, key)
        try:
            self.table.update_item(
                Key={"pk": self.partition, "sk": "LATEST"},
                UpdateExpression=(
                    "SET snapshot_key = :key, snapshot_id = :id, completed_at = :completed, "
                    "scan_status = :status, schema_version = :schema"
                ),
                ConditionExpression="attribute_not_exists(completed_at) OR completed_at < :completed",
                ExpressionAttributeValues={
                    ":key": key,
                    ":id": snapshot_id,
                    ":completed": completed_at,
                    ":status": snapshot["scan"]["status"],
                    ":schema": snapshot["schema_version"],
                },
            )
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                latest = self._get("LATEST")
                return bool(latest and latest.get("snapshot_id") == snapshot_id)
            raise PublicationError("public latest pointer could not be updated") from None
        except (BotoCoreError, KeyError, TypeError, ValueError):
            raise PublicationError("public latest pointer could not be updated") from None

    def record_attempt(
        self,
        status: str,
        completed_at: str,
        *,
        publication_status: str = "READY",
        affected_services: Any = (),
    ) -> None:
        if status not in {"PASS", "FAIL", "UNKNOWN", "ERROR"}:
            raise PublicationError("scan attempt status is invalid")
        if publication_status not in {"READY", "PAUSED"}:
            raise PublicationError("publication status is invalid")
        if not isinstance(affected_services, (list, tuple)) or len(affected_services) > 3:
            raise PublicationError("affected service status is invalid")
        validated_affected_services = []
        seen_services = set()
        for item in affected_services:
            if (
                not isinstance(item, dict)
                or set(item) != {"service", "status"}
                or item.get("service") not in {"iam", "s3", "cloudtrail"}
                or item.get("status") not in {"UNKNOWN", "ERROR"}
                or item["service"] in seen_services
                or item["status"] != status
                or status not in {"UNKNOWN", "ERROR"}
            ):
                raise PublicationError("affected service status is invalid")
            seen_services.add(item["service"])
            validated_affected_services.append(dict(item))
        if publication_status == "PAUSED":
            message = "Publication is paused. The console is showing the last complete public snapshot."
        elif status in {"UNKNOWN", "ERROR"}:
            message = "The last scan was incomplete or failed. The console is showing the last complete snapshot."
        else:
            message = "The latest complete scan is available."
        try:
            self.table.update_item(
                Key={"pk": self.partition, "sk": "LATEST_STATUS"},
                UpdateExpression=(
                    "SET scan_status = :status, publication_status = :publication, "
                    "completed_at = :completed, message = :message, affected_services = :affected"
                ),
                ConditionExpression="attribute_not_exists(completed_at) OR completed_at <= :completed",
                ExpressionAttributeValues={
                    ":status": status,
                    ":publication": publication_status,
                    ":completed": completed_at,
                    ":message": message,
                    ":affected": validated_affected_services,
                },
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return
            raise PublicationError("scan attempt status could not be recorded") from None
        except (BotoCoreError, KeyError, TypeError, ValueError):
            raise PublicationError("scan attempt status could not be recorded") from None

    def _put_immutable_object(self, key: str, body: bytes) -> None:
        try:
            self.s3.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=body,
                ContentType="application/json",
                CacheControl="public, max-age=60, must-revalidate",
                IfNoneMatch="*",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in {"PreconditionFailed", "412"}:
                raise PublicationError("immutable public snapshot object could not be written") from None
            try:
                existing = self.s3.get_object(Bucket=self.bucket_name, Key=key)["Body"].read(
                    MAX_PUBLIC_SNAPSHOT_BYTES + 1
                )
            except (ClientError, BotoCoreError, KeyError, OSError):
                raise PublicationError("existing public snapshot could not be verified") from None
            if existing != body:
                raise PublicationError("public snapshot key already contains different data")
        except (BotoCoreError, OSError, TypeError, ValueError):
            raise PublicationError("immutable public snapshot object could not be written") from None

    def _put_run_index(self, snapshot: dict[str, Any], key: str) -> None:
        completed_at = snapshot["scan"]["completed_at"]
        snapshot_id = snapshot["snapshot_id"]
        item = {
            "pk": self.partition,
            "sk": f"RUN#{completed_at}#{snapshot_id}",
            "snapshot_id": snapshot_id,
            "snapshot_key": key,
            "completed_at": completed_at,
            "scan_status": snapshot["scan"]["status"],
            "finding_count": snapshot["summary"]["total_findings"],
            "schema_version": snapshot["schema_version"],
        }
        if len(json.dumps(item, separators=(",", ":")).encode("utf-8")) > MAX_DYNAMODB_ITEM_BYTES:
            raise PublicationError("public run index item exceeds the size limit")
        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise PublicationError("public run index could not be written") from None
            current = self._get(item["sk"])
            if not current or current.get("snapshot_id") != snapshot_id:
                raise PublicationError("public run index key already contains different data") from None
        except (BotoCoreError, KeyError, TypeError, ValueError):
            raise PublicationError("public run index could not be written") from None

    def _get(self, sort_key: str) -> dict[str, Any] | None:
        try:
            item = self.table.get_item(
                Key={"pk": self.partition, "sk": sort_key},
                ConsistentRead=True,
            ).get("Item")
            return item
        except (ClientError, BotoCoreError, KeyError, TypeError, ValueError):
            raise PublicationError("public result index could not be read") from None


def publish_private_snapshot(
    receipt: Any,
    environ: Any = None,
    *,
    s3_client: Any = None,
    secrets_client: Any = None,
    public_store: Any = None,
    session_factory: Any = None,
) -> dict[str, Any]:
    """Read one allowlisted private object, redact it, then publish to public storage."""
    values = os.environ if environ is None else environ
    account_id = values.get("PHASE3_TARGET_ACCOUNT_ID", "").strip()
    region = (values.get("AWS_REGION") or "").strip()
    private_bucket = values.get("PHASE3_PRIVATE_SNAPSHOT_BUCKET", "").strip()
    public_bucket = values.get("PHASE3_PUBLIC_RESULTS_BUCKET", "").strip()
    table_name = values.get("PHASE3_PUBLIC_INDEX_TABLE", "").strip()
    secret_arn = values.get("PHASE3_PSEUDONYM_SECRET_ARN", "").strip()
    if not isinstance(receipt, dict) or set(receipt) != {
        "run_id", "status", "finding_count", "snapshot_key", "drift_counts"
    }:
        raise PublicationError("private snapshot receipt is invalid")
    if not _ACCOUNT_ID.fullmatch(account_id):
        raise PublicationError("publisher demo account is not configured")
    snapshot_key = receipt.get("snapshot_key")
    if (
        not isinstance(snapshot_key, str)
        or not snapshot_key.startswith(f"snapshots/{account_id}/")
        or ".." in snapshot_key.split("/")
    ):
        raise PublicationError("private snapshot key is outside the demo account prefix")
    if public_store is None:
        if not all((region, private_bucket, public_bucket, table_name, secret_arn)):
            raise PublicationError("public publisher is not fully configured")
        make_session = session_factory or boto3.session.Session
        aws = make_session(region_name=region)
        s3_client = s3_client or aws.client("s3")
        secrets_client = secrets_client or aws.client("secretsmanager")
        table = aws.resource("dynamodb").Table(table_name)
        public_store = S3DynamoPublicStore(
            bucket_name=public_bucket,
            table=table,
            s3_client=s3_client,
        )
    if not private_bucket or not secret_arn:
        raise PublicationError("private source or pseudonym key is not configured")
    if s3_client is None or secrets_client is None:
        raise PublicationError("publisher service clients are unavailable")
    try:
        response = s3_client.get_object(Bucket=private_bucket, Key=snapshot_key)
        body = response["Body"].read(10 * 1024 * 1024 + 1)
    except (ClientError, BotoCoreError, KeyError, OSError):
        raise PublicationError("private scan snapshot could not be read") from None
    if len(body) > 10 * 1024 * 1024:
        raise PublicationError("private scan snapshot exceeds the size limit")
    try:
        report = json.loads(body, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise PublicationError("private scan snapshot is invalid JSON") from None
    try:
        secret_response = secrets_client.get_secret_value(SecretId=secret_arn)
        encoded_key = secret_response.get("SecretString")
        if not isinstance(encoded_key, str):
            raise ValueError
        hmac_key = base64.b64decode(encoded_key, validate=True)
    except (ClientError, BotoCoreError, KeyError, TypeError, ValueError):
        raise PublicationError("public pseudonym key could not be read") from None
    from .redaction import PublicSnapshotError, redact_snapshot

    try:
        public_snapshot = redact_snapshot(report, hmac_key)
    except PublicSnapshotError as exc:
        raise PublicationError(str(exc)) from None
    return publish_snapshot(public_snapshot, public_store)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicationError("private scan snapshot contains duplicate JSON keys")
        result[key] = value
    return result


def lambda_handler(event: Any, context: Any, *, public_store: Any = None) -> dict[str, Any]:
    """Lambda entry point receiving only a private receipt or safe status event."""
    del context
    if isinstance(event, dict) and event.get("kind") in {"scan_failure", "publication_failure"}:
        if set(event) != {"kind", "completed_at"}:
            raise PublicationError("scan status event is invalid")
        values = os.environ
        region = values.get("AWS_REGION", "").strip()
        table_name = values.get("PHASE3_PUBLIC_INDEX_TABLE", "").strip()
        completed_at = event.get("completed_at")
        if not isinstance(completed_at, str):
            raise PublicationError("scan failure status is not configured")
        try:
            from datetime import UTC, datetime

            parsed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            timestamp = parsed.astimezone(UTC).isoformat()
            if public_store is None:
                if not region or not table_name:
                    raise ValueError
                aws = boto3.session.Session(region_name=region)
                table = aws.resource("dynamodb").Table(table_name)
                public_store = S3DynamoPublicStore(bucket_name="phase3-status-only", table=table, s3_client=None)
            paused = event["kind"] == "publication_failure"
            public_store.record_attempt(
                "ERROR",
                timestamp,
                publication_status="PAUSED" if paused else "READY",
            )
        except (ClientError, BotoCoreError, KeyError, TypeError, ValueError):
            raise PublicationError("scan status could not be recorded") from None
        return {"status": "PUBLICATION_PAUSED" if paused else "SCAN_FAILURE_RECORDED"}
    if not isinstance(event, dict) or set(event) != {"receipt"}:
        raise PublicationError("publisher event is invalid")
    return publish_private_snapshot(event["receipt"], public_store=public_store)
