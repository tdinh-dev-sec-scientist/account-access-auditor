"""Strict, time-bounded finding exceptions for local policy scans."""

from __future__ import annotations

import hmac
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from .severity import Severity

MAX_EXCEPTION_FILE_BYTES = 1_048_576
MAX_EXCEPTIONS = 1_000
_FINGERPRINT = re.compile(r"^[a-f0-9]{16}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_CONTROL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ALLOWED_KEYS = {
    "id",
    "fingerprint",
    "control_id",
    "resource_reference",
    "source_file",
    "owner",
    "approver",
    "reason",
    "created_at",
    "expires_at",
}


class ExceptionConfigError(ValueError):
    """The exception file is invalid or cannot be read safely."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ExceptionConfigError("YAML mapping keys must be strings")
        if key in mapping:
            raise ExceptionConfigError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        raise ExceptionConfigError(f"{field} must be an ISO-8601 timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ExceptionConfigError(f"{field} must be an ISO-8601 timestamp with a timezone") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExceptionConfigError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _text(value: Any, field: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 and char not in "\t" for char in value)
    ):
        raise ExceptionConfigError(f"{field} must be non-empty text of at most {maximum} characters")
    return value.strip()


def _scope(record: dict[str, Any]) -> dict[str, str]:
    fingerprint = record.get("fingerprint")
    control_id = record.get("control_id")
    resource = record.get("resource_reference")
    source_file = record.get("source_file")
    if fingerprint is not None:
        if (
            not isinstance(fingerprint, str)
            or not _FINGERPRINT.fullmatch(fingerprint)
            or control_id is not None
            or resource is not None
            or source_file is not None
        ):
            raise ExceptionConfigError("fingerprint scope must be an exact 16-character finding fingerprint")
        return {"fingerprint": fingerprint}
    if (
        not isinstance(control_id, str)
        or not _CONTROL_ID.fullmatch(control_id)
        or (resource is None) == (source_file is None)
    ):
        raise ExceptionConfigError(
            "rule exceptions require a control_id and exactly one exact resource_reference or source_file"
        )
    if resource is not None:
        resource = _text(resource, "resource_reference", maximum=512)
        if any(char in resource for char in "*?[]"):
            raise ExceptionConfigError("wildcards are not allowed in exception scopes")
        return {"control_id": control_id, "resource_reference": resource}

    source_file = _text(source_file, "source_file", maximum=512).replace("\\", "/")
    path = PurePosixPath(source_file)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(char in source_file for char in "*?[]")
    ):
        raise ExceptionConfigError("source_file must be an exact relative path without wildcards or traversal")
    return {"control_id": control_id, "source_file": path.as_posix()}


def load_exceptions(path: str | Path, *, as_of: datetime | None = None) -> list[dict[str, Any]]:
    """Load strict YAML exception records; malformed files never suppress findings."""
    source = Path(path)
    try:
        if source.stat().st_size > MAX_EXCEPTION_FILE_BYTES:
            raise ExceptionConfigError("exception file exceeds the 1 MiB size limit")
        raw = source.read_text(encoding="utf-8")
    except ExceptionConfigError:
        raise
    except (OSError, UnicodeError):
        raise ExceptionConfigError("exception file could not be read as UTF-8") from None
    try:
        document = yaml.load(raw, Loader=_UniqueKeyLoader)
    except ExceptionConfigError:
        raise
    except yaml.YAMLError:
        raise ExceptionConfigError("exception file contains invalid YAML") from None

    if not isinstance(document, dict) or set(document) != {"exceptions"}:
        raise ExceptionConfigError("exception file must contain only an exceptions list")
    records = document["exceptions"]
    if not isinstance(records, list) or len(records) > MAX_EXCEPTIONS:
        raise ExceptionConfigError("exceptions must be a list of at most 1000 records")

    now = (as_of or datetime.now(UTC)).astimezone(UTC)
    seen_ids: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, raw_record in enumerate(records):
        if not isinstance(raw_record, dict) or set(raw_record) - _ALLOWED_KEYS:
            raise ExceptionConfigError(f"exception {index + 1} must be an object with only supported fields")
        required = {"id", "owner", "reason", "created_at", "expires_at"}
        if not required <= set(raw_record):
            raise ExceptionConfigError(f"exception {index + 1} is missing required fields")
        record_id = _text(raw_record["id"], "id", maximum=64)
        if not _IDENTIFIER.fullmatch(record_id) or record_id in seen_ids:
            raise ExceptionConfigError("exception IDs must be unique simple identifiers")
        seen_ids.add(record_id)
        owner = _text(raw_record["owner"], "owner", maximum=128)
        reason = _text(raw_record["reason"], "reason", maximum=2000)
        approver = raw_record.get("approver")
        if approver is not None:
            approver = _text(approver, "approver", maximum=128)
        created = _timestamp(raw_record["created_at"], "created_at")
        expires = _timestamp(raw_record["expires_at"], "expires_at")
        if created > now:
            raise ExceptionConfigError("created_at cannot be in the future")
        if expires <= created:
            raise ExceptionConfigError("expires_at must be after created_at")
        scope = _scope(raw_record)
        validated.append(
            {
                "id": record_id,
                **scope,
                "owner": owner,
                "approver": approver,
                "reason": reason,
                "created_at": created.isoformat(timespec="seconds"),
                "expires_at": expires.isoformat(timespec="seconds"),
                "state": "ACTIVE" if now <= expires else "EXPIRED",
            }
        )
    return validated


def _matches(finding: dict[str, Any], exception: dict[str, Any]) -> bool:
    if "fingerprint" in exception:
        candidate = finding.get("fingerprint")
        return isinstance(candidate, str) and hmac.compare_digest(candidate, exception["fingerprint"])
    if finding.get("control_id") != exception["control_id"]:
        return False
    if "resource_reference" in exception:
        return finding.get("resource_reference") == exception["resource_reference"]
    location = finding.get("source_location")
    return isinstance(location, dict) and location.get("file") == exception["source_file"]


def evaluate_exceptions(
    findings: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
    *,
    threshold: str,
    as_of: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Annotate findings and evaluate the gate without deleting or rewriting evidence."""
    threshold_severity = Severity.from_string(threshold)
    now = (as_of or datetime.now(UTC)).astimezone(UTC)
    evaluations: list[dict[str, Any]] = []
    annotated: list[dict[str, Any]] = []
    violations = 0
    for exception in exceptions:
        matches = [finding for finding in findings if _matches(finding, exception)]
        timestamp_state = exception["state"]
        state = (
            f"MATCHED_{timestamp_state}"
            if matches
            else f"UNMATCHED_{timestamp_state}"
        )
        evaluations.append({**exception, "state": state, "match_count": len(matches)})

    for finding in findings:
        matches = [exception for exception in exceptions if _matches(finding, exception)]
        finding_exceptions = []
        active_exception = False
        for exception in matches:
            expires = _timestamp(exception["expires_at"], "expires_at")
            created = _timestamp(exception["created_at"], "created_at")
            state = "ACTIVE" if created <= now <= expires else "EXPIRED"
            active_exception = active_exception or state == "ACTIVE"
            finding_exceptions.append(
                {
                    "id": exception["id"],
                    "owner": exception["owner"],
                    "approver": exception["approver"],
                    "reason": exception["reason"],
                    "created_at": exception["created_at"],
                    "expires_at": exception["expires_at"],
                    "state": state,
                }
            )
        gated_severity = Severity.from_string(finding["severity"]).at_least(threshold_severity)
        is_gate_finding = gated_severity and not active_exception
        violations += int(is_gate_finding)
        annotated.append({**finding, "exceptions": finding_exceptions, "gate": is_gate_finding})
    return annotated, evaluations, violations
