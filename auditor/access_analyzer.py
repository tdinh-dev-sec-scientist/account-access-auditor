"""Explicit, opt-in IAM policy validation through IAM Access Analyzer."""

from __future__ import annotations

import json
import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .models.contracts import scanner_finding_record
from .severity import Severity

POLICY_TYPES = ("IDENTITY_POLICY", "RESOURCE_POLICY", "SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY")
RESOURCE_TYPES = (
    "AWS::S3::Bucket",
    "AWS::S3::AccessPoint",
    "AWS::S3::MultiRegionAccessPoint",
    "AWS::S3ObjectLambda::AccessPoint",
    "AWS::IAM::AssumeRolePolicyDocument",
    "AWS::DynamoDB::Table",
)
MAX_POLICY_BYTES = 1_048_576
MAX_FINDING_PAGES = 100
_ISSUE_CODE = re.compile(r"[^A-Z0-9_.-]+")
_SEVERITY = {
    "SECURITY_WARNING": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "SUGGESTION": Severity.INFO,
}


def validate_policy_document(
    session,
    policy_document: dict[str, Any],
    *,
    policy_type: str,
    source_file: str,
    validate_policy_resource_type: str | None = None,
    account_ref: dict[str, str] | None = None,
    region: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate a supplied policy document and preserve API findings as records.

    The caller must provide the explicitly guarded Access Analyzer session. The
    API evaluates caller-supplied JSON; it does not create or change AWS resources.
    """
    if policy_type not in POLICY_TYPES:
        return [], [_input_error("InvalidPolicyType", "policy type is not supported")]
    if validate_policy_resource_type is not None and (
        policy_type != "RESOURCE_POLICY" or validate_policy_resource_type not in RESOURCE_TYPES
    ):
        return [], [_input_error("InvalidResourceType", "resource type is not valid for this policy type")]
    if not isinstance(source_file, str) or not source_file.strip() or len(source_file) > 1024:
        return [], [_input_error("InvalidSourceFile", "source file must be non-empty text of at most 1024 characters")]
    if not isinstance(policy_document, dict):
        return [], [_input_error("InvalidPolicyDocument", "policy document must be a JSON object")]
    try:
        policy_text = json.dumps(policy_document, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return [], [_input_error("InvalidPolicyDocument", "policy document is not valid JSON data")]
    if len(policy_text.encode("utf-8")) > MAX_POLICY_BYTES:
        return [], [_input_error("PolicyTooLarge", "policy document exceeds the 1 MiB limit")]

    request: dict[str, Any] = {
        "policyDocument": policy_text,
        "policyType": policy_type,
        "locale": "EN",
        "maxResults": 100,
    }
    if validate_policy_resource_type is not None:
        request["validatePolicyResourceType"] = validate_policy_resource_type

    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    client = session.client("accessanalyzer")
    token = None
    seen_tokens: set[str] = set()
    for _page_number in range(MAX_FINDING_PAGES):
        page_request = dict(request)
        if token is not None:
            page_request["nextToken"] = token
        try:
            page = client.validate_policy(**page_request)
        except (ClientError, BotoCoreError) as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown") if isinstance(exc, ClientError) else exc.__class__.__name__
            errors.append(
                {
                    "service": "Access Analyzer",
                    "operation": "accessanalyzer:ValidatePolicy",
                    "resource": source_file,
                    "code": code,
                    "category": "scanner_error",
                    "message": f"IAM Access Analyzer validation failed ({code})",
                }
            )
            return findings, errors
        raw_findings = page.get("findings")
        if not isinstance(raw_findings, list):
            errors.append(_input_error("InvalidScannerOutput", "Access Analyzer findings must be a list"))
            return findings, errors
        for raw_finding in raw_findings:
            record = _finding_record(raw_finding, source_file, account_ref, region)
            if record is None:
                errors.append(_input_error("InvalidScannerOutput", "Access Analyzer returned a malformed finding"))
            else:
                findings.append(record)
        token = page.get("nextToken")
        if token is None:
            return findings, errors
        if not isinstance(token, str) or not token or token in seen_tokens:
            errors.append(_input_error("InvalidScannerOutput", "Access Analyzer returned an invalid pagination token"))
            return findings, errors
        seen_tokens.add(token)
    errors.append(_input_error("ResultLimitExceeded", "Access Analyzer returned more than 100 result pages"))
    return findings, errors


def _finding_record(
    raw: Any,
    source_file: str,
    account_ref: dict[str, str] | None,
    region: str | None,
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    issue = raw.get("issueCode")
    finding_type = raw.get("findingType")
    details = raw.get("findingDetails")
    locations = raw.get("locations")
    if (
        not isinstance(issue, str)
        or not issue.strip()
        or not isinstance(finding_type, str)
        or finding_type not in _SEVERITY
        or not isinstance(details, str)
        or not isinstance(locations, list)
    ):
        return None
    line = None
    if locations and isinstance(locations[0], dict):
        span = locations[0].get("span")
        start = span.get("start") if isinstance(span, dict) else None
        candidate = start.get("line") if isinstance(start, dict) else None
        if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
            line = candidate
    source_location = {"file": source_file}
    if line is not None:
        source_location["line"] = line
    control_code = _ISSUE_CODE.sub("_", issue.upper()).strip("_.-")[:112] or "UNKNOWN"
    return scanner_finding_record(
        control_id=f"AA-{control_code}",
        scanner="aws-access-analyzer",
        scanner_rule_id=issue[:128],
        source_type="iam-policy",
        severity=_SEVERITY[finding_type],
        source_severity=finding_type,
        title=issue[:256],
        description=details[:4000],
        evidence={
            "finding_type": finding_type,
            "locations": locations[:100],
            "learn_more_link": str(raw.get("learnMoreLink") or "")[:2048],
        },
        remediation="Review the policy location and the linked Access Analyzer guidance.",
        source_location=source_location,
        account_ref=account_ref,
        region=region,
        service="access-analyzer",
    )


def _input_error(code: str, message: str) -> dict[str, Any]:
    return {
        "service": "Access Analyzer",
        "operation": "validation-input",
        "resource": None,
        "code": code,
        "category": "scanner_error",
        "message": message,
    }
