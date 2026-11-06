#!/usr/bin/env python3
"""Collect Stage 2 acceptance evidence from the live deployment.

    python3 scripts/collect_phase3_stage2_evidence.py \\
        --profile vorrin-admin --demo-profile vorrin-demo-admin --bucket-prefix vorrin \\
        --reviewer "Truong Dinh"

Prerequisites: Stage 2 applied, the pseudonym key stored, at least one
published snapshot, and a fresh ID token from scripts/phase3_id_token.py.

Three checks, in this order:

1. Redaction: runs tests/test_phase3_stage2_redaction_cases.py (one test per
   required category), then scans the live published snapshot and API
   responses for the account IDs, ARNs, bucket and role names, emails, IPs and
   access keys, and validates the snapshot against the closed public schema.
2. Public API methods: GET and HEAD with the ID token must return 200; every
   other standard method must be refused.
3. Publisher failure (changes AWS, then restores it): a deliberately invalid
   pseudonym key is made current, one scan runs, the publisher must fail, and
   the public latest pointer and object must be byte-for-byte unchanged. The
   original key version is made current again in a ``finally`` block; the key
   value itself is never read.

Without --confirm-reviewed nothing is written to docs/evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phase3.redaction import PublicSnapshotError, validate_public_snapshot  # noqa: E402
from phase3.stage_evidence import StageEvidenceError, validate_stage_evidence  # noqa: E402

EVIDENCE = ROOT / "docs/evidence"
MANIFEST = EVIDENCE / "phase3-stage-acceptance.json"
TOKEN_FILE = ROOT / "build/phase3/id-token"
CASE_TESTS = "tests/test_phase3_stage2_redaction_cases.py"
FILES = (
    "stage2/redaction-test-results.json",
    "stage2/publisher-failure.json",
    "stage2/public-api-methods.json",
)
REJECTED_METHODS = ("OPTIONS", "PATCH", "POST", "PUT", "DELETE", "TRACE", "CONNECT")
_GENERIC_LEAKS = {
    "arn": re.compile(r"arn:aws[a-z-]*:"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ip_address": re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])"),
    "access_key": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
}
INVALID_KEY = "!invalid-pseudonym-key-for-the-stage2-publisher-failure-test!"


class CollectError(RuntimeError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dump(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


# -- 1. Redaction -------------------------------------------------------------


def case_results(junit_xml: str) -> tuple[list[str], list[str]]:
    """Return (passed categories, failed test IDs) from a pytest JUnit report."""
    passed, failed = [], []
    for case in ET.fromstring(junit_xml).iter("testcase"):
        name = case.get("name", "")
        if not name.startswith("test_case_"):
            continue
        if any(child.tag in {"failure", "error", "skipped"} for child in case):
            failed.append(name)
        else:
            passed.append(name.removeprefix("test_case_"))
    return sorted(passed), sorted(failed)


def run_case_tests() -> tuple[list[str], list[str]]:
    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "cases.xml"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                CASE_TESTS,
                f"--junitxml={report}",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        if not report.exists():
            raise CollectError("the redaction case tests did not run")
        return case_results(report.read_text(encoding="utf-8"))


def count_leaks(bodies: list[bytes], private_values: list[str]) -> dict[str, int]:
    """Count private identifiers in published bytes; an empty result means none."""
    found: dict[str, int] = {}
    for body in bodies:
        text = body.decode("utf-8", errors="replace")
        for value in private_values:
            if value and value in text:
                found[f"value:{value[:4]}…"] = found.get(f"value:{value[:4]}…", 0) + text.count(value)
        for label, pattern in _GENERIC_LEAKS.items():
            hits = len(pattern.findall(text))
            if hits:
                found[label] = found.get(label, 0) + hits
    return found


# -- 2. API methods ------------------------------------------------------------


def method_results(request) -> dict[str, str]:
    """``request(method)`` returns an HTTP status, or None when the connection is refused."""
    results = {}
    for method in ("GET", "HEAD"):
        status = request(method)
        results[method] = "served" if status == 200 else f"failed:{status}"
    for method in REJECTED_METHODS:
        status = request(method)
        results[method] = "rejected" if status is None or status >= 400 else f"accepted:{status}"
    return results


def https_requester(host: str, path: str, token: str):
    def request(method: str) -> int | None:
        connection = http.client.HTTPSConnection(host, timeout=30)
        try:
            connection.request(method, path, headers={"Authorization": f"Bearer {token}"})
            return connection.getresponse().status
        except (OSError, http.client.HTTPException):
            return None
        finally:
            connection.close()

    return request


def fetch(host: str, path: str, token: str) -> tuple[int, bytes]:
    connection = http.client.HTTPSConnection(host, timeout=30)
    try:
        connection.request("GET", path, headers={"Authorization": f"Bearer {token}"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


# -- Documents -------------------------------------------------------------------


def build_documents(
    *,
    reviewer: str,
    reviewed_at: str,
    test_suite_sha256: str,
    passed_categories: list[str],
    failed_case_ids: list[str],
    leaks: dict[str, int],
    unapproved_fields: int,
    previous_sha256: str,
    after_sha256: str,
    methods: dict[str, str],
) -> dict[str, bytes]:
    review = {"schema_version": 1, "reviewed_by": reviewer, "reviewed_at": reviewed_at}
    problems = []
    if failed_case_ids:
        problems.append(f"redaction cases failed: {', '.join(failed_case_ids)}")
    if leaks:
        problems.append(f"published data contains private identifiers: {leaks}")
    if unapproved_fields:
        problems.append("the published snapshot does not match the closed public schema")
    if previous_sha256 != after_sha256:
        problems.append("the public snapshot changed during the injected publisher failure")
    bad_methods = {
        method: result for method, result in methods.items() if result not in {"served", "rejected"}
    }
    if bad_methods:
        problems.append(f"API method results are wrong: {bad_methods}")
    if problems:
        raise CollectError("; ".join(problems))
    redaction = {
        **review,
        "test_suite_sha256": test_suite_sha256,
        "passed_case_categories": passed_categories,
        "failed_case_ids": [],
        "leaked_identifier_count": 0,
        "published_unapproved_fields": 0,
    }
    publisher = {
        **review,
        "injected_failure": "redaction",
        "previous_snapshot_sha256": previous_sha256,
        "published_snapshot_sha256": after_sha256,
        "last_good_preserved": True,
    }
    api = {**review, "method_results": methods}
    return {FILES[0]: _dump(redaction), FILES[1]: _dump(publisher), FILES[2]: _dump(api)}


def update_manifest(
    manifest: dict[str, Any], files: dict[str, bytes], reviewer: str, reviewed_at: str
) -> None:
    manifest["stages"]["stage2"] = {
        "status": "passed",
        "reviewed_by": reviewer,
        "reviewed_at": reviewed_at,
        "criteria": {
            "redaction_and_secret_tests": True,
            "publisher_failure_atomicity": True,
            "public_api_method_tests": True,
        },
        "evidence": list(FILES),
        "evidence_sha256": {path: _sha(body) for path, body in files.items()},
    }


# -- 3. Publisher failure (AWS) ---------------------------------------------------


def latest_public(dynamodb, s3, table: str, bucket: str) -> tuple[str, bytes]:
    item = dynamodb.get_item(
        TableName=table, Key={"pk": {"S": "demo"}, "sk": {"S": "LATEST"}}, ConsistentRead=True
    ).get("Item")
    if not item or "snapshot_key" not in item:
        raise CollectError("nothing is published yet: store the pseudonym key and run one scan first")
    key = item["snapshot_key"]["S"]
    return key, s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def current_version(secrets, secret_id: str) -> str:
    versions = secrets.describe_secret(SecretId=secret_id).get("VersionIdsToStages", {})
    current = [version for version, stages in versions.items() if "AWSCURRENT" in stages]
    if len(current) != 1:
        raise CollectError("store the pseudonym key first (the secret has no current value)")
    return current[0]


def inject_publisher_failure(secrets, sfn, secret_id: str, state_machine_arn: str, wait=time.sleep) -> str:
    """Run one scan with an unusable pseudonym key; always restore the original key."""
    original = current_version(secrets, secret_id)
    injected = None
    try:
        injected = secrets.put_secret_value(SecretId=secret_id, SecretString=INVALID_KEY)["VersionId"]
        execution = sfn.start_execution(stateMachineArn=state_machine_arn)["executionArn"]
        for _ in range(120):
            described = sfn.describe_execution(executionArn=execution)
            if described["status"] != "RUNNING":
                break
            wait(15)
        else:
            raise CollectError("the injected scan did not finish within 30 minutes")
    finally:
        if injected and current_version(secrets, secret_id) != original:
            secrets.update_secret_version_stage(
                SecretId=secret_id,
                VersionStage="AWSCURRENT",
                MoveToVersionId=original,
                RemoveFromVersionId=injected,
            )
        if current_version(secrets, secret_id) != original:
            raise CollectError("the original pseudonym key is NOT current; restore it before anything else")
    if described["status"] != "FAILED" or described.get("error") != "Phase3PublicationPaused":
        raise CollectError(
            f"expected the scan to stop with Phase3PublicationPaused, got {described['status']} "
            f"{described.get('error', '')}".strip()
        )
    return execution


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--demo-profile", required=True)
    parser.add_argument("--bucket-prefix", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--id-token-file", type=Path, default=TOKEN_FILE)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--confirm-reviewed", action="store_true")
    args = parser.parse_args()

    import boto3

    try:
        token = args.id_token_file.read_text(encoding="ascii").strip()
    except OSError:
        print("error: no ID token; run scripts/phase3_id_token.py first", file=sys.stderr)
        return 1
    admin = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    demo = boto3.session.Session(profile_name=args.demo_profile, region_name=args.region)
    account_id = admin.client("sts").get_caller_identity()["Account"]
    demo_account_id = demo.client("sts").get_caller_identity()["Account"]
    prefix = args.bucket_prefix
    public_bucket = f"{prefix}-p3-public-{account_id}"
    table = f"{prefix}-p3-public-index"
    secret_id = f"{prefix}/phase3/public-pseudonym-hmac"
    state_machine = f"arn:aws:states:{args.region}:{account_id}:stateMachine:{prefix}-p3-scheduled-scan"
    s3, dynamodb = admin.client("s3"), admin.client("dynamodb")

    try:
        apis = [
            api["id"]
            for page in admin.client("apigateway").get_paginator("get_rest_apis").paginate()
            for api in page["items"]
            if api["name"] == f"{prefix}-p3-public-api"
        ]
        if len(apis) != 1:
            raise CollectError("expected exactly one public API; is Stage 2 applied?")
        host = f"{apis[0]}.execute-api.{args.region}.amazonaws.com"

        print("1/3 Redaction case tests and live leak scan…")
        passed, failed = run_case_tests()
        key, body = latest_public(dynamodb, s3, table, public_bucket)
        try:
            validate_public_snapshot(json.loads(body))
            unapproved = 0
        except (PublicSnapshotError, ValueError):
            unapproved = 1
        responses = [body]
        for route in ("latest", "runs", "findings", "drift"):
            status, response = fetch(host, f"/v1/api/{route}", token)
            if status == 401:
                raise CollectError(
                    "the ID token was refused (expired?); run scripts/phase3_id_token.py again"
                )
            responses.append(response)
        private_values = [
            account_id,
            demo_account_id,
            "AccountAccessAuditorReadOnly",
            f"{prefix}-p3-demo-a",
            f"{prefix}-p3-demo-b",
            f"{prefix}-p3-trail",
            f"{prefix}-p3-private",
        ]
        leaks = count_leaks(responses, private_values)
        print(
            f"    categories passed: {', '.join(passed)}; failed: {failed or 'none'}; leaks: {leaks or 'none'}"
        )

        print("2/3 Public API methods…")
        methods = method_results(https_requester(host, "/v1/api/latest", token))
        print(f"    {methods}")

        if not args.confirm_reviewed:
            print("\nDry run: skipped the publisher-failure test and wrote nothing.")
            print("If the lines above look right, rerun with --confirm-reviewed (takes ~10 minutes).")
            return 0

        print("3/3 Publisher failure: running one scan with an unusable key (~10 minutes)…")
        execution = inject_publisher_failure(
            admin.client("secretsmanager"), admin.client("stepfunctions"), secret_id, state_machine
        )
        after_key, after_body = latest_public(dynamodb, s3, table, public_bucket)
        print(
            f"    {execution.rsplit(':', 1)[-1]}: publication paused; latest pointer unchanged: {after_key == key}"
        )
        reviewed_at = datetime.now().astimezone().replace(microsecond=0).isoformat()
        files = build_documents(
            reviewer=args.reviewer,
            reviewed_at=reviewed_at,
            test_suite_sha256=_sha((ROOT / CASE_TESTS).read_bytes()),
            passed_categories=passed,
            failed_case_ids=failed,
            leaks=leaks,
            unapproved_fields=unapproved,
            previous_sha256=_sha(body),
            after_sha256=_sha(after_body) if after_key == key else "changed",
            methods=methods,
        )
    except CollectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for path, content in files.items():
        target = EVIDENCE / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    update_manifest(manifest, files, args.reviewer, reviewed_at)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    try:
        validate_stage_evidence("stage2", manifest["stages"]["stage2"], evidence_root=EVIDENCE)
    except StageEvidenceError as exc:
        print(f"error: written evidence does not validate: {exc}", file=sys.stderr)
        return 1
    print(f"\nWrote {len(files)} files under docs/evidence/stage2 and marked Stage 2 passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
