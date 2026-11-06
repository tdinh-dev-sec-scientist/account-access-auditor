#!/usr/bin/env python3
"""Collect Stage 1 acceptance evidence from two consecutive scheduled scans.

    python3 scripts/collect_phase3_stage1_evidence.py \\
        --profile vorrin-admin --demo-profile vorrin-demo-admin --bucket-prefix vorrin \\
        --previous-execution <name> --current-execution <name> \\
        --terraform-change-commit <sha> --reviewer "Truong Dinh"

Every AWS call is read-only. Without --confirm-reviewed the script prints what
it found and writes nothing. Read that summary, then rerun with
--confirm-reviewed to write the four stage1/ files and mark Stage 1 passed in
docs/evidence/phase3-stage-acceptance.json.

What is checked before anything is written:

* both executions were started by the scan scheduler role (CloudTrail), not by
  hand, they SUCCEEDED, and they are the two runs exactly six hours apart;
* each run's private snapshot exists, completed, and belongs to the demo
  account; its SHA-256 is taken over the stored object bytes;
* the current snapshot records at least one new and one resolved finding;
* the read-only target role grants no action outside Get*, List* or Describe*.

Account IDs and role ARNs never leave this machine: the evidence keeps only
their SHA-256 digests. ``scheduled_at`` is the start minute of the Step
Functions execution, because the Scheduler does not record its own fire time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phase3.stage_evidence import StageEvidenceError, validate_stage_evidence  # noqa: E402

EVIDENCE = ROOT / "docs/evidence"
MANIFEST = EVIDENCE / "phase3-stage-acceptance.json"
TARGET_ROLE = "AccountAccessAuditorReadOnly"
FILES = (
    "stage1/scheduled-scan-results.json",
    "stage1/schedule-execution-log.json",
    "stage1/drift-review.json",
    "stage1/read-only-role-review.json",
)
_READ_ACTION = re.compile(r"^[a-z0-9-]+:(Get|List|Describe)[A-Za-z0-9*]*$")
_SCHEDULE_GAP = timedelta(hours=6)


class CollectError(RuntimeError):
    pass


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise CollectError(f"timestamp without a timezone: {value}")
    return parsed


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _dump(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def write_actions(documents: list[dict[str, Any]]) -> list[str]:
    """Allowed actions that are not Get*, List* or Describe*."""
    found: set[str] = set()
    for document in documents:
        statements = document.get("Statement", [])
        for statement in [statements] if isinstance(statements, dict) else statements:
            if statement.get("Effect") != "Allow":
                continue
            if "NotAction" in statement:
                found.add("NotAction")
                continue
            actions = statement.get("Action", [])
            for action in [actions] if isinstance(actions, str) else actions:
                if not _READ_ACTION.fullmatch(action):
                    found.add(action)
    return sorted(found)


def drift_ids(snapshot: dict[str, Any]) -> tuple[list[str], list[str]]:
    new, resolved = [], []
    for transition in snapshot.get("drift") or []:
        if transition.get("state") == "new":
            new.append(transition["fingerprint"])
        elif transition.get("state") == "resolved":
            resolved.append(transition["fingerprint"])
    return sorted(set(new)), sorted(set(resolved))


def build_documents(
    *,
    runs: list[dict[str, Any]],
    reviewer: str,
    reviewed_at: str,
    demo_account_id: str,
    terraform_change_sha256: str,
    role_arn: str,
    policy_documents: list[dict[str, Any]],
) -> dict[str, bytes]:
    """Return the four evidence files; ``runs`` is [previous, current]."""
    review = {"schema_version": 1, "reviewed_by": reviewer, "reviewed_at": reviewed_at}
    previous, current = runs
    if _parse(current["scheduled_at"]) - _parse(previous["scheduled_at"]) != _SCHEDULE_GAP:
        raise CollectError("the two scheduled runs are not exactly six hours apart")
    new, resolved = drift_ids(current["snapshot"])
    if not new or not resolved:
        raise CollectError(
            f"the current scan records {len(new)} new and {len(resolved)} resolved findings; "
            "Stage 1 needs at least one of each"
        )
    blocked = write_actions(policy_documents)
    if blocked:
        raise CollectError(f"{TARGET_ROLE} allows non-read actions: {', '.join(blocked)}")

    log = {
        **review,
        "complete_export": True,
        "export_window_start": previous["workflow_started_at"],
        "export_window_end": current["workflow_stopped_at"],
        "scheduled_executions": [
            {
                "scan_run_id": run["scan_run_id"],
                "scheduled_at": run["scheduled_at"],
                "workflow_started_at": run["workflow_started_at"],
                "scan_started_at": run["started_at"],
                "status": "complete",
                "snapshot_sha256": run["snapshot_sha256"],
            }
            for run in runs
        ],
    }
    log_bytes = _dump(log)
    scans = {
        **review,
        "target_account_label": "demo-account",
        "target_account_id_sha256": _sha256_text(demo_account_id),
        "schedule_execution_log_evidence_path": FILES[1],
        "schedule_execution_log_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "consecutive_schedule_runs": True,
        "scans": [
            {
                "scan_run_id": run["scan_run_id"],
                "trigger": "scheduled",
                "status": "complete",
                "started_at": run["started_at"],
                "completed_at": run["completed_at"],
                "snapshot_sha256": run["snapshot_sha256"],
            }
            for run in runs
        ],
    }
    drift = {
        **review,
        "terraform_change_sha256": terraform_change_sha256,
        "previous_scan_run_id": previous["scan_run_id"],
        "current_scan_run_id": current["scan_run_id"],
        "new_finding_ids": new,
        "resolved_finding_ids": resolved,
    }
    canonical_policy = json.dumps(policy_documents, sort_keys=True, separators=(",", ":"))
    role = {
        **review,
        "role_arn_sha256": _sha256_text(role_arn),
        "policy_evidence_sha256": _sha256_text(canonical_policy),
        "effective_write_actions": [],
    }
    return {FILES[0]: _dump(scans), FILES[1]: log_bytes, FILES[2]: _dump(drift), FILES[3]: _dump(role)}


def update_manifest(
    manifest: dict[str, Any], files: dict[str, bytes], reviewer: str, reviewed_at: str
) -> None:
    manifest["stages"]["stage1"] = {
        "status": "passed",
        "reviewed_by": reviewer,
        "reviewed_at": reviewed_at,
        "criteria": {
            "two_consecutive_scheduled_scans": True,
            "reviewed_new_and_resolved_drift": True,
            "read_only_target_role_evidence": True,
        },
        "evidence": list(FILES),
        "evidence_sha256": {path: hashlib.sha256(body).hexdigest() for path, body in files.items()},
    }


# -- AWS reads ---------------------------------------------------------------


def _execution(sfn, cloudtrail, state_machine_arn: str, name: str, scheduler_role: str) -> dict[str, Any]:
    arn = state_machine_arn.replace(":stateMachine:", ":execution:") + f":{name}"
    execution = sfn.describe_execution(executionArn=arn)
    if execution["status"] != "SUCCEEDED":
        raise CollectError(f"execution {name} is {execution['status']}, not SUCCEEDED")
    started = execution["startDate"]
    scan_run_id = None
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=arn):
        for event in page["events"]:
            output = (event.get("stateExitedEventDetails") or {}).get("output")
            if output:
                scan_run_id = (json.loads(output).get("phase3") or {}).get("scan_run_id")
            if scan_run_id:
                break
        if scan_run_id:
            break
    if not scan_run_id:
        raise CollectError(f"execution {name} has no scan_run_id in its history")

    caller = None
    for page in cloudtrail.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "StartExecution"}],
        StartTime=started - timedelta(minutes=5),
        EndTime=started + timedelta(minutes=5),
    ):
        for event in page["Events"]:
            record = json.loads(event["CloudTrailEvent"])
            if (record.get("responseElements") or {}).get("executionArn") == arn:
                caller = (record.get("userIdentity") or {}).get("arn", "")
    if caller is None:
        raise CollectError(f"CloudTrail has no StartExecution event for {name}")
    if f":assumed-role/{scheduler_role}/" not in caller:
        raise CollectError(f"execution {name} was not started by the {scheduler_role} schedule")
    return {
        "name": name,
        "scan_run_id": scan_run_id,
        "workflow_started_at": _iso(started),
        "workflow_stopped_at": _iso(execution["stopDate"]),
        "scheduled_at": _iso(started.replace(second=0, microsecond=0)),
    }


def _snapshot(s3, bucket: str, demo_account_id: str, run: dict[str, Any]) -> dict[str, Any]:
    stopped = _parse(run["workflow_stopped_at"])
    key = None
    for day in {stopped.date(), (stopped - timedelta(days=1)).date()}:
        candidate = f"snapshots/{demo_account_id}/{day:%Y/%m/%d}/{run['scan_run_id']}.json"
        if s3.list_objects_v2(Bucket=bucket, Prefix=candidate).get("KeyCount"):
            key = candidate
    if key is None:
        raise CollectError(f"no private snapshot for scan run {run['scan_run_id']}")
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    snapshot = json.loads(body)
    scan_run = snapshot["contract"]["scan_run"]
    if scan_run.get("run_id") != run["scan_run_id"] or scan_run.get("status") not in {"PASS", "FAIL"}:
        raise CollectError(f"snapshot for {run['scan_run_id']} is not a completed scan")
    coverage = {item.get("account_id") for item in snapshot["metadata"]["scan_coverage"]}
    if coverage != {demo_account_id}:
        raise CollectError(f"snapshot for {run['scan_run_id']} does not cover only the demo account")
    started, completed = _parse(scan_run["started_at"]), _parse(scan_run["completed_at"])
    if started < _parse(run["workflow_started_at"]):
        raise CollectError(f"scan {run['scan_run_id']} started before its workflow")
    return {
        **run,
        "started_at": _iso(started),
        "completed_at": _iso(completed),
        "snapshot_sha256": hashlib.sha256(body).hexdigest(),
        "snapshot": snapshot,
    }


def _role_policies(iam) -> tuple[str, list[dict[str, Any]]]:
    role_arn = iam.get_role(RoleName=TARGET_ROLE)["Role"]["Arn"]
    documents = []
    for page in iam.get_paginator("list_role_policies").paginate(RoleName=TARGET_ROLE):
        for name in page["PolicyNames"]:
            documents.append(iam.get_role_policy(RoleName=TARGET_ROLE, PolicyName=name)["PolicyDocument"])
    for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=TARGET_ROLE):
        for attached in page["AttachedPolicies"]:
            policy = iam.get_policy(PolicyArn=attached["PolicyArn"])["Policy"]
            version = iam.get_policy_version(
                PolicyArn=attached["PolicyArn"], VersionId=policy["DefaultVersionId"]
            )
            documents.append(version["PolicyVersion"]["Document"])
    if not documents:
        raise CollectError(f"{TARGET_ROLE} has no permission policies")
    return role_arn, documents


def _terraform_change_sha256(commit: str) -> str:
    patch = subprocess.run(
        ["git", "show", "--format=", commit, "--", "infra/phase3/demo-account"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    if not patch.strip():
        raise CollectError(f"commit {commit} does not change infra/phase3/demo-account")
    return hashlib.sha256(patch).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", required=True, help="Management-account profile (read-only use).")
    parser.add_argument("--demo-profile", required=True, help="Demo-account profile (read-only use).")
    parser.add_argument("--bucket-prefix", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--previous-execution", required=True, help="Execution name of the scan before the change."
    )
    parser.add_argument(
        "--current-execution", required=True, help="Execution name of the next scheduled scan."
    )
    parser.add_argument(
        "--terraform-change-commit", required=True, help="Commit that changed the demo account."
    )
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--confirm-reviewed", action="store_true")
    args = parser.parse_args()

    import boto3

    admin = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    demo = boto3.session.Session(profile_name=args.demo_profile, region_name=args.region)
    account_id = admin.client("sts").get_caller_identity()["Account"]
    demo_account_id = demo.client("sts").get_caller_identity()["Account"]
    state_machine = (
        f"arn:aws:states:{args.region}:{account_id}:stateMachine:{args.bucket_prefix}-p3-scheduled-scan"
    )
    scheduler_role = f"{args.bucket_prefix}-p3-scan-scheduler"
    bucket = f"{args.bucket_prefix}-p3-private-{account_id}"
    try:
        sfn, cloudtrail, s3 = admin.client("stepfunctions"), admin.client("cloudtrail"), admin.client("s3")
        runs = [
            _snapshot(
                s3, bucket, demo_account_id, _execution(sfn, cloudtrail, state_machine, name, scheduler_role)
            )
            for name in (args.previous_execution, args.current_execution)
        ]
        role_arn, policies = _role_policies(demo.client("iam"))
        reviewed_at = datetime.now().astimezone().replace(microsecond=0).isoformat()
        files = build_documents(
            runs=runs,
            reviewer=args.reviewer,
            reviewed_at=reviewed_at,
            demo_account_id=demo_account_id,
            terraform_change_sha256=_terraform_change_sha256(args.terraform_change_commit),
            role_arn=role_arn,
            policy_documents=policies,
        )
    except CollectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    new, resolved = drift_ids(runs[1]["snapshot"])
    for run in runs:
        print(
            f"{run['name']}: scan {run['scan_run_id']} scheduled {run['scheduled_at']} "
            f"ran {run['started_at']} -> {run['completed_at']}"
        )
    for label, ids in (("new", new), ("resolved", resolved)):
        for fingerprint in ids:
            finding = next(
                t["finding"] for t in runs[1]["snapshot"]["drift"] if t["fingerprint"] == fingerprint
            )
            print(f"  {label}: {fingerprint} {finding.get('rule_id')} {finding.get('title')}")
    print(f"{TARGET_ROLE}: {len(policies)} policies, no non-read actions")

    if not args.confirm_reviewed:
        print("\nNothing written. Review the lines above, then rerun with --confirm-reviewed.")
        return 0
    for path, body in files.items():
        target = EVIDENCE / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    update_manifest(manifest, files, args.reviewer, reviewed_at)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    try:
        validate_stage_evidence(
            "stage1",
            manifest["stages"]["stage1"],
            evidence_root=EVIDENCE,
            expected_demo_account_id_sha256=_sha256_text(demo_account_id),
        )
    except StageEvidenceError as exc:
        print(f"error: written evidence does not validate: {exc}", file=sys.stderr)
        return 1
    print(f"\nWrote {len(files)} files under docs/evidence/stage1 and marked Stage 1 passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
