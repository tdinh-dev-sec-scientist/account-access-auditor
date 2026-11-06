import hashlib
import json

import pytest

from phase3.stage_evidence import validate_stage_evidence
from scripts.collect_phase3_stage1_evidence import (
    FILES,
    CollectError,
    build_documents,
    update_manifest,
    write_actions,
)

DEMO = "123456789012"
READ_POLICY = {
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetBucketPolicy", "iam:List*"], "Resource": "*"},
        {"Effect": "Deny", "NotAction": "s3:Get*", "Resource": "*"},
    ]
}


def _run(index, drift):
    hour = 5 + 6 * index
    return {
        "scan_run_id": f"run-{index}",
        "scheduled_at": f"2026-11-06T{hour:02d}:09:00Z",
        "workflow_started_at": f"2026-11-06T{hour:02d}:09:15Z",
        "workflow_stopped_at": f"2026-11-06T{hour:02d}:14:00Z",
        "started_at": f"2026-11-06T{hour:02d}:10:00Z",
        "completed_at": f"2026-11-06T{hour:02d}:12:00Z",
        "snapshot_sha256": hashlib.sha256(str(index).encode()).hexdigest(),
        "snapshot": {"drift": drift},
    }


def _build(tmp_path, drift=None, policies=None):
    drift = (
        drift
        if drift is not None
        else [
            {"fingerprint": "aaaa", "state": "new"},
            {"fingerprint": "bbbb", "state": "resolved"},
            {"fingerprint": "cccc", "state": "persistent"},
        ]
    )
    files = build_documents(
        runs=[_run(0, []), _run(1, drift)],
        reviewer="Reviewer",
        reviewed_at="2026-11-06T18:00:00-05:00",
        demo_account_id=DEMO,
        terraform_change_sha256="d" * 64,
        role_arn=f"arn:aws:iam::{DEMO}:role/AccountAccessAuditorReadOnly",
        policy_documents=policies or [READ_POLICY],
    )
    for path, body in files.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_bytes(body)
    return files


def test_generated_evidence_passes_the_stage1_validator(tmp_path):
    files = _build(tmp_path)
    manifest = {"stages": {}}
    update_manifest(manifest, files, "Reviewer", "2026-11-06T18:00:00-05:00")
    record = manifest["stages"]["stage1"]
    assert record["evidence"] == list(FILES)
    validate_stage_evidence(
        "stage1",
        record,
        evidence_root=tmp_path,
        expected_demo_account_id_sha256=hashlib.sha256(DEMO.encode()).hexdigest(),
    )
    drift = json.loads(files["stage1/drift-review.json"])
    assert drift["new_finding_ids"] == ["aaaa"] and drift["resolved_finding_ids"] == ["bbbb"]
    assert all(DEMO.encode() not in body for body in files.values())


def test_requires_both_new_and_resolved_findings(tmp_path):
    with pytest.raises(CollectError, match="1 new and 0 resolved"):
        _build(tmp_path, drift=[{"fingerprint": "aaaa", "state": "new"}])


def test_rejects_write_actions_and_not_action():
    assert write_actions([READ_POLICY]) == []
    risky = {
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:*", "s3:GetObject"]},
            {"Effect": "Allow", "NotAction": "iam:*"},
        ]
    }
    assert write_actions([risky]) == ["NotAction", "s3:*", "s3:PutObject"]


def test_rejects_runs_not_six_hours_apart(tmp_path):
    late = _run(1, [{"fingerprint": "a", "state": "new"}, {"fingerprint": "b", "state": "resolved"}])
    late["scheduled_at"] = "2026-11-06T12:10:00Z"
    with pytest.raises(CollectError, match="six hours"):
        build_documents(
            runs=[_run(0, []), late],
            reviewer="R",
            reviewed_at="2026-11-06T18:00:00-05:00",
            demo_account_id=DEMO,
            terraform_change_sha256="d" * 64,
            role_arn="arn",
            policy_documents=[READ_POLICY],
        )
