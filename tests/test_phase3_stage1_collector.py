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


# -- main() against fake AWS responses -----------------------------------------

import io  # noqa: E402
import sys  # noqa: E402
import types  # noqa: E402
from datetime import UTC, datetime  # noqa: E402

import scripts.collect_phase3_stage1_evidence as stage1  # noqa: E402

ADMIN = "210987654321"


def _snapshot_body(run_id, started, completed, drift):
    return json.dumps(
        {
            "metadata": {"scan_source": "aws-fleet", "scan_coverage": [{"account_id": DEMO}]},
            "contract": {
                "scan_run": {
                    "run_id": run_id,
                    "status": "FAIL",
                    "started_at": started,
                    "completed_at": completed,
                }
            },
            "drift": drift,
        }
    ).encode()


class _Fakes:
    def __init__(self, scheduler_caller=True):
        self.executions = {
            "exec-a": (
                datetime(2026, 11, 6, 17, 9, 15, tzinfo=UTC),
                datetime(2026, 11, 6, 17, 14, tzinfo=UTC),
                "run-a",
            ),
            "exec-b": (
                datetime(2026, 11, 6, 23, 9, 15, tzinfo=UTC),
                datetime(2026, 11, 6, 23, 14, tzinfo=UTC),
                "run-b",
            ),
        }
        self.objects = {
            f"snapshots/{DEMO}/2026/11/06/run-a.json": _snapshot_body(
                "run-a", "2026-11-06T17:10:00+00:00", "2026-11-06T17:13:00+00:00", []
            ),
            f"snapshots/{DEMO}/2026/11/06/run-b.json": _snapshot_body(
                "run-b",
                "2026-11-06T23:10:00+00:00",
                "2026-11-06T23:13:00+00:00",
                [
                    {"fingerprint": "f-new", "state": "new", "finding": {"rule_id": "S3-001", "title": "t"}},
                    {
                        "fingerprint": "f-old",
                        "state": "resolved",
                        "finding": {"rule_id": "S3-001", "title": "t"},
                    },
                ],
            ),
        }
        role = "vorrin-p3-scan-scheduler" if scheduler_caller else "SomeoneElse"
        self.caller = f"arn:aws:sts::{ADMIN}:assumed-role/{role}/session"

    def session(self, profile_name, region_name):
        fakes = self
        account = ADMIN if profile_name == "admin" else DEMO

        class Paginator:
            def __init__(self, pages):
                self.pages = pages

            def paginate(self, **kwargs):
                return self.pages(**kwargs)

        def client(name):
            c = types.SimpleNamespace()
            c.get_caller_identity = lambda: {"Account": account}

            def history(executionArn):
                run = fakes.executions[executionArn.rsplit(":", 1)[-1]][2]
                return [
                    {
                        "events": [
                            {"type": "ExecutionStarted"},
                            {
                                "stateExitedEventDetails": {
                                    "name": "Init",
                                    "output": json.dumps({"phase3": {"scan_run_id": run}}),
                                }
                            },
                        ]
                    }
                ]

            def describe_execution(executionArn):
                start, stop, _ = fakes.executions[executionArn.rsplit(":", 1)[-1]]
                return {"status": "SUCCEEDED", "startDate": start, "stopDate": stop}

            def trail_pages(LookupAttributes, StartTime, EndTime):
                events = []
                for name, (start, _stop, _run) in fakes.executions.items():
                    if StartTime <= start <= EndTime:
                        arn = f"arn:aws:states:us-east-1:{ADMIN}:execution:vorrin-p3-scheduled-scan:{name}"
                        record = {
                            "responseElements": {"executionArn": arn},
                            "userIdentity": {"arn": fakes.caller},
                        }
                        events.append({"CloudTrailEvent": json.dumps(record)})
                return [{"Events": events}]

            policy_arn = "arn:aws:iam::x:policy/target"
            pages = {
                "get_execution_history": history,
                "lookup_events": trail_pages,
                "list_role_policies": lambda RoleName: [{"PolicyNames": []}],
                "list_attached_role_policies": lambda RoleName: [
                    {"AttachedPolicies": [{"PolicyArn": policy_arn}]}
                ],
            }
            c.get_paginator = lambda op: Paginator(pages[op])
            c.describe_execution = describe_execution
            c.list_objects_v2 = lambda Bucket, Prefix: {"KeyCount": int(Prefix in fakes.objects)}
            c.get_object = lambda Bucket, Key: {"Body": io.BytesIO(fakes.objects[Key])}
            c.get_role = lambda RoleName: {"Role": {"Arn": f"arn:aws:iam::{DEMO}:role/{RoleName}"}}
            c.get_policy = lambda PolicyArn: {"Policy": {"DefaultVersionId": "v3"}}
            c.get_policy_version = lambda PolicyArn, VersionId: {"PolicyVersion": {"Document": READ_POLICY}}
            return c

        return types.SimpleNamespace(client=client)


def _run_main(monkeypatch, tmp_path, fakes, *extra):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    manifest = evidence / "phase3-stage-acceptance.json"
    manifest.write_text(json.dumps({"schema_version": 3, "stages": {"stage1": {}}}))
    monkeypatch.setattr(stage1, "EVIDENCE", evidence)
    monkeypatch.setattr(stage1, "MANIFEST", manifest)
    monkeypatch.setattr(stage1, "_terraform_change_sha256", lambda commit: "e" * 64)
    fake_boto3 = types.SimpleNamespace(session=types.SimpleNamespace(Session=fakes.session))
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    argv = [
        "collect",
        "--profile", "admin", "--demo-profile", "demo", "--bucket-prefix", "vorrin",
        "--previous-execution", "exec-a", "--current-execution", "exec-b",
        "--terraform-change-commit", "abc", "--reviewer", "Reviewer", *extra,
    ]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)
    return stage1.main(), evidence, manifest


def test_main_dry_run_writes_nothing(monkeypatch, tmp_path, capsys):
    code, evidence, _ = _run_main(monkeypatch, tmp_path, _Fakes())
    out = capsys.readouterr().out
    assert code == 0
    assert "new: f-new S3-001" in out and "resolved: f-old S3-001" in out
    assert not (evidence / "stage1").exists()


def test_main_confirmed_writes_valid_evidence(monkeypatch, tmp_path):
    code, evidence, manifest = _run_main(monkeypatch, tmp_path, _Fakes(), "--confirm-reviewed")
    assert code == 0
    record = json.loads(manifest.read_text())["stages"]["stage1"]
    assert record["status"] == "passed"
    log = json.loads((evidence / "stage1/schedule-execution-log.json").read_text())
    assert [e["scheduled_at"] for e in log["scheduled_executions"]] == [
        "2026-11-06T17:09:00Z",
        "2026-11-06T23:09:00Z",
    ]
    assert all(
        DEMO not in path.read_text() and ADMIN not in path.read_text() for path in evidence.rglob("*.json")
    )


def test_main_rejects_runs_not_started_by_the_scheduler(monkeypatch, tmp_path, capsys):
    code, _, _ = _run_main(monkeypatch, tmp_path, _Fakes(scheduler_caller=False))
    assert code == 1
    assert "not started by the vorrin-p3-scan-scheduler schedule" in capsys.readouterr().err
