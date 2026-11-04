from __future__ import annotations

import json
from io import BytesIO

import pytest

from phase3.scan_task import ScanTaskError, configured_fleet, run_scan_task


def test_configured_fleet_targets_only_the_named_demo_account():
    fleet = configured_fleet(
        {
            "PHASE3_TARGET_ACCOUNT_ID": "123456789012",
            "PHASE3_TARGET_ROLE_ARN": "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly",
            "AWS_REGION": "us-east-1",
        }
    )

    assert [(account.account_id, account.role_arn) for account in fleet.accounts] == [
        ("123456789012", "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly")
    ]
    assert fleet.regions == ("us-east-1",)
    assert fleet.services == ("iam", "s3", "cloudtrail")


def test_configured_fleet_rejects_a_role_for_another_account():
    with pytest.raises(ScanTaskError, match="target role must belong to the configured demo account"):
        configured_fleet(
            {
                "PHASE3_TARGET_ACCOUNT_ID": "123456789012",
                "PHASE3_TARGET_ROLE_ARN": "arn:aws:iam::210987654321:role/AccountAccessAuditorReadOnly",
                "AWS_REGION": "us-east-1",
            }
        )


def test_configured_fleet_rejects_any_role_other_than_the_named_read_only_role():
    with pytest.raises(ScanTaskError, match="named read-only role"):
        configured_fleet(
            {
                "PHASE3_TARGET_ACCOUNT_ID": "123456789012",
                "PHASE3_TARGET_ROLE_ARN": "arn:aws:iam::123456789012:role/Admin",
                "AWS_REGION": "us-east-1",
            }
        )


def test_configured_fleet_requires_explicit_target_and_region():
    with pytest.raises(ScanTaskError, match="demo account and AWS region must be configured"):
        configured_fleet({})


def test_scan_task_assumes_only_configured_read_only_target_and_invokes_private_writer():
    source_session = object()
    source_guard = object()
    captured = {}

    class SnapshotWriterClient:
        def invoke(self, *, FunctionName, InvocationType, Payload):
            captured["writer_function"] = FunctionName
            captured["invocation_type"] = InvocationType
            captured["writer_event"] = json.loads(Payload)
            receipt = {
                "run_id": "12345678-1234-1234-1234-123456789abc",
                "status": "FAIL",
                "finding_count": 1,
                "snapshot_key": "snapshots/123456789012/2026/11/03/12345678-1234-1234-1234-123456789abc.json",
                "drift_counts": {"new": 1, "persistent": 0, "changed": 0, "resolved": 0, "unknown": 0},
            }
            return {"StatusCode": 200, "Payload": BytesIO(json.dumps(receipt).encode())}

    def session_factory(**kwargs):
        captured["session_kwargs"] = kwargs
        return source_session, source_guard

    def scanner(fleet, audit_config, session, **kwargs):
        captured["fleet"] = fleet
        captured["session"] = session
        captured["source_guard"] = kwargs["source_guard"]
        captured["fail_on"] = kwargs["fail_on"]
        captured["run_id"] = kwargs["run_id"]
        return {"contract": {"scan_run": {"run_id": kwargs["run_id"], "status": "FAIL"}}}

    result = run_scan_task(
        {
            "PHASE3_TARGET_ACCOUNT_ID": "123456789012",
            "PHASE3_TARGET_ROLE_ARN": "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly",
            "PHASE3_SCAN_RUN_ID": "12345678-1234-1234-1234-123456789abc",
            "PHASE3_SNAPSHOT_WRITER_FUNCTION": "phase3-snapshot-writer",
            "AWS_REGION": "us-east-1",
        },
        session_factory=session_factory,
        scanner=scanner,
        snapshot_writer=SnapshotWriterClient(),
    )

    assert result["run_id"] == "12345678-1234-1234-1234-123456789abc"
    assert result["status"] == "FAIL"
    assert captured["session_kwargs"] == {"profile": None, "region": "us-east-1"}
    assert captured["fleet"].accounts[0].account_id == "123456789012"
    assert captured["session"] is source_session
    assert captured["source_guard"] is source_guard
    assert captured["fail_on"] == "MEDIUM"
    assert captured["run_id"] == "12345678-1234-1234-1234-123456789abc"
    assert captured["writer_function"] == "phase3-snapshot-writer"
    assert captured["invocation_type"] == "RequestResponse"
    assert captured["writer_event"]["report"]["contract"]["scan_run"]["run_id"] == captured["run_id"]
