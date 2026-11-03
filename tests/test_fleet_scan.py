from __future__ import annotations

from auditor.fleet import FleetConfig, TargetAccount
from auditor.models.finding import Finding, Severity


class FakeSession:
    def __init__(self, account_id: str, region_name: str):
        self.account_id = account_id
        self.region_name = region_name


def test_fleet_scan_collects_global_services_once_and_cloudtrail_per_region(monkeypatch):
    from auditor import fleet_scan

    config = FleetConfig(
        accounts=(
            TargetAccount(
                "123456789012",
                "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly",
            ),
        ),
        regions=("us-east-1", "us-west-2"),
        services=("iam", "s3", "cloudtrail"),
    )
    calls = []

    def assume(_source, *, role_arn, role_session_name, external_id, region_name):
        assert role_arn == config.accounts[0].role_arn
        assert role_session_name.startswith("auditor-")
        assert external_id is None
        return FakeSession("123456789012", region_name), None

    def caller(session):
        return session.account_id, "arn:aws:sts::123456789012:assumed-role/AccountAccessAuditorReadOnly/demo"

    def scan(session, services, _audit_config, _run_id):
        calls.append((session.region_name, tuple(services)))
        findings = []
        for service in services:
            if service == "iam":
                findings.append(_finding("IAM-004", "shared-role"))
            elif service == "s3":
                findings.append(_finding("S3-001", "shared-bucket"))
            else:
                findings.append(_finding("CT-001", f"trail-{session.region_name}"))
        return findings, [], {f"{service}_resources": 1 for service in services}

    monkeypatch.setattr(fleet_scan, "_run_scan", scan)
    monkeypatch.setattr(fleet_scan, "_assume_role", assume)
    monkeypatch.setattr(fleet_scan, "_describe_caller", caller)

    report = fleet_scan.run_fleet_scan(config, {}, FakeSession("source", "us-east-1"), run_id="run-1")

    assert calls == [
        ("us-east-1", ("iam", "s3")),
        ("us-east-1", ("cloudtrail",)),
        ("us-west-2", ("cloudtrail",)),
    ]
    assert report["contract"]["scan_run"]["regions"] == ["us-east-1", "us-west-2"]
    findings = report["contract"]["findings"]
    assert len(findings) == 4
    assert {finding["account_ref"]["id"] for finding in findings} == {"123456789012"}
    assert {finding["region"] for finding in findings} == {"aws-global", "us-east-1", "us-west-2"}
    assert len({finding["fingerprint"] for finding in findings}) == 4
    assert report["contract"]["scan_run"]["status"] == "PASS"


def test_fleet_scan_marks_a_missing_target_as_unknown_and_continues(monkeypatch):
    from auditor import fleet_scan

    first = TargetAccount(
        "123456789012", "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly"
    )
    second = TargetAccount(
        "210987654321", "arn:aws:iam::210987654321:role/AccountAccessAuditorReadOnly"
    )
    config = FleetConfig((first, second), ("us-east-1",), ("cloudtrail",))
    collected = []

    def assume(_source, *, role_arn, role_session_name, external_id, region_name):
        if role_arn == first.role_arn:
            raise RuntimeError("assume denied")
        return FakeSession(second.account_id, region_name), None

    monkeypatch.setattr(fleet_scan, "_assume_role", assume)
    monkeypatch.setattr(fleet_scan, "_describe_caller", lambda session: (session.account_id, "arn"))
    monkeypatch.setattr(
        fleet_scan,
        "_run_scan",
        lambda session, services, *_args: (collected.append(session.account_id) or [], [], {}),
    )

    report = fleet_scan.run_fleet_scan(config, {}, FakeSession("source", "us-east-1"), run_id="run-2")

    assert collected == [second.account_id]
    assert report["contract"]["scan_run"]["status"] == "UNKNOWN"
    assert report["contract"]["scan_run"]["exit_code"] == 3
    assert report["collection_errors"][0]["account_id"] == first.account_id


def _finding(rule_id: str, resource: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        service="AWS",
        resource=resource,
        title=rule_id,
        description="test finding",
        remediation="fix it",
    )
