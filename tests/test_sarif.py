from __future__ import annotations

from auditor.reporters.sarif import to_sarif


def test_sarif_maps_findings_to_rules_locations_and_exception_properties():
    report = {
        "metadata": {"tool_version": "1.0.0"},
        "contract": {"scan_run": {"status": "FAIL"}},
        "findings": [
            {
                "control_id": "IAC-K8S-001",
                "scanner_rule_id": "data.main.deny",
                "severity": "HIGH",
                "title": "Privileged container",
                "description": "Container runs privileged.",
                "remediation": "Disable privileged mode.",
                "source_location": {"file": "k8s/api.yaml", "line": 12},
                "fingerprint": "0123456789abcdef",
                "exceptions": [{"id": "EXC-1", "state": "ACTIVE", "owner": "platform", "reason": "reviewed"}],
                "gate": False,
            },
            {
                "control_id": "IAC-LOW-001",
                "scanner_rule_id": "rule.low",
                "severity": "LOW",
                "title": "Low issue",
                "description": "Description",
                "remediation": "Fix it.",
                "source_location": {"file": "infra/main.tf"},
                "fingerprint": "fedcba9876543210",
                "exceptions": [],
                "gate": False,
            },
        ],
        "collection_errors": [],
    }

    document = to_sarif(report)

    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    run = document["runs"][0]
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
        "IAC-K8S-001",
        "IAC-LOW-001",
    }
    first, second = run["results"]
    assert first["level"] == "error"
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "k8s/api.yaml"
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    assert first["partialFingerprints"]["account-access-auditor/v1"] == "0123456789abcdef"
    assert first["properties"]["exceptions"][0]["id"] == "EXC-1"
    assert second["level"] == "note"


def test_sarif_marks_collection_failures_as_unsuccessful_invocations():
    document = to_sarif(
        {
            "metadata": {"tool_version": "1.0.0"},
            "contract": {"scan_run": {"status": "ERROR"}},
            "findings": [],
            "collection_errors": [
                {"service": "IaC", "operation": "checkov", "message": "scanner unavailable"}
            ],
        }
    )

    invocation = document["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["level"] == "error"
    assert "scanner unavailable" in invocation["toolExecutionNotifications"][0]["message"]["text"]
