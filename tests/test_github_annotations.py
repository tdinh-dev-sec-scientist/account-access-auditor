from auditor.reporters.github_actions import annotations_for_report, escape_command_data


def test_github_annotations_escape_untrusted_paths_and_messages():
    assert escape_command_data("a%,\r\n:b") == "a%25%2C%0D%0A%3Ab"
    report = {
        "contract": {"scan_run": {"status": "FAIL"}},
        "findings": [
            {
                "control_id": "IAC-K8S-001",
                "severity": "HIGH",
                "title": "Bad pod",
                "description": "line 1\n::warning::forged",
                "source_location": {"file": "manifests/a,b.yaml", "line": 4},
                "exceptions": [],
                "gate": True,
            }
        ],
        "collection_errors": [],
    }

    output = annotations_for_report(report)

    assert output.startswith("::error file=manifests/a%2Cb.yaml,line=4,title=IAC-K8S-001::")
    assert "%0A" in output
    assert "\n::warning::forged" not in output


def test_scanner_errors_emit_failing_workflow_annotations():
    output = annotations_for_report(
        {
            "contract": {"scan_run": {"status": "ERROR"}},
            "findings": [],
            "collection_errors": [
                {"service": "IaC", "operation": "conftest", "message": "failed to start"}
            ],
        }
    )

    assert "::error title=IaC scanner error::IaC conftest: failed to start" in output
