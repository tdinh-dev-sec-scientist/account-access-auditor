from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
LOCAL_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


def test_readme_and_docs_local_links_resolve():
    documents = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    missing = []

    for document in documents:
        for destination in LOCAL_LINK.findall(document.read_text(encoding="utf-8")):
            destination = destination.split("#", 1)[0].split("?", 1)[0]
            if not destination or destination.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if not (document.parent / destination).exists():
                missing.append(f"{document.relative_to(ROOT)}: {destination}")

    assert not missing, "broken local documentation links:\n" + "\n".join(missing)


def test_readme_and_status_record_phase2_release_completion_under_approved_scope():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    status = (ROOT / "docs/implementation-status.md").read_text(encoding="utf-8")
    remediation = (ROOT / "docs/remediation.md").read_text(encoding="utf-8")
    normalized_remediation = " ".join(remediation.split())

    assert "Phase 2 is release-complete under the approved read-only Stage 6 amendment" in readme
    assert "Phase 2 is release-complete under the approved read-only Stage 6 amendment" in status
    assert "Phase 3 has not started" in status
    assert "AWS sandbox apply is not implemented or claimed" in readme
    assert "AWS sandbox apply is not implemented or claimed" in status
    assert "AWS sandbox apply is not implemented or claimed" in normalized_remediation
    assert "satisfies the amended Phase 2 Stage 6 acceptance" in normalized_remediation
    assert "phase2-stage6-amendment.md" in status


def test_phase2_plan_amendment_explicitly_supersedes_direct_aws_apply_criterion():
    with ZipFile(ROOT / "AWS_Cloud_Security_Guardrails_Phase_2_Final_Plan.docx") as plan:
        document = ET.fromstring(plan.read("word/document.xml"))
    plan_text = " ".join(
        node.text or ""
        for node in document.findall(
            ".//w:t", {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        )
    )
    amendment = (ROOT / "docs/phase2-stage6-amendment.md").read_text(encoding="utf-8")

    assert "Remediation previews can be rescanned; direct apply is sandbox-only." in plan_text
    assert "User-approved Stage 6 read-only acceptance amendment (2026-11-02)" in amendment
    assert "does not implement or claim AWS sandbox apply" in amendment
    assert "remaining Section 13 criteria" in amendment
    assert "supersedes the plan's direct AWS apply acceptance" in amendment


def test_phase2_status_records_live_gatekeeper_acceptance():
    status = (ROOT / "docs/implementation-status.md").read_text(encoding="utf-8")
    normalized_status = " ".join(status.split())

    assert "Gatekeeper live admission acceptance passed on 2026-11-02" in normalized_status
    assert "clean Pod was accepted and the violating Pod was denied" in normalized_status
    assert "Checkov 3.4.3 and Conftest 0.71.1 fixture tests passed" in normalized_status
    assert "Grype findings use shared versioned `Finding` records" in normalized_status
    assert "Stage 6" in normalized_status and "approved read-only amendment" in normalized_status
    assert "Local signed-release acceptance passed on 2026-11-03 UTC" in normalized_status
    assert "A read-only live AWS audit completed on 2026-11-02" in normalized_status
    assert "versioned 1.0.0 contract" in normalized_status
    assert "10 findings and no collection errors" in normalized_status
    assert "Syft 1.55.0, Grype 0.121.0, and Cosign 3.1.4" in normalized_status
    assert "`HIGH` gate passed" in normalized_status
    assert "all five artifact signatures verified" in normalized_status


def test_phase2_status_and_readme_use_generated_coverage_metric():
    metrics = json.loads((ROOT / "results/metrics.json").read_text(encoding="utf-8"))
    coverage = metrics["metrics"]["coverage"]["overall_branch_inclusive_percent"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    status = (ROOT / "docs/implementation-status.md").read_text(encoding="utf-8")
    normalized_status = " ".join(status.split())

    assert coverage >= 86
    assert "PASS (86% CI floor)" in readme
    assert "exact test and coverage values are in `results/metrics.json`" in readme
    assert "exact percentage is recorded" in normalized_status


def test_runbook_describes_gatekeeper_smoke_as_separate_live_check():
    runbook = (ROOT / "docs/operations-runbook.md").read_text(encoding="utf-8")
    normalized_runbook = " ".join(runbook.split())

    assert "not part of the default suite" in normalized_runbook
    assert "exercised separately on 2026-11-02" in normalized_runbook


def test_ci_installs_optional_scanners_before_metrics_collection():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    scanner_install = workflow.index("Install pinned IaC scanners for reproducible metrics")
    coverage = workflow.index("Unit tests and coverage")
    metrics = workflow.index("Metric evidence table")

    assert scanner_install < coverage < metrics
    assert "requirements-scanners.txt" in workflow
    assert "conftest_0.71.1_Linux_x86_64.tar.gz" in workflow
