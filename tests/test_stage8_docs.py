from __future__ import annotations

import json
import re
from pathlib import Path


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


def test_readme_and_status_do_not_claim_phase2_release_completion():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    status = (ROOT / "docs/implementation-status.md").read_text(encoding="utf-8")
    remediation = (ROOT / "docs/remediation.md").read_text(encoding="utf-8")

    assert "Phase 2 is not release-complete" in readme
    assert "Phase 2 is not release-complete" in status
    assert "Phase 3 has not started" in status
    assert "criterion remains unmet" in remediation


def test_phase2_status_records_live_gatekeeper_acceptance():
    status = (ROOT / "docs/implementation-status.md").read_text(encoding="utf-8")
    normalized_status = " ".join(status.split())

    assert "Gatekeeper live admission acceptance passed on 2026-11-02" in normalized_status
    assert "clean Pod was accepted and the violating Pod was denied" in normalized_status
    assert "Checkov 3.4.3 and Conftest 0.71.1 fixture tests passed" in normalized_status
    assert "Grype findings use shared versioned `Finding` records" in normalized_status
    assert "Stage 6" in normalized_status and "read-only deviation" in normalized_status
    assert "Syft, Grype, and Cosign binaries are unavailable" in normalized_status
    assert "sandbox policy denied access to the Docker daemon" in normalized_status


def test_phase2_status_and_readme_use_generated_coverage_metric():
    metrics = json.loads((ROOT / "results/metrics.json").read_text(encoding="utf-8"))
    coverage = f"{metrics['metrics']['coverage']['overall_branch_inclusive_percent']:.2f}%"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    status = (ROOT / "docs/implementation-status.md").read_text(encoding="utf-8")

    assert coverage in readme
    assert coverage in status


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
    assert "conftest_0.71.1_Linux_amd64.tar.gz" in workflow
