from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_live_console_accepts_only_validated_public_snapshot_fields():
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")

    assert 'snapshot.schema_version !== "2.0.0"' in script
    assert 'new Set(["PASS", "FAIL", "UNKNOWN", "ERROR"])' in script
    assert "snapshot.findings.length > 2000" in script
    assert "function mapPublicFinding" in script
    assert "resource: finding.resource_ref" in script
    assert "function mapPublicEvidenceSummary" in script
    assert "evidence: mapPublicEvidenceSummary(finding.evidence_summary)" in script
    assert (
        'fetch("/api/latest"' not in script
    )  # latest uses a same-origin URL object with origin verification
    assert 'new URL("/api/latest", window.location.href)' in script
    assert "apiUrl.origin !== window.location.origin" in script


def test_live_console_distinguishes_stale_partial_and_static_kill_switch_states():
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")
    status = (ROOT / "scripts/console/status.js").read_text(encoding="utf-8")

    assert 'response.headers.get("X-Phase3-Static-Mode") === "true"' in script
    assert "statusUi.render(document, statusUi.staticMode())" in script
    assert "statusUi.render(document, statusUi.apiUnavailable())" in script
    assert "statusUi.liveSnapshot" in script
    assert "statusUi.renderRinFallback" in script
    assert "The last complete public snapshot remains available" in status


def test_console_status_renderer_displays_failure_fixtures():
    result = subprocess.run(
        ["node", "--test", str(ROOT / "tests/phase3_console_status.test.cjs")],
        check=False,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_console_platform_knowledge_corpus():
    result = subprocess.run(
        ["node", "--test", str(ROOT / "tests/phase3_platform_knowledge.test.cjs")],
        check=False,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_console_navigation_accessibility_regressions():
    result = subprocess.run(
        ["node", "--test", str(ROOT / "tests/phase3_console_navigation.test.cjs")],
        check=False,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_console_has_a_clear_security_and_limitations_view():
    html = (ROOT / "scripts/console/index.html").read_text(encoding="utf-8")
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")
    styles = (ROOT / "scripts/console/console.css").read_text(encoding="utf-8")

    assert 'data-view="security-limits"' in html
    assert '"security-limits": renderSecurityLimits' in script
    assert "Security &amp; limitations" in html or "Security &amp; limitations" in script
    assert "No live Phase 3 stage gate has passed" in script
    assert "read-only" in script.lower()
    assert "Rin stays disabled" in script
    assert "private snapshot writer" in script
    assert "Actual AWS role-policy captures are still pending review" in script
    assert "infra/phase3/policies/target-readonly.json" in script
    assert "tests/test_phase3_redaction.py" in script
    assert "docs/phase3-status.md" in script
    assert 'link.rel = "noopener noreferrer"' in script
    assert "module-evidence-links" in script
    assert re.search(r"\.module-evidence-link\s*\{[^}]*min-height:\s*44px", styles)


def test_live_rin_sends_one_public_finding_and_never_uses_cross_origin_requests():
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")

    assert 'fetch("/api/rin"' in script
    assert 'method: "POST"' in script
    assert "finding_id: finding.publicId" in script
    assert "function getRinSessionToken" in script
    assert "window.crypto.getRandomValues" in script
    assert "sessionStorage.setItem(key, rinSessionToken)" in script
    assert "safe evidence summary" in script


def test_live_rin_unavailable_path_uses_a_prepared_fixture_answer():
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")

    assert 'answerFromFixture(question, "misconfigured")' in script
    assert "statusUi.renderRinFallback(bubble, answer.text, answer.source)" in script


def test_rin_uses_local_approved_knowledge_for_general_platform_questions():
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")
    html = (ROOT / "scripts/console/index.html").read_text(encoding="utf-8")

    assert "const platformKnowledge = window.Phase3PlatformKnowledge" in script
    assert "platformKnowledge.answerPlatformQuestion(question)" in script
    assert 'src="knowledge.js"' in html
    assert html.index('src="knowledge.js"') < html.index('src="console.js"')


def test_phase3_deploy_bundle_contains_only_allowlisted_console_assets(tmp_path):
    output = tmp_path / "phase3-web"
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_phase3_web.py"), "--output", str(output)],
        check=False,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert {path.name for path in output.iterdir()} == {
        "index.html",
        "console.css",
        "console.js",
        "status.js",
        "knowledge.js",
        "auth.js",
    }
    built_html = (output / "index.html").read_text(encoding="utf-8")
    built_script = (output / "console.js").read_text(encoding="utf-8")
    built_styles = (output / "console.css").read_text(encoding="utf-8")
    assert built_html.index('src="status.js"') < built_html.index('src="console.js"')
    assert built_html.index('src="knowledge.js"') < built_html.index('src="console.js"')
    assert built_html.index('src="auth.js"') < built_html.index('src="console.js"')
    assert "Repository links show local design and tests, not live AWS proof" in built_script
    assert "Rin IAM policy" in built_script
    assert 'item.dataset.label = item.getAttribute("aria-label")' in built_script
    assert "workspace.inert = open" in built_script
    assert re.search(r"\.module-evidence-link\s*\{[^}]*min-height:\s*44px", built_styles)
    combined = "\n".join(path.read_text(encoding="utf-8") for path in output.iterdir())
    for value in (
        "123456789012",
        "arn:aws:iam",
        "principal_arn",
        "lab-admin-console-nomfa",
        "lab-public-assets",
        "lab-full-admin",
    ):
        assert value not in combined
    assert '"evidence":{"policy_is_aws_managed":false,"statement_count":1}' in combined.replace(" ", "")
    assert '"principal_arn"' not in combined
    assert "Public snapshot" in combined
    assert "aws_audit_results.json" not in combined
