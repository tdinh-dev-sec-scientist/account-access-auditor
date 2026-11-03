from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_live_console_accepts_only_validated_public_snapshot_fields():
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")

    assert 'snapshot.schema_version !== "1.0.0"' in script
    assert 'new Set(["PASS", "FAIL", "UNKNOWN", "ERROR"])' in script
    assert 'snapshot.findings.length > 2000' in script
    assert "function mapPublicFinding" in script
    assert 'resource: finding.resource_ref' in script
    assert "evidence: {}" in script
    assert 'fetch("/api/latest"' not in script  # latest uses a same-origin URL object with origin verification
    assert 'new URL("/api/latest", window.location.href)' in script
    assert "apiUrl.origin !== window.location.origin" in script


def test_live_console_distinguishes_stale_partial_and_static_kill_switch_states():
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")

    assert 'response.headers.get("X-Phase3-Static-Mode") === "true"' in script
    assert 'latestFreshness.latest_attempt_status' in script
    assert 'latestFreshness.stale' in script
    assert "last-good public snapshot remains available from the API" in script
    assert "showing checked-in Moto reports" in script
    assert 'latestFreshness.publication_paused' in script
    assert "Publication paused" in script


def test_console_has_a_clear_security_and_limitations_view():
    html = (ROOT / "scripts/console/index.html").read_text(encoding="utf-8")
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")

    assert 'data-view="security-limits"' in html
    assert '"security-limits": renderSecurityLimits' in script
    assert "Security &amp; limitations" in html or "Security &amp; limitations" in script
    assert "No live Phase 3 stage gate has passed" in script
    assert "read-only" in script.lower()
    assert "Rin stays disabled" in script
    assert "private snapshot writer" in script


def test_live_rin_sends_one_public_finding_and_never_uses_cross_origin_requests():
    script = (ROOT / "scripts/console/console.js").read_text(encoding="utf-8")

    assert 'fetch("/api/rin"' in script
    assert 'method: "POST"' in script
    assert 'finding_id: finding.publicId' in script
    assert "function getRinSessionToken" in script
    assert "window.crypto.getRandomValues" in script
    assert 'sessionStorage.setItem(key, rinSessionToken)' in script
    assert "raw account identifiers or evidence are sent" in script


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
    assert {path.name for path in output.iterdir()} == {"index.html", "console.css", "console.js"}
    combined = "\n".join(path.read_text(encoding="utf-8") for path in output.iterdir())
    for value in ("123456789012", "arn:aws:iam", "principal_arn", "lab-admin-console-nomfa", "lab-public-assets", "lab-full-admin"):
        assert value not in combined
    assert '"evidence":{}' in combined.replace(" ", "")
    assert "Public snapshot" in combined
    assert "aws_audit_results.json" not in combined
