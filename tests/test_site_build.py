"""The published demo site: its numbers come from the artifacts, not from prose.

The site is the first thing a stranger sees, and it is generated rather than
written, so the risk it carries is a build that renders but lies -- a hardcoded
count, a stale transcript, a placeholder that never got filled in. These tests
pin the page to `results/`.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO_ROOT, "results")


def _module():
    """scripts/ is not a package, so load the builder by path."""
    path = os.path.join(REPO_ROOT, "scripts", "build_site.py")
    spec = importlib.util.spec_from_file_location("build_site", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_site = _module()


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    """Build the site once, into a temporary directory."""
    destination = tmp_path_factory.mktemp("site")
    build_site.SITE = str(destination)
    build_site.main()
    return destination


@pytest.fixture(scope="module")
def index(site):
    return (site / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def runs(index):
    """The JSON the page animates, as the browser would parse it."""
    blob = re.search(r'<script type="application/json" id="run-data">(.*?)</script>', index, re.S)
    assert blob, "the page does not carry its data blob"
    return json.loads(blob.group(1).replace("<\\/", "</"))


@pytest.fixture(scope="module")
def primary():
    with open(os.path.join(RESULTS, "aws_audit_results.json"), encoding="utf-8") as handle:
        return json.load(handle)


def test_the_site_has_the_pages_it_links_to(site):
    for name in ("index.html", "report.html", "aws_audit_results.json", ".nojekyll"):
        assert (site / name).exists(), f"{name} is missing from the built site"


def test_the_headline_count_is_the_one_the_scan_produced(index, primary):
    total = primary["summary"]["total_findings"]
    assert f'<div class="hero" id="total">{total}</div>' in index


def test_every_severity_count_matches_the_report(runs, primary):
    assert runs["misconfigured"]["counts"] == primary["summary"]["by_severity"]
    assert sum(runs["misconfigured"]["counts"].values()) == primary["summary"]["total_findings"]


def test_the_scoring_panel_matches_the_benchmark(runs):
    with open(os.path.join(RESULTS, "expected_vs_actual.json"), encoding="utf-8") as handle:
        scoring = {item["profile"]: item for item in json.load(handle)["profiles"]}
    for profile, run in runs.items():
        assert run["expected"] == scoring[profile]["expected_count"]
        assert run["tp"] == scoring[profile]["true_positives"]
        assert run["fn"] == scoring[profile]["false_negatives"]
        assert run["fp"] == scoring[profile]["false_positives"]


def test_the_transcript_is_captured_from_the_terminal_reporter(runs, primary):
    """Not transcribed: the recording is whatever the real reporter printed."""
    assert runs["misconfigured"]["transcript"] == build_site.transcript(primary)
    assert "Scanning IAM" in "\n".join(runs["misconfigured"]["transcript"])


def test_every_finding_reaches_both_the_table_and_the_data(index, runs, primary):
    assert len(runs["misconfigured"]["findings"]) == len(primary["findings"])
    for finding in primary["findings"]:
        assert finding["resource"] in index


def test_the_stat_tiles_carry_the_ids_the_replay_updates(index):
    """A tile whose value is escaped markup renders a literal tag and never updates."""
    for identifier in ("total", "resources", "api-calls", "duration", "expected", "tp", "fn", "fp"):
        assert f'id="{identifier}"' in index, f"the replay has no hook for {identifier}"
    assert "&lt;span" not in index, "markup was escaped into the page as text"


def test_the_data_blob_cannot_close_the_script_element(index, runs):
    """`</script>` inside the JSON would end the element early and break the page."""
    blob = re.search(r'id="run-data">(.*?)</script>', index, re.S).group(1)
    assert "</" not in blob
    assert runs, "the blob must still parse after escaping"


def test_the_page_says_the_scan_is_a_replay(index):
    """Canned output presented as a live scan would be the one dishonest thing here."""
    assert "This is a replay" in index
    assert "emulated" in index or "moto" in index


def test_both_lab_profiles_are_offered(runs):
    assert set(runs) == {"misconfigured", "no-trail"}
    assert runs["misconfigured"]["total"] > runs["no-trail"]["total"]


def test_read_only_console_is_built_as_a_separate_workspace(site, index):
    console = site / "console"
    assert (console / "index.html").exists()
    assert (console / "console.css").exists()
    assert (console / "status.js").exists()
    assert (console / "knowledge.js").exists()
    assert (console / "console.js").exists()
    assert 'href="console/"' in index


def test_every_local_console_script_reference_is_published(site):
    console = site / "console"
    html = (console / "index.html").read_text(encoding="utf-8")
    scripts = re.findall(r'<script src="([^"]+)" defer></script>', html)
    assert scripts
    assert all((console / script).is_file() for script in scripts)


@pytest.fixture(scope="module")
def console(site):
    return (site / "console" / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def console_data(console):
    blob = re.search(r'<script type="application/json" id="console-data">(.*?)</script>', console, re.S)
    assert blob, "the console does not carry its source data"
    return json.loads(blob.group(1).replace("<\\/", "</"))


def test_console_data_matches_the_read_only_lab_reports(console_data, primary):
    profile = console_data["profiles"]["misconfigured"]
    assert profile["readOnly"] is True
    assert profile["findingCount"] == primary["summary"]["total_findings"]
    assert profile["severityCounts"] == primary["summary"]["by_severity"]
    assert len(profile["findings"]) == len(primary["findings"])
    assert profile["run"]["executionStatus"] == primary["contract"]["scan_run"]["status"]
    assert profile["run"]["gateStatus"] == primary["contract"]["scan_run"]["gate_status"]
    assert profile["findings"][0]["evidence"] == primary["findings"][0]["evidence"]


def test_console_masks_numeric_fixture_account_ids(primary):
    report = json.loads(json.dumps(primary))
    report["contract"]["scan_run"]["account_refs"][0]["id"] = 123456789012
    profile = build_site.console_profile("fixture", "Fixture", report)
    assert profile["accountIdSuffix"] == "9012"


def test_console_exposes_all_modules_and_truthful_empty_states(console, site):
    for view in (
        "overview",
        "aws-accounts",
        "security-scans",
        "findings",
        "drift-history",
        "iac-security",
        "ci-cd",
        "supply-chain",
        "exceptions",
        "ai-analyst",
        "settings",
        "security-limits",
    ):
        assert f'data-view="{view}"' in console
    application = console + (site / "console" / "console.js").read_text(encoding="utf-8")
    assert "Moto emulated account" in application
    assert "Historical snapshots unavailable" in application
    assert "No CI run data" in application
    assert "No artifact assessment data" in application
    assert "AI-generated recommendations are advisory" in application
    assert "Exception workflows are not enabled" in application
    assert "No live Phase 3 stage gate has passed" in application


def test_console_preserves_execution_and_security_gate_as_separate_states(console_data, console):
    run = console_data["profiles"]["misconfigured"]["run"]
    assert run["executionStatus"] == "PASS"
    assert run["findingCount"] > 0
    assert run["gateStatus"] == "NOT_CONFIGURED"
    assert "Execution status does not mean the findings are absent" in console
    assert "NOT CONFIGURED" in console


def test_console_json_blob_cannot_close_its_script_element(console, console_data):
    blob = re.search(r'id="console-data">(.*?)</script>', console, re.S).group(1)
    assert "</" not in blob
    assert console_data["profiles"], "the data remains parseable after escaping"


def test_console_uses_only_its_same_origin_api_and_has_responsive_accessible_styles(site, console):
    script = (site / "console" / "console.js").read_text(encoding="utf-8")
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    assert "connect-src 'self'" in console
    assert "form-action 'none'" in console
    assert 'new URL("/api/latest", window.location.href)' in script
    assert 'fetch("/api/rin"' in script
    assert 'credentials: "omit"' in script
    assert 'redirect: "error"' in script
    assert "XMLHttpRequest" not in script
    assert "@media" in styles
    assert "prefers-reduced-motion" in styles
    assert ":focus-visible" in styles


def test_console_distinguishes_scan_states_and_displays_snapshot_time(site, console):
    script = (site / "console" / "console.js").read_text(encoding="utf-8")
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    for state, marker in (("PASS", "✓"), ("FAIL", "×"), ("UNKNOWN", "?"), ("ERROR", "!")):
        assert f'{state}: "{marker}"' in script
        assert f".status-{state.lower()} .status-marker" in styles
    assert 'id="snapshot-generated-at"' in console
    assert "snapshot-generated-at" in script


def test_console_has_persistent_dark_and_light_modes(console, site):
    script = (site / "console" / "console.js").read_text(encoding="utf-8")
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    assert 'id="theme-toggle"' in console
    assert 'data-theme="dark"' in console
    assert '[data-theme="light"]' in styles
    assert 'setAttribute("data-theme"' in script
    assert "localStorage" in script
    assert "--app-bg: #202326" in styles
    assert "--accent: #c079d2" in styles


def test_console_sidebar_has_desktop_collapse_and_accessible_mobile_drawer(console, site):
    script = (site / "console" / "console.js").read_text(encoding="utf-8")
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    assert 'aria-controls="sidebar"' in console
    assert ".app-frame.is-collapsed" in styles
    assert ".breadcrumb { min-width: 0; flex: 1 1 200px; padding-left: 58px; }" in styles
    assert "aria-hidden" in script
    assert "inert" in script
    assert 'event.key === "Escape"' in script
    assert 'setAttribute("aria-label", "Expand navigation")' in script
    assert 'class="menu-glyph"' in console
    assert '.menu-toggle[aria-expanded="true"] .menu-glyph' in styles
    assert "window.scrollTo(0, 0)" in script
    assert "focus({ preventScroll: true })" in script
    assert console.index("</aside>") < console.index('id="menu-toggle"') < console.index('class="workspace"')


def test_collapsed_sidebar_navigation_items_keep_accessible_names_and_tooltips(console):
    nav_items = re.findall(r'<button class="nav-item[^\"]*"[^>]*>', console)
    assert nav_items
    assert all(re.search(r'aria-label="[^"]+"', item) for item in nav_items)
    assert all(re.search(r'title="[^"]+"', item) for item in nav_items)


def test_console_assistant_keeps_local_fallback_and_gates_live_rin(console, site):
    script = (site / "console" / "console.js").read_text(encoding="utf-8")
    assert 'id="assistant-dialog"' in console
    assert 'id="assistant-launcher"' in console
    assert (
        console.index('class="topbar"')
        < console.index("</header>")
        < console.index('id="assistant-launcher"')
    )
    assert console.index('id="assistant-launcher"') < console.index('id="assistant-dialog"')
    assert re.search(
        r"\.assistant-launcher\s*\{[^}]*position:\s*fixed[^}]*right:\s*24px[^}]*bottom:\s*22px",
        (site / "console" / "console.css").read_text(encoding="utf-8"),
        re.S,
    )
    assert 'id="assistant-form"' in console
    assert "Fixture answers stay in this browser" in console
    assert "provider optional" in script
    assert "answerFromFixture" in script
    assert "severityCounts" in script
    assert 'fetch("/api/rin"' in script
    assert "XMLHttpRequest" not in script
    assert "connect-src 'self'" in console


def test_console_uses_the_vorrin_brand_in_the_title_and_navigation(console):
    assert "<title>Security Overview · Vorrin</title>" in console
    assert 'aria-label="Vorrin Cloud Security home"' in console
    assert '<span class="brand-copy"><strong>Vorrin</strong><small>Cloud Security</small></span>' in console


def test_console_names_rin_and_keeps_the_assistant_grounded(console, site):
    script = (site / "console" / "console.js").read_text(encoding="utf-8")
    assert '<h2 id="assistant-title">Rin</h2>' in console
    assert "I follow the evidence. I don't guess." in console
    assert "I keep the evidence close and the guesses out." in script
    assert "I only receive one redacted finding at a time" in console
    assert "Fixture mode · no model calls" in console
    assert 'class="assistant-avatar-stage" aria-hidden="true"' in console


def test_console_supports_keyboard_skip_and_touch_sized_navigation(console, site):
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    assert '<a class="skip-link" href="#main-content">Skip to main content</a>' in console
    assert re.search(r"\.skip-link:focus-visible\s*\{", styles)
    assert re.search(r"\.nav-item\s*\{[^}]*min-height:\s*44px", styles, re.S)
    assert re.search(r"\.menu-toggle\s*\{[^}]*min-width:\s*44px[^}]*min-height:\s*44px", styles, re.S)


def test_console_uses_local_sysdig_inspired_type_and_a_reduced_motion_3d_mascot(console, site):
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    assert 'font-family: "Avenir Next", "SF Pro Display", ui-sans-serif, system-ui, sans-serif' in styles
    assert "font-family: Inter" not in styles
    assert re.search(r"\.nav-item\s*\{[^}]*font-size:\s*14px", styles, re.S)
    assert "fonts.googleapis.com" not in styles
    assert ".assistant-avatar-face" in styles
    assert "perspective: 150px" in styles
    assert "clip-path: polygon" in styles
    assert "--motion-smooth: cubic-bezier(.22, 1, .36, 1)" in styles
    assert ".assistant-launcher-orb" in styles and "position: fixed" in styles
    assert "@media (prefers-reduced-motion: reduce)" in styles


def test_landing_page_uses_the_vorrin_brand(index):
    assert "<title>Vorrin · AWS Account &amp; Access Configuration Auditor</title>" in index
    assert "<h1>Vorrin</h1>" in index


def test_console_type_never_drops_below_ten_pixels_and_mobile_body_is_sixteen(console, site):
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    pixel_sizes = [int(size) for size in re.findall(r"font-size:\s*(\d+)px", styles)]
    assert min(pixel_sizes) >= 12
    assert "body { font-size: 16px; }" in styles


def test_dark_primary_action_text_meets_wcag_aa_contrast(console, site):
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    dark_tokens = styles.split(':root[data-theme="light"]', maxsplit=1)[0]
    foreground = re.search(r"--accent-text:\s*(#[0-9a-fA-F]{6})", dark_tokens).group(1)
    background = re.search(r"--accent-strong:\s*(#[0-9a-fA-F]{6})", dark_tokens).group(1)

    def luminance(color):
        channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
    assert (light + 0.05) / (dark + 0.05) >= 4.5


def test_console_footer_does_not_imply_an_ai_result_exists(console):
    assert "AI features are optional; recommendations are advisory." in console
    assert "AI-generated recommendations are advisory" not in console


def test_light_theme_dim_text_meets_wcag_aa_contrast(console, site):
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    light_tokens = styles.split(':root[data-theme="light"]', maxsplit=1)[1].split("}", maxsplit=1)[0]
    foreground = re.search(r"--text-dim:\s*(#[0-9a-fA-F]{6})", light_tokens).group(1)
    background = re.search(r"--app-bg:\s*(#[0-9a-fA-F]{6})", light_tokens).group(1)

    def luminance(color):
        channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
    assert (light + 0.05) / (dark + 0.05) >= 4.5


def test_topbar_inputs_and_floating_assistant_have_accessible_targets(console, site):
    styles = (site / "console" / "console.css").read_text(encoding="utf-8")
    assert re.search(r"\.search-box\s*\{[^}]*min-height:\s*44px", styles, re.S)
    assert re.search(r"\.scope-select-wrap select\s*\{[^}]*min-height:\s*44px", styles, re.S)
    assert re.search(r"\.assistant-launcher\s*\{[^}]*min-height:\s*64px", styles, re.S)
    assert not re.search(r"\.assistant-launcher\s*\{[^}]*\bwidth:\s*40px", styles)
    assert not re.search(r"\.assistant-launcher\s*\{[^}]*\bflex:\s*0 0 40px", styles)
