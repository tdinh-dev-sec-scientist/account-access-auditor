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
