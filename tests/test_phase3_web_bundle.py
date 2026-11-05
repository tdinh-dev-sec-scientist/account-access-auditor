"""The fixture profiles in the Phase 3 static console pass the public allowlist."""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from phase3.web_bundle import safe_fixture_profile
from scripts.build_phase3_web import build_web_bundle

ROOT = Path(__file__).resolve().parents[1]
KEY = b"k" * 32
HOSTED_UI = "https://vorrin-console.auth.us-east-1.amazoncognito.com"


def _report(name: str = "aws_audit_results.json") -> dict[str, Any]:
    return json.loads((ROOT / "results" / name).read_text(encoding="utf-8"))


def _profile(report: dict[str, Any]) -> dict[str, Any]:
    return safe_fixture_profile(report, key="misconfigured", label="Misconfigured", pseudonym_key=KEY)


def test_profile_keeps_counts_and_severities_from_the_saved_report():
    report = _report()
    profile = _profile(report)

    assert profile["key"] == "misconfigured"
    assert profile["readOnly"] is True
    assert profile["findingCount"] == len(report["findings"]) == 25
    assert sum(profile["severityCounts"].values()) == profile["findingCount"]
    assert sorted(item["severity"] for item in profile["findings"]) == sorted(
        item["severity"] for item in report["findings"]
    )
    assert set(profile["servicesScanned"]) == {"iam", "s3", "cloudtrail"}
    assert profile["run"]["scanSource"] == "Saved Moto fixture"


def test_profile_does_not_leak_account_ids_resource_names_or_access_keys():
    report = _report()
    serialized = json.dumps(_profile(report))

    assert report["metadata"]["account_id"] not in serialized
    assert "lab-admin-console-nomfa" not in serialized
    assert "lab-public-assets" not in serialized
    assert "AKIA" not in serialized


def test_profile_pseudonyms_are_stable_for_a_key_and_change_with_it():
    report = _report()
    first = _profile(report)
    second = _profile(copy.deepcopy(report))
    rekeyed = safe_fixture_profile(
        report, key="misconfigured", label="Misconfigured", pseudonym_key=b"z" * 32
    )

    assert [item["publicId"] for item in first["findings"]] == [
        item["publicId"] for item in second["findings"]
    ]
    assert {item["publicId"] for item in first["findings"]}.isdisjoint(
        item["publicId"] for item in rekeyed["findings"]
    )


def test_profile_handles_the_no_trail_fixture():
    profile = _profile(_report("aws_audit_results_no-trail.json"))

    assert profile["findingCount"] == 1
    assert profile["findings"][0]["ruleId"]


def _drop_metadata(report: dict[str, Any]) -> None:
    report["metadata"] = None


def _short_account(report: dict[str, Any]) -> None:
    report["metadata"]["account_id"] = "1234"


def _no_scan_run(report: dict[str, Any]) -> None:
    report["contract"] = {}


def _findings_not_a_list(report: dict[str, Any]) -> None:
    report["findings"] = {}


def _unsupported_service(report: dict[str, Any]) -> None:
    report["metadata"]["services_scanned"] = ["EC2"]


def _finding_not_an_object(report: dict[str, Any]) -> None:
    report["findings"] = ["not a finding"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_drop_metadata, "fixture report is invalid"),
        (_short_account, "fixture report is invalid"),
        (_no_scan_run, "fixture report is invalid"),
        (_findings_not_a_list, "fixture report is invalid"),
        (_unsupported_service, "unsupported service"),
        (_finding_not_an_object, "fixture finding is invalid"),
    ],
)
def test_profile_rejects_malformed_reports(change, message):
    report = _report()
    change(report)

    with pytest.raises(ValueError, match=message):
        _profile(report)


def test_profile_rejects_a_non_object_report():
    with pytest.raises(ValueError, match="fixture report is invalid"):
        _profile([])  # type: ignore[arg-type]


def _meta_csp(html: str) -> str:
    return re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1)


def test_bundle_meta_csp_allows_only_the_configured_hosted_ui(tmp_path):
    output = build_web_bundle(tmp_path / "web", auth_origin=HOSTED_UI)
    csp = _meta_csp((output / "index.html").read_text(encoding="utf-8"))

    assert f"connect-src 'self' {HOSTED_UI};" in csp
    assert "script-src 'self';" in csp


def test_bundle_without_sign_in_keeps_connect_src_self(tmp_path):
    output = build_web_bundle(tmp_path / "web")

    assert "connect-src 'self';" in _meta_csp((output / "index.html").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "origin",
    [
        "https://attacker.example",
        "http://vorrin-console.auth.us-east-1.amazoncognito.com",
        "https://vorrin-console.auth.us-east-1.amazoncognito.com/",
        "https://vorrin-console.auth.us-east-1.amazoncognito.com.attacker.example",
        "https://x.auth.us-east-1.amazoncognito.com; script-src *",
        "https://vorrin-console.auth.us-east-1.amazoncognito.com 'unsafe-inline'",
    ],
)
def test_bundle_rejects_anything_but_a_cognito_hosted_ui_origin(tmp_path, origin):
    with pytest.raises(ValueError, match="Cognito Hosted UI origin"):
        build_web_bundle(tmp_path / "web", auth_origin=origin)
    assert not (tmp_path / "web").exists()


def test_bundle_cli_reports_an_invalid_origin(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/build_phase3_web.py"),
            "--output",
            str(tmp_path / "web"),
            "--auth-origin",
            "https://attacker.example",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "Cognito Hosted UI origin" in result.stderr
