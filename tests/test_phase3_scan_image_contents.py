"""The scan image must contain every file a scan reads at runtime.

The test copies only the paths Dockerfile.phase3-scan COPYs into an empty
directory and runs a fleet scan from there in a subprocess, so a data file
missing from the image shows up here instead of as UNKNOWN scans in AWS.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCAN = r"""
import json, sys
app = sys.argv[1]
sys.path.insert(0, app)
import boto3
from moto import mock_aws
from auditor import fleet_scan
from auditor.config import defaults
from auditor.fleet import FleetConfig, TargetAccount

assert fleet_scan.__file__.startswith(app), fleet_scan.__file__
with mock_aws():
    session = boto3.session.Session(region_name="us-east-1")
    session.client("s3").create_bucket(Bucket="demo-a")
    session.client("iam").create_user(UserName="alice")
    account = session.client("sts").get_caller_identity()["Account"]
    config = FleetConfig(
        accounts=(TargetAccount(account, f"arn:aws:iam::{account}:role/AccountAccessAuditorReadOnly"),),
        regions=("us-east-1",),
        services=("iam", "s3", "cloudtrail"),
    )
    fleet_scan._assume_role = lambda _source, **kw: (boto3.session.Session(region_name=kw["region_name"]), None)
    report = fleet_scan.run_fleet_scan(config, defaults(), session, run_id="image-contents")
    print(json.dumps({
        "status": report["contract"]["scan_run"]["status"],
        "errors": [error.get("code") for error in report.get("collection_errors", [])],
    }))
"""


def _copied_paths() -> list[str]:
    dockerfile = (ROOT / "Dockerfile.phase3-scan").read_text(encoding="utf-8")
    sources = []
    for line in dockerfile.splitlines():
        match = re.match(r"COPY\s+(?:--\S+\s+)*(\S+)\s+/app/", line)
        if match and not match.group(1).endswith(".txt"):
            sources.append(match.group(1))
    return sources


def test_the_image_copies_the_cis_mapping():
    assert {"auditor", "phase3", "compliance"} <= set(_copied_paths())


def test_a_scan_from_only_the_image_files_completes_without_errors(tmp_path):
    app = tmp_path / "app"
    for source in _copied_paths():
        shutil.copytree(ROOT / source, app / source, ignore=shutil.ignore_patterns("__pycache__"))
    result = subprocess.run(
        [sys.executable, "-c", SCAN, str(app)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    assert outcome == {"status": "PASS", "errors": []}
