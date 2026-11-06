"""One test per Stage 2 redaction category.

scripts/collect_phase3_stage2_evidence.py runs this file and records a
category as passed only when its test passes, so keep the
``test_case_<category>`` names in step with phase3.stage_evidence.
"""

from __future__ import annotations

import pytest

from phase3.redaction import PublicSnapshotError, redact_snapshot, validate_public_snapshot
from tests.test_phase3_redaction import HMAC_KEY, _report

ACCOUNT_ID = "123456789012"


def _publish(report, key=HMAC_KEY):
    public = redact_snapshot(report, key)
    assert validate_public_snapshot(public) is None
    return public


def _fails_closed(text):
    report = _report()
    report["contract"]["findings"][0]["description"] = f"Demo evidence includes {text}."
    with pytest.raises(PublicSnapshotError, match="sensitive pattern"):
        redact_snapshot(report, HMAC_KEY)


def test_case_account_id():
    public = repr(_publish(_report()))
    assert ACCOUNT_ID not in public
    assert "account_id" not in public


def test_case_arn():
    report = _report()
    report["contract"]["findings"][0]["evidence"] = {
        "principal_arn": f"arn:aws:iam::{ACCOUNT_ID}:role/private-role",
        "bucket_arn": "arn:aws:s3:::company-private-bucket",
    }
    public = repr(_publish(report))
    assert "arn:aws" not in public
    assert "private-role" not in public
    assert "company-private-bucket" not in public


def test_case_ip_address():
    _fails_closed("198.51.100.42")


def test_case_email():
    _fails_closed("analyst@example.com")


def test_case_access_key():
    _fails_closed("AKIA" + "1234567890ABCDEF")


def test_case_unknown_field():
    report = _report()
    report["contract"]["findings"][0]["unexpected_private_field"] = "never-public-value"
    report["unknown_top_level"] = "never-public-value"
    public = repr(_publish(report))
    assert "unexpected_private_field" not in public
    assert "unknown_top_level" not in public
    assert "never-public-value" not in public


def test_case_stable_pseudonym():
    first = _publish(_report())
    again = _publish(_report())
    other_key = _publish(_report(), key=b"another-test-key-material-of-32-bytes!!")
    finding_id = first["findings"][0]["id"]
    assert finding_id == again["findings"][0]["id"]
    assert finding_id != other_key["findings"][0]["id"]
    assert first["findings"][0]["resource_ref"] == again["findings"][0]["resource_ref"]
    assert first["findings"][0]["resource_ref"] != other_key["findings"][0]["resource_ref"]
