from __future__ import annotations

import copy
import re

import pytest

from phase3.redaction import PublicSnapshotError, _pseudonym, redact_snapshot, validate_public_snapshot


HMAC_KEY = b"p3-test-key-material-with-at-least-32-bytes"
SECRET_KEY_ASSIGNMENT = "AWS_SECRET_" + "ACCESS_KEY"


def _finding(**updates):
    record = {
        "fingerprint": "a111111111111111",
        "control_id": "S3-001",
        "scanner": "account-access-auditor",
        "scanner_rule_id": "S3-001",
        "source_type": "aws",
        "resource_reference": "bucket:company-private-bucket",
        "severity": "HIGH",
        "title": "Bucket public access protection is incomplete",
        "description": "Two bucket-level public access controls are disabled.",
        "evidence": {"principal_arn": "arn:aws:iam::123456789012:user/alice"},
        "remediation": "Enable all four bucket public access block settings.",
        "references": [
            {"type": "compliance", "framework": "CIS AWS Foundations", "id": "2.1.5", "title": "Protect S3 buckets"}
        ],
        "lifecycle_state": "open",
        "detected_at": "2026-11-02T10:00:00+00:00",
        "account_ref": {"provider": "aws", "id": "123456789012"},
        "service": "s3",
        "region": "us-east-1",
    }
    record.update(updates)
    return record


def _report():
    finding = _finding()
    return {
        "metadata": {
            "scan_source": "aws-fleet",
            "scan_coverage": [
                {"account_id": "123456789012", "service": "s3", "region": "us-east-1", "complete": True}
            ],
            "unknown_internal_metadata": {"secret": "never-public"},
        },
        "summary": {"status": "FAIL", "total_findings": 1, "drift": {"new": 1}},
        "collection_errors": [{"message": "internal error containing private data"}],
        "contract": {
            "schema_version": "1.0.0",
            "scan_run": {
                "run_id": "run-secret-identifier",
                "scan_source": "aws-fleet",
                "started_at": "2026-11-02T09:59:00+00:00",
                "completed_at": "2026-11-02T10:00:00+00:00",
                "status": "FAIL",
                "gate_status": "FAIL",
                "regions": ["us-east-1"],
                "scanner_versions": {"account-access-auditor": "1.0.0"},
            },
            "findings": [finding],
        },
        "drift": [{"state": "new", "finding": finding, "account_id": "123456789012"}],
        "unknown_top_level": "must be dropped",
    }


def test_redaction_keeps_only_public_allowlist_and_stable_keyed_pseudonyms():
    report = _report()
    public = redact_snapshot(report, HMAC_KEY)
    again = redact_snapshot(report, HMAC_KEY)
    encoded = repr(public)

    assert public == again
    assert public["scan"]["status"] == "FAIL"
    assert public["summary"]["total_findings"] == 1
    assert public["findings"][0]["id"] == again["findings"][0]["id"]
    assert public["findings"][0]["resource_ref"].startswith("resource-")
    assert "evidence" not in public["findings"][0]
    assert "account_id" not in encoded
    assert "123456789012" not in encoded
    assert "arn:aws" not in encoded
    assert "company-private-bucket" not in encoded
    assert "unknown_internal_metadata" not in encoded
    assert "never-public" not in encoded
    assert "unknown_top_level" not in encoded
    assert "internal error" not in encoded
    assert validate_public_snapshot(public) is None


def test_redaction_rejects_secret_patterns_in_public_text_and_unknown_fields_stay_dropped():
    report = _report()
    report["contract"]["findings"][0]["description"] = f"{SECRET_KEY_ASSIGNMENT}=not-a-real-key"
    with pytest.raises(PublicSnapshotError, match="sensitive pattern"):
        redact_snapshot(report, HMAC_KEY)

    clean = _report()
    clean["contract"]["findings"][0]["unexpected"] = "private"
    public = redact_snapshot(clean, HMAC_KEY)
    assert "unexpected" not in repr(public)


def test_redaction_rejects_short_key_and_invalid_scan_contract():
    with pytest.raises(PublicSnapshotError, match="at least 32 bytes"):
        redact_snapshot(_report(), b"short")
    malformed = _report()
    malformed["contract"]["scan_run"]["status"] = "CLEAN"
    with pytest.raises(PublicSnapshotError, match="fleet contract"):
        redact_snapshot(malformed, HMAC_KEY)


def test_redaction_removes_resource_and_principal_names_embedded_in_allowed_prose():
    report = _report()
    finding = report["contract"]["findings"][0]
    finding["resource_reference"] = "bucket:lab-public-assets"
    finding["evidence"] = {
        "bucket_name": "lab-public-assets",
        "principal_name": "alice-admin",
        "policy_name": "lab-full-admin",
    }
    finding["title"] = "Bucket lab-public-assets has a public policy"
    finding["description"] = "The IAM user 'alice-admin' has a policy 'lab-full-admin' on bucket 'lab-public-assets'."
    finding["remediation"] = "Update lab-public-assets after reviewing the lab-full-admin policy."

    public = redact_snapshot(report, HMAC_KEY)
    text = repr(public)

    for private_value in ("lab-public-assets", "alice-admin", "lab-full-admin"):
        assert private_value not in text
    assert "[redacted]" in text


def test_public_schema_rejects_extra_fields_or_unsafe_identifiers():
    public = redact_snapshot(_report(), HMAC_KEY)
    with pytest.raises(PublicSnapshotError, match="schema"):
        validate_public_snapshot({**public, "account_id": "123456789012"})
    mutated = copy.deepcopy(public)
    mutated["findings"][0]["resource_ref"] = "arn:aws:s3:::secret"
    with pytest.raises(PublicSnapshotError, match="schema"):
        validate_public_snapshot(mutated)


def test_valid_hmac_pseudonym_with_twelve_decimal_digits_is_not_treated_as_an_account_id():
    resource_reference = "bucket:company-private-bucket"
    key = None
    for index in range(10000):
        candidate = index.to_bytes(32, "big")
        token = _pseudonym(candidate, "resource", resource_reference)
        if re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", token):
            key = candidate
            break
    assert key is not None, "the deterministic test-key search should find a matching pseudonym"

    public = redact_snapshot(_report(), key)

    assert public["findings"][0]["resource_ref"].startswith("resource-")
    assert validate_public_snapshot(public) is None
    mutated = copy.deepcopy(public)
    mutated["drift"][0]["finding"]["account_name"] = "Production"
    with pytest.raises(PublicSnapshotError, match="schema"):
        validate_public_snapshot(mutated)
    mutated = copy.deepcopy(public)
    mutated["findings"][0]["resource_ref"] = "friendly-resource-name"
    with pytest.raises(PublicSnapshotError, match="schema"):
        validate_public_snapshot(mutated)
