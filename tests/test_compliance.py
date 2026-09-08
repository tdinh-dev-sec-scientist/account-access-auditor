"""The CIS mapping: its integrity, and the honesty of the count derived from it."""

from __future__ import annotations

import json

import pytest

from auditor import compliance
from auditor.rules import registry


def test_mapping_loads_and_names_its_benchmark_version():
    document = compliance.load_mapping()
    assert document["benchmark"]["name"].startswith("CIS")
    assert compliance.benchmark_version() == "3.0.0"


def test_mapping_has_exactly_one_entry_per_registered_rule():
    mapped_ids = {entry["rule_id"] for entry in compliance.entries()}
    assert mapped_ids == set(registry.rule_ids())
    assert len(compliance.entries()) == 14


def test_every_entry_records_a_rationale_for_its_status():
    for entry in compliance.entries():
        assert len(entry["rationale"]) > 80, (
            f"{entry['rule_id']}: a mapping decision needs a defensible justification"
        )


def test_mapped_entries_name_a_control_and_unmapped_ones_do_not():
    for entry in compliance.entries():
        if entry["status"] == compliance.MAPPED:
            assert entry["control_id"] and entry["control_title"]
        elif entry["status"] == compliance.UNMAPPED:
            assert entry["control_id"] is None


def test_the_headline_count_counts_only_direct_mappings():
    """`partial` entries are documented but must never inflate the metric."""
    counts = compliance.status_counts()
    assert compliance.mapped_count() == counts["mapped"]
    assert compliance.mapped_count() < len(compliance.entries())
    partial = [e["rule_id"] for e in compliance.entries() if e["status"] == compliance.PARTIAL]
    assert partial, "the mapping should record related-but-not-equivalent controls honestly"
    assert not set(partial) & set(compliance.mapped_rule_ids())


def test_mapped_count_matches_the_committed_file():
    with open(compliance.MAPPING_PATH, encoding="utf-8") as handle:
        document = json.load(handle)
    expected = sum(1 for entry in document["rules"] if entry["status"] == "mapped")
    assert compliance.mapped_count() == expected == 11


def test_control_ids_look_like_cis_section_numbers():
    for entry in compliance.entries():
        if entry["control_id"]:
            parts = entry["control_id"].split(".")
            assert 2 <= len(parts) <= 3
            assert all(part.isdigit() for part in parts), entry["control_id"]


def test_compliance_block_is_embedded_in_every_finding():
    block = compliance.compliance_block("CT-003")
    assert block["control_id"] == "3.2"
    assert "v3.0.0" in block["framework"]
    assert block["status"] == "mapped"


def test_unknown_rule_gets_an_explicit_unmapped_block_not_a_crash():
    assert compliance.compliance_block("NOPE-1")["status"] == "unmapped"


def test_a_missing_mapping_file_is_an_explicit_error():
    with pytest.raises(compliance.ComplianceMappingError, match="not found"):
        compliance.load_mapping("/nonexistent/cis_mapping.json")


def test_a_malformed_mapping_file_is_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps({"benchmark": {"version": "3.0.0"}, "rules": [{"rule_id": "X", "status": "mapped"}]})
    )
    with pytest.raises(compliance.ComplianceMappingError, match="missing keys"):
        compliance.load_mapping(str(bad))


def test_a_mapped_entry_without_a_control_is_rejected(tmp_path):
    bad = tmp_path / "bad2.json"
    bad.write_text(
        json.dumps(
            {
                "benchmark": {"name": "CIS", "version": "3.0.0"},
                "rules": [
                    {
                        "rule_id": "X",
                        "finding": "f",
                        "control_id": None,
                        "control_title": None,
                        "status": "mapped",
                        "rationale": "r",
                    }
                ],
            }
        )
    )
    with pytest.raises(compliance.ComplianceMappingError, match="marked mapped"):
        compliance.load_mapping(str(bad))
