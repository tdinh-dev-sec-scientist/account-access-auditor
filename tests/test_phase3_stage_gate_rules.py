"""Schema and review-record rejection rules of the Phase 3 stage gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phase3.stage_gates import StageGateError, validate_stage_gates
from tests.test_phase3_stage_gates import _write_manifest


def _edit(manifest: Path, change) -> None:
    value = json.loads(manifest.read_text(encoding="utf-8"))
    change(value)
    manifest.write_text(json.dumps(value), encoding="utf-8")


def _stage1(change):
    def apply(value):
        change(value["stages"]["stage1"])

    return apply


@pytest.mark.parametrize(
    ("stages", "message"),
    [
        ({1}, "must be a subset of 2, 3, and 4"),
        ({True}, "must be a subset of 2, 3, and 4"),
        ({3}, "Stage 3 also requires Stage 2"),
        ({2, 4}, "Stage 4 also requires Stage 2 and Stage 3"),
    ],
)
def test_enabled_stage_sets_must_be_consistent(tmp_path, stages, message):
    manifest = _write_manifest(tmp_path)

    with pytest.raises(StageGateError, match=message):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages=stages)


def test_a_missing_manifest_blocks_every_stage(tmp_path):
    with pytest.raises(StageGateError, match="missing or invalid"):
        validate_stage_gates(tmp_path / "absent.json", root=tmp_path, enabled_stages=set())


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(schema_version=2),
        lambda value: value.update(schema_version=True),
        lambda value: value["stages"].pop("stage4"),
        lambda value: value.update(extra=True),
    ],
)
def test_manifest_schema_is_enforced(tmp_path, change):
    manifest = _write_manifest(tmp_path)
    _edit(manifest, change)

    with pytest.raises(StageGateError, match="does not match its schema"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages=set())


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda record: record.pop("reviewed_at"), "record does not match its schema"),
        (lambda record: record.update(status="approved"), "invalid acceptance status"),
        (lambda record: record.update(criteria={}), "criteria do not match the plan"),
        (
            lambda record: record.update(criteria=dict.fromkeys(record["criteria"], "yes")),
            "criteria must be boolean",
        ),
    ],
)
def test_stage_record_schema_is_enforced(tmp_path, change, message):
    manifest = _write_manifest(tmp_path)
    _edit(manifest, _stage1(change))

    with pytest.raises(StageGateError, match=message):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages=set())


def test_a_pending_stage_cannot_claim_a_reviewer(tmp_path):
    manifest = _write_manifest(tmp_path)
    _edit(manifest, _stage1(lambda record: record.update(reviewed_by="someone")))

    with pytest.raises(StageGateError, match="pending stage1 cannot claim acceptance evidence"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages=set())


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda record: record.update(reviewed_by=" "), "requires a reviewer"),
        (lambda record: record.update(reviewed_by="r" * 121), "requires a reviewer"),
        (lambda record: record.update(reviewed_at=None), "requires a review timestamp"),
        (lambda record: record.update(reviewed_at="last week"), "invalid review timestamp"),
        (lambda record: record.update(reviewed_at="2026-11-03T00:00:00"), "must include a timezone"),
        (
            lambda record: record["criteria"].update({next(iter(record["criteria"])): False}),
            "incomplete plan acceptance criteria",
        ),
        (lambda record: record.update(evidence=[]), "distinct, checked-in evidence files"),
        (
            lambda record: record.update(evidence=record["evidence"] * 2),
            "distinct, checked-in evidence files",
        ),
        (
            lambda record: record.update(evidence=[*record["evidence"], "stage2/other.json"]),
            "invalid evidence path",
        ),
        (
            lambda record: record.update(evidence_sha256={}),
            "requires a digest for every reviewed evidence file",
        ),
        (
            lambda record: record["evidence_sha256"].update({record["evidence"][0]: "not-a-digest"}),
            "invalid evidence digest",
        ),
    ],
)
def test_passed_stage_review_records_are_validated(tmp_path, change, message):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})
    _edit(manifest, _stage1(change))

    with pytest.raises(StageGateError, match=message):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_one_acceptance_requires_the_runtime_demo_account_binding(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})

    with pytest.raises(StageGateError, match="requires the configured demo account ID"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2}, require_runtime_bindings=True)


def test_a_later_stage_cannot_pass_before_its_predecessors(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage2"})

    with pytest.raises(StageGateError, match="stage2 cannot pass before every preceding stage"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages=set())
