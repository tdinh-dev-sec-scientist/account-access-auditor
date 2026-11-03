from __future__ import annotations

from datetime import UTC, datetime

import pytest
import yaml

from auditor.exceptions import ExceptionConfigError, evaluate_exceptions, load_exceptions

AS_OF = datetime(2026, 11, 2, 12, tzinfo=UTC)
FINDING = {
    "fingerprint": "0123456789abcdef",
    "control_id": "IAC-K8S-001",
    "resource_reference": "Pod/api",
    "source_location": {"file": "k8s/api.yaml", "line": 12},
    "severity": "HIGH",
    "title": "Privileged pod",
}


def _exception(**overrides):
    return {
        "id": "EXC-001",
        "fingerprint": FINDING["fingerprint"],
        "owner": "platform-team",
        "reason": "Vendor image requires a reviewed exception.",
        "created_at": "2026-10-01T00:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z",
        **overrides,
    }


def _write_exceptions(tmp_path, items):
    path = tmp_path / "exceptions.yaml"
    path.write_text(yaml.safe_dump({"exceptions": items}))
    return path


def test_active_exception_is_visible_and_suppresses_only_its_matching_gate(tmp_path):
    exceptions = load_exceptions(_write_exceptions(tmp_path, [_exception()]), as_of=AS_OF)

    findings, evaluations, violations = evaluate_exceptions(
        [FINDING], exceptions, threshold="HIGH", as_of=AS_OF
    )

    assert violations == 0
    assert findings[0]["exceptions"][0]["id"] == "EXC-001"
    assert findings[0]["gate"] is False
    assert evaluations[0]["state"] == "MATCHED_ACTIVE"
    assert evaluations[0]["owner"] == "platform-team"
    assert evaluations[0]["reason"]


def test_expired_exception_stays_visible_but_does_not_suppress(tmp_path):
    exceptions = load_exceptions(
        _write_exceptions(
            tmp_path,
            [_exception(expires_at="2026-11-01T00:00:00Z")],
        ),
        as_of=AS_OF,
    )

    findings, evaluations, violations = evaluate_exceptions(
        [FINDING], exceptions, threshold="HIGH", as_of=AS_OF
    )

    assert violations == 1
    assert findings[0]["exceptions"][0]["state"] == "EXPIRED"
    assert findings[0]["gate"] is True
    assert evaluations[0]["state"] == "MATCHED_EXPIRED"


@pytest.mark.parametrize(
    "bad",
    [
        _exception(reason=""),
        _exception(owner=""),
        _exception(expires_at="2026-09-30T00:00:00Z"),
        _exception(created_at="2026-11-03T00:00:00Z"),
        _exception(created_at="2026-10-01T00:00:00"),
        _exception(fingerprint="*"),
        _exception(control_id="IAC-K8S-*", resource_reference="Pod/api", fingerprint=None),
        _exception(control_id="IAC-K8S-001", fingerprint=None),
        _exception(
            control_id="IAC-K8S-001",
            fingerprint=None,
            source_file="../outside.yaml",
        ),
        _exception(approver="security", unexpected="value"),
    ],
)
def test_invalid_exception_records_fail_closed(tmp_path, bad):
    with pytest.raises(ExceptionConfigError):
        load_exceptions(_write_exceptions(tmp_path, [bad]), as_of=AS_OF)


def test_unmatched_exception_is_visible_in_evaluation(tmp_path):
    exceptions = load_exceptions(
        _write_exceptions(tmp_path, [_exception(fingerprint="fedcba9876543210")]),
        as_of=AS_OF,
    )

    _, evaluations, violations = evaluate_exceptions([FINDING], exceptions, threshold="HIGH", as_of=AS_OF)

    assert violations == 1
    assert evaluations[0]["state"] == "UNMATCHED_ACTIVE"


def test_missing_or_oversized_exception_file_is_rejected(tmp_path):
    with pytest.raises(ExceptionConfigError):
        load_exceptions(tmp_path / "missing.yaml", as_of=AS_OF)
    oversized = tmp_path / "oversized.yaml"
    oversized.write_text("#" + ("x" * 1_048_576))
    with pytest.raises(ExceptionConfigError, match="1 MiB"):
        load_exceptions(oversized, as_of=AS_OF)


def test_nonstring_yaml_mapping_keys_are_rejected_as_config_errors(tmp_path):
    path = tmp_path / "invalid-key.yaml"
    path.write_text("exceptions:\n  - ? [unhashable]\n    : value\n")

    with pytest.raises(ExceptionConfigError, match="mapping keys must be strings"):
        load_exceptions(path, as_of=AS_OF)
