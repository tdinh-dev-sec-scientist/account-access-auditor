"""Configuration loading and validation.

A typo'd threshold is a rule that quietly stops firing, which is why unknown and
malformed keys are reported rather than ignored.
"""

from __future__ import annotations

import pytest
import yaml

from auditor.config import DEFAULTS, ConfigError, defaults, describe, load_config, validate


def write(tmp_path, content):
    path = tmp_path / "config.yaml"
    path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return str(path)


def test_defaults_are_a_complete_usable_configuration():
    config = defaults()
    assert set(config) == {"iam", "s3", "cloudtrail"}
    assert config["iam"]["access_key_max_age_days"] == 90  # CIS 1.14
    assert config["iam"]["access_key_unused_days"] == 45  # CIS 1.12
    assert validate(config) == []


def test_defaults_are_copied_not_shared():
    first = defaults()
    first["iam"]["access_key_max_age_days"] = 1
    assert defaults()["iam"]["access_key_max_age_days"] == 90
    assert DEFAULTS["iam"]["access_key_max_age_days"] == 90


def test_no_path_means_defaults():
    assert load_config(None) == DEFAULTS


def test_user_values_are_merged_over_defaults_key_by_key(tmp_path):
    config = load_config(write(tmp_path, {"iam": {"access_key_max_age_days": 30}}))
    assert config["iam"]["access_key_max_age_days"] == 30
    assert config["iam"]["access_key_critical_age_days"] == 180  # untouched default
    assert config["s3"] == DEFAULTS["s3"]


def test_a_missing_file_falls_back_to_defaults_with_a_warning(tmp_path, caplog):
    config = load_config(str(tmp_path / "absent.yaml"))
    assert config == DEFAULTS
    assert "not found" in caplog.text


def test_a_missing_file_can_be_made_fatal(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(str(tmp_path / "absent.yaml"), required=True)


def test_invalid_yaml_is_an_explicit_error(tmp_path):
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(write(tmp_path, "iam: [unclosed"))


def test_a_non_mapping_document_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="mapping at the top level"):
        load_config(write(tmp_path, "- a\n- b\n"))


def test_an_empty_file_is_treated_as_no_overrides(tmp_path):
    assert load_config(write(tmp_path, "")) == DEFAULTS


@pytest.mark.parametrize(
    "config,problem",
    [
        ({"nope": {}}, "unknown configuration section"),
        ({"iam": {"nope": 1}}, "unknown key"),
        ({"iam": {"access_key_max_age_days": "90"}}, "must be a whole number"),
        ({"iam": {"access_key_max_age_days": -1}}, "must not be negative"),
        ({"iam": {"require_mfa_for_console_users": 1}}, "must be true/false"),
        ({"iam": "not-a-mapping"}, "must be a mapping"),
    ],
)
def test_validation_names_the_specific_problem(config, problem):
    problems = validate(config)
    assert any(problem in item for item in problems), problems


def test_an_escalation_threshold_below_the_base_threshold_is_reported():
    problems = validate({"iam": {"access_key_max_age_days": 200, "access_key_critical_age_days": 100}})
    assert any("escalation tier would fire before" in p for p in problems)


def test_a_boolean_is_not_accepted_where_a_number_belongs():
    """bool is a subclass of int in Python; a config loader must not be fooled."""
    assert validate({"iam": {"access_key_max_age_days": True}})


def test_invalid_keys_are_dropped_and_the_rest_still_applies(tmp_path, caplog):
    config = load_config(
        write(
            tmp_path,
            {
                "iam": {"access_key_max_age_days": 30, "bogus": 1},
                "unknown_section": {"x": 1},
            },
        )
    )
    assert config["iam"]["access_key_max_age_days"] == 30
    assert "bogus" not in config["iam"]
    assert "unknown_section" not in config
    assert "configuration problem" in caplog.text


def test_strict_mode_refuses_to_run_on_a_bad_configuration(tmp_path):
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(write(tmp_path, {"iam": {"bogus": 1}}), strict=True)


def test_the_committed_config_file_is_valid():
    """The repository's own config.yaml must pass its own validator."""
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "config.yaml"), encoding="utf-8") as handle:
        assert validate(yaml.safe_load(handle)) == []


def test_describe_reports_every_setting_and_whether_it_is_a_default():
    rows = describe(load_config(None))
    assert len(rows) == sum(len(v) for v in DEFAULTS.values())
    assert all(is_default for _, _, is_default in rows)
    keys = [key for key, _, _ in rows]
    assert "iam.access_key_unused_days" in keys


def test_switching_a_check_off_suppresses_only_that_rule():
    from auditor.rules import engine
    from tests.builders import bucket, s3_state

    data = s3_state(bucket("b", public_access_block=None, encryption_configured=False))
    config = defaults()
    config["s3"]["check_encryption"] = False

    rule_ids = {f.rule_id for f in engine.evaluate_service("s3", data, config)}
    assert rule_ids == {"S3-001"}
