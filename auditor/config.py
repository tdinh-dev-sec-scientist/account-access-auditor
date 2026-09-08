"""Configuration: built-in defaults, overridden by config.yaml, validated.

Thresholds live in configuration rather than in rule source, so the same rule
set can be tuned per environment without editing detection logic. Every key is
validated on load: an unknown key or a threshold of the wrong type is reported
rather than silently ignored, because a typo'd threshold is a rule that quietly
stops firing.
"""

from __future__ import annotations

import copy
import logging
import os
from typing import Any

log = logging.getLogger(__name__)

DEFAULTS: dict[str, Any] = {
    "iam": {
        "require_mfa_for_console_users": True,
        "report_programmatic_users_without_mfa": True,
        "access_key_max_age_days": 90,  # CIS 1.14
        "access_key_critical_age_days": 180,  # project escalation tier
        "access_key_unused_days": 45,  # CIS 1.12
        "inactive_key_check": True,
        "dormant_key_check": True,
        "check_wildcard_policies": True,
        "include_groups": True,
        "include_roles": True,
    },
    "s3": {
        "check_public_access": True,
        "check_encryption": True,
    },
    "cloudtrail": {
        "require_trail": True,
        "require_multi_region": True,
        "require_log_validation": True,
        "check_logging_status": True,
    },
}

# key -> expected python type, used to reject a threshold written as "90 days".
_SCHEMA: dict[str, dict[str, type]] = {
    section: {key: type(value) for key, value in values.items()} for section, values in DEFAULTS.items()
}


class ConfigError(ValueError):
    """The configuration file is present but not usable."""


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def validate(config: dict[str, Any], strict: bool = False) -> list[str]:
    """Return a list of human-readable problems with ``config``.

    In strict mode the caller turns these into an error; otherwise they are
    logged as warnings and the affected keys fall back to their defaults.
    """
    problems: list[str] = []

    for section, values in config.items():
        if section not in _SCHEMA:
            problems.append(f"unknown configuration section '{section}'")
            continue
        if not isinstance(values, dict):
            problems.append(f"section '{section}' must be a mapping, got {type(values).__name__}")
            continue
        for key, value in values.items():
            expected = _SCHEMA[section].get(key)
            if expected is None:
                problems.append(f"unknown key '{section}.{key}'")
                continue
            # bool is a subclass of int; an int where a bool belongs is a mistake.
            if expected is bool and not isinstance(value, bool):
                problems.append(f"'{section}.{key}' must be true/false, got {value!r}")
            elif expected is int and (isinstance(value, bool) or not isinstance(value, int)):
                problems.append(f"'{section}.{key}' must be a whole number, got {value!r}")
            elif expected is int and isinstance(value, int) and value < 0:
                problems.append(f"'{section}.{key}' must not be negative, got {value!r}")

    iam = config.get("iam", {})
    if isinstance(iam, dict):
        maximum = iam.get("access_key_max_age_days")
        critical = iam.get("access_key_critical_age_days")
        if isinstance(maximum, int) and isinstance(critical, int) and critical < maximum:
            problems.append(
                "'iam.access_key_critical_age_days' is below 'iam.access_key_max_age_days', "
                "so the escalation tier would fire before the base tier"
            )

    return problems


def defaults() -> dict[str, Any]:
    return copy.deepcopy(DEFAULTS)


def load_config(path: str | None = None, strict: bool = False, required: bool = False) -> dict[str, Any]:
    """Load config.yaml merged over the defaults.

    A missing file is not an error unless ``required``: the defaults are a
    complete, usable configuration on their own.
    """
    if not path:
        return defaults()

    if not os.path.exists(path):
        if required:
            raise ConfigError(f"Configuration file not found: {path}")
        log.warning("Config file not found: %s (using defaults)", path)
        return defaults()

    try:
        import yaml  # imported lazily so the rules and tests do not need PyYAML
    except ImportError:  # pragma: no cover - depends on the environment
        log.warning("PyYAML is not installed; using default configuration")
        return defaults()

    try:
        with open(path, encoding="utf-8") as handle:
            user_config = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Config file {path} is not valid YAML: {exc}") from exc

    if not isinstance(user_config, dict):
        raise ConfigError(f"Config file {path} must contain a mapping at the top level")

    problems = validate(user_config, strict=strict)
    if problems:
        message = f"{len(problems)} configuration problem(s) in {path}: " + "; ".join(problems)
        if strict:
            raise ConfigError(message)
        log.warning("%s (unrecognised keys are ignored)", message)
        user_config = _drop_invalid(user_config)

    log.debug("Loaded configuration from %s", path)
    return _deep_merge(DEFAULTS, user_config)


def _drop_invalid(config: dict[str, Any]) -> dict[str, Any]:
    """Keep only keys that exist in the schema with the right type."""
    cleaned: dict[str, Any] = {}
    for section, values in config.items():
        if section not in _SCHEMA or not isinstance(values, dict):
            continue
        kept = {}
        for key, value in values.items():
            expected = _SCHEMA[section].get(key)
            if expected is None:
                continue
            if expected is bool and not isinstance(value, bool):
                continue
            if expected is int and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                continue
            kept[key] = value
        if kept:
            cleaned[section] = kept
    return cleaned


def describe(config: dict[str, Any]) -> list[tuple[str, Any, bool]]:
    """(dotted key, value, is_default) for every effective setting."""
    rows: list[tuple[str, Any, bool]] = []
    for section, values in DEFAULTS.items():
        for key, default_value in values.items():
            actual = config.get(section, {}).get(key, default_value)
            rows.append((f"{section}.{key}", actual, actual == default_value))
    return rows
