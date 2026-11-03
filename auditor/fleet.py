"""Validated configuration for read-only multi-account AWS scans."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

MAX_CONFIG_BYTES = 1_048_576
MAX_ACCOUNTS = 100
MAX_REGIONS = 32
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_ROLE_ARN = re.compile(
    r"^arn:aws:iam::(?P<account>[0-9]{12}):role/AccountAccessAuditorReadOnly$"
)
_REGION = re.compile(r"^[a-z]{2,}(?:-[a-z0-9]+)+-[0-9]+$")
_EXTERNAL_ID_ENV_NAME = re.compile(r"^AUDITOR_EXTERNAL_ID_[A-Z0-9_]{1,64}$")
_CREDENTIAL_LIKE_ENV_NAME = re.compile(
    r"(?:^|_)(?:ACCESS_KEY(?:_ID)?|API_KEY|AUTH(?:ORIZATION)?|BEARER|CLIENT_SECRET|COOKIE|"
    r"CREDENTIALS?|JWT|KEY|OAUTH|PASS(?:WORD|WD|PHRASE)?|PRIVATE_KEY|PWD|SECRET(?:_ACCESS_KEY)?|"
    r"SESSION|SIGNING_KEY|TOKEN)(?:_|$)"
)
_SERVICES = ("iam", "s3", "cloudtrail")


class FleetConfigError(ValueError):
    """A fleet target configuration is malformed or unsafe."""


@dataclass(frozen=True)
class TargetAccount:
    account_id: str
    role_arn: str
    external_id_env: str | None = None


@dataclass(frozen=True)
class FleetConfig:
    accounts: tuple[TargetAccount, ...]
    regions: tuple[str, ...]
    services: tuple[str, ...]


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _is_safe_external_id_env(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(_EXTERNAL_ID_ENV_NAME.fullmatch(value))
        and not _CREDENTIAL_LIKE_ENV_NAME.search(value)
    )


def _construct_mapping(loader: _UniqueKeyLoader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise FleetConfigError("configuration mapping keys must be strings")
        if key in mapping:
            raise FleetConfigError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def load_fleet_config(path: str | Path) -> FleetConfig:
    """Read a bounded UTF-8 YAML fleet configuration without secret values."""
    source = Path(path)
    try:
        if source.stat().st_size > MAX_CONFIG_BYTES:
            raise FleetConfigError("fleet configuration exceeds the 1 MiB size limit")
        text = source.read_text(encoding="utf-8")
    except FleetConfigError:
        raise
    except (OSError, UnicodeError):
        raise FleetConfigError("fleet configuration could not be read as UTF-8") from None
    return parse_fleet_config(text)


def parse_fleet_config(text: str) -> FleetConfig:
    """Parse and validate fleet targets; external-ID values remain in env vars."""
    try:
        document = yaml.load(text, Loader=_UniqueKeyLoader)
    except FleetConfigError:
        raise
    except yaml.YAMLError:
        raise FleetConfigError("fleet configuration contains invalid YAML") from None

    allowed = {"accounts", "regions", "services"}
    if not isinstance(document, dict) or set(document) - allowed:
        raise FleetConfigError("fleet configuration must be a mapping with only supported fields")
    raw_accounts = document.get("accounts")
    raw_regions = document.get("regions")
    if not isinstance(raw_accounts, list) or not 1 <= len(raw_accounts) <= MAX_ACCOUNTS:
        raise FleetConfigError(f"accounts must contain between 1 and {MAX_ACCOUNTS} targets")
    if not isinstance(raw_regions, list) or not 1 <= len(raw_regions) <= MAX_REGIONS:
        raise FleetConfigError(f"regions must contain between 1 and {MAX_REGIONS} regions")

    accounts = tuple(_parse_account(record, index) for index, record in enumerate(raw_accounts, start=1))
    account_ids = [account.account_id for account in accounts]
    if len(set(account_ids)) != len(account_ids):
        raise FleetConfigError("account IDs must be unique")

    regions: list[str] = []
    for region in raw_regions:
        if not isinstance(region, str) or not _REGION.fullmatch(region):
            raise FleetConfigError("regions must be exact AWS region names")
        regions.append(region)
    if len(set(regions)) != len(regions):
        raise FleetConfigError("regions must be unique")

    raw_services = document.get("services", list(_SERVICES))
    if (
        not isinstance(raw_services, list)
        or not raw_services
        or any(not isinstance(service, str) or service not in _SERVICES for service in raw_services)
    ):
        raise FleetConfigError("services must be a non-empty list of iam, s3, and/or cloudtrail")
    if len(set(raw_services)) != len(raw_services):
        raise FleetConfigError("services must be unique")
    services = tuple(service for service in _SERVICES if service in raw_services)

    return FleetConfig(accounts, tuple(regions), services)


def _parse_account(record: Any, index: int) -> TargetAccount:
    if not isinstance(record, dict) or set(record) - {"account_id", "role_arn", "external_id_env"}:
        raise FleetConfigError(f"account {index} must contain only account_id, role_arn, and external_id_env")
    account_id = record.get("account_id")
    role_arn = record.get("role_arn")
    if not isinstance(account_id, str) or not _ACCOUNT_ID.fullmatch(account_id):
        raise FleetConfigError(f"account {index} account_id must be a quoted 12-digit string")
    match = _ROLE_ARN.fullmatch(role_arn) if isinstance(role_arn, str) else None
    if not match:
        raise FleetConfigError(
            f"account {index} role_arn must name the AccountAccessAuditorReadOnly role"
        )
    if match.group("account") != account_id:
        raise FleetConfigError("role ARN account must match account_id")
    external_id_env = record.get("external_id_env")
    if external_id_env is not None and not _is_safe_external_id_env(external_id_env):
        raise FleetConfigError(
            f"account {index} external_id_env must use the AUDITOR_EXTERNAL_ID_* namespace "
            "and not reference credential-like variables"
        )
    return TargetAccount(account_id, role_arn, external_id_env)


def resolve_external_id(account: TargetAccount) -> str | None:
    """Resolve the configured external ID without retaining it in config data."""
    if account.external_id_env is None:
        return None
    if not _is_safe_external_id_env(account.external_id_env):
        raise FleetConfigError(
            "external ID environment variable must use the AUDITOR_EXTERNAL_ID_* namespace "
            "and not reference credential-like variables"
        )
    value = os.environ.get(account.external_id_env)
    if value is None or not value.strip() or len(value) > 1024:
        raise FleetConfigError(
            f"external ID environment variable {account.external_id_env} is missing or invalid"
        )
    return value
