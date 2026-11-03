from __future__ import annotations

import pytest

from auditor.fleet import FleetConfigError, load_fleet_config, resolve_external_id


def test_load_fleet_config_validates_target_scope_and_regions(tmp_path):
    config_path = tmp_path / "targets.yaml"
    config_path.write_text(
        "accounts:\n"
        "  - account_id: '123456789012'\n"
        "    role_arn: arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly\n"
        "    external_id_env: AUDITOR_EXTERNAL_ID_PROD\n"
        "regions: [us-east-1, us-west-2]\n"
        "services: [iam, s3, cloudtrail]\n",
        encoding="utf-8",
    )

    config = load_fleet_config(config_path)

    assert [account.account_id for account in config.accounts] == ["123456789012"]
    assert [account.role_arn for account in config.accounts] == [
        "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly"
    ]
    assert config.accounts[0].external_id_env == "AUDITOR_EXTERNAL_ID_PROD"
    assert config.regions == ("us-east-1", "us-west-2")
    assert config.services == ("iam", "s3", "cloudtrail")


def test_load_fleet_config_rejects_account_role_mismatch(tmp_path):
    config_path = tmp_path / "targets.yaml"
    config_path.write_text(
        "accounts:\n"
        "  - account_id: '123456789012'\n"
        "    role_arn: arn:aws:iam::999999999999:role/AccountAccessAuditorReadOnly\n"
        "regions: [us-east-1]\n",
        encoding="utf-8",
    )

    with pytest.raises(FleetConfigError, match="role ARN account must match account_id"):
        load_fleet_config(config_path)


def test_load_fleet_config_rejects_duplicate_yaml_keys(tmp_path):
    config_path = tmp_path / "targets.yaml"
    config_path.write_text(
        "accounts: []\naccounts: []\nregions: [us-east-1, us-east-1]\n",
        encoding="utf-8",
    )

    with pytest.raises(FleetConfigError, match="duplicate YAML key"):
        load_fleet_config(config_path)


def test_load_fleet_config_rejects_duplicate_regions():
    from auditor.fleet import parse_fleet_config

    with pytest.raises(FleetConfigError, match="regions must be unique"):
        parse_fleet_config(
            "accounts:\n"
            "  - account_id: '123456789012'\n"
            "    role_arn: arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly\n"
            "regions: [us-east-1, us-east-1]\n"
        )


def test_external_id_is_resolved_from_environment_without_serializing_secret(monkeypatch):
    monkeypatch.setenv("AUDITOR_EXTERNAL_ID_PROD", "a-private-external-id")
    config = load_fleet_config_from_text(
        "accounts:\n"
        "  - account_id: '123456789012'\n"
        "    role_arn: arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly\n"
        "    external_id_env: AUDITOR_EXTERNAL_ID_PROD\n"
        "regions: [us-east-1]\n"
    )

    assert resolve_external_id(config.accounts[0]) == "a-private-external-id"
    assert "a-private-external-id" not in repr(config)


def test_external_id_resolution_requires_the_referenced_environment_variable(monkeypatch):
    monkeypatch.delenv("AUDITOR_EXTERNAL_ID_PROD", raising=False)
    config = load_fleet_config_from_text(
        "accounts:\n"
        "  - account_id: '123456789012'\n"
        "    role_arn: arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly\n"
        "    external_id_env: AUDITOR_EXTERNAL_ID_PROD\n"
        "regions: [us-east-1]\n"
    )

    with pytest.raises(FleetConfigError, match="environment variable.*missing or invalid"):
        resolve_external_id(config.accounts[0])


@pytest.mark.parametrize(
    "environment_name",
    [
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "AUDITOR_EXTERNAL_ID_SECRET",
        "AUDITOR_EXTERNAL_ID_API_TOKEN",
        "AUDITOR_EXTERNAL_ID_PROD_PRIVATE_KEY",
        "AUDITOR_EXTERNAL_ID_BASIC_AUTH",
        "AUDITOR_EXTERNAL_ID_JWT",
        "AUDITOR_EXTERNAL_ID_DB_PASS",
        "AUDITOR_EXTERNAL_ID_DB_PWD",
    ],
)
def test_fleet_rejects_external_id_env_names_that_can_leak_credentials(environment_name):
    with pytest.raises(FleetConfigError, match="AUDITOR_EXTERNAL_ID_.*credential-like"):
        load_fleet_config_from_text(
            "accounts:\n"
            "  - account_id: '123456789012'\n"
            "    role_arn: arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly\n"
            f"    external_id_env: {environment_name}\n"
            "regions: [us-east-1]\n"
        )


def test_external_id_resolver_revalidates_direct_account_objects(monkeypatch):
    from auditor.fleet import TargetAccount

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-aws-secret")
    account = TargetAccount(
        "123456789012",
        "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly",
        "AWS_SECRET_ACCESS_KEY",
    )

    with pytest.raises(FleetConfigError, match="AUDITOR_EXTERNAL_ID_.*credential-like"):
        resolve_external_id(account)


def load_fleet_config_from_text(text: str):
    from auditor.fleet import parse_fleet_config

    return parse_fleet_config(text)
