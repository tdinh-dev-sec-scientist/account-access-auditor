"""Normalization: raw Boto3 response shapes -> the internal model.

These cases pin the awkward parts of the real AWS responses -- the ones that
would otherwise be discovered in production: a null LocationConstraint meaning
us-east-1, a missing LastUsedDate meaning "never used", an empty-string delivery
error meaning "no error".
"""

from __future__ import annotations

import datetime as dt

import pytest

from auditor.normalize import cloudtrail, iam, s3

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def days_ago(n: int) -> dt.datetime:
    return NOW - dt.timedelta(days=n)


# ---------------------------------------------------------------------- IAM --


def test_user_identity_starts_unknown_not_false():
    """The distinction between 'no MFA' and 'could not check' starts here."""
    user = iam.user_identity({"UserName": "a", "Arn": "arn:aws:iam::1:user/a"})
    assert user["console_access_enabled"] is None
    assert user["mfa_device_count"] is None
    assert user["access_keys"] == [] and user["policies"] == []


def test_user_identity_formats_dates_as_iso():
    user = iam.user_identity({"UserName": "a", "CreateDate": days_ago(10), "PasswordLastUsed": days_ago(2)})
    assert user["create_date"].startswith("2025-12-22")
    assert user["password_last_used"].startswith("2025-12-30")


def test_mfa_devices_counts_and_records_serials():
    result = iam.mfa_devices({"MFADevices": [{"SerialNumber": "arn:aws:iam::1:mfa/a"}]})
    assert result == {"mfa_device_count": 1, "mfa_device_serials": ["arn:aws:iam::1:mfa/a"]}


def test_mfa_devices_handles_an_empty_or_absent_response():
    assert iam.mfa_devices({})["mfa_device_count"] == 0
    assert iam.mfa_devices(None)["mfa_device_count"] == 0


def test_access_key_age_is_computed_from_create_date():
    key = iam.access_key({"AccessKeyId": "AKIA1", "Status": "Active", "CreateDate": days_ago(120)}, now=NOW)
    assert key["age_days"] == 120 and key["status"] == "Active"


def test_never_used_key_is_signalled_by_a_missing_last_used_date():
    """AWS returns ServiceName/Region as the literal 'N/A' and omits LastUsedDate."""
    key = iam.access_key(
        {"AccessKeyId": "AKIA1", "CreateDate": days_ago(10)},
        {"AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}},
        now=NOW,
    )
    assert key["last_used_date"] is None
    assert key["last_used_days_ago"] is None
    assert key["last_used_service"] is None and key["last_used_region"] is None


def test_used_key_records_when_and_where():
    key = iam.access_key(
        {"AccessKeyId": "AKIA1", "CreateDate": days_ago(90)},
        {"AccessKeyLastUsed": {"LastUsedDate": days_ago(3), "ServiceName": "s3", "Region": "eu-west-1"}},
        now=NOW,
    )
    assert key["last_used_days_ago"] == 3
    assert key["last_used_service"] == "s3" and key["last_used_region"] == "eu-west-1"


def test_unknown_last_used_is_flagged_so_rules_can_stay_silent():
    key = iam.access_key(
        {"AccessKeyId": "AKIA1", "CreateDate": days_ago(9)}, None, last_used_known=False, now=NOW
    )
    assert key["last_used_known"] is False


def test_missing_create_date_yields_unknown_age_not_zero():
    assert iam.access_key({"AccessKeyId": "AKIA1"}, now=NOW)["age_days"] is None


@pytest.mark.parametrize(
    "arn,expected",
    [
        ("arn:aws:iam::aws:policy/AdministratorAccess", True),
        ("arn:aws:iam::123456789012:policy/custom", False),
        (None, False),
        ("", False),
    ],
)
def test_aws_managed_policies_are_identified_by_arn(arn, expected):
    assert iam.is_aws_managed(arn) is expected


def test_policy_record_carries_type_and_managed_flag():
    record = iam.policy_record("p", {"Statement": []}, "managed", "arn:aws:iam::aws:policy/p")
    assert record["type"] == "managed" and record["is_aws_managed"] is True


def test_managed_policy_document_extracts_the_default_version():
    document = iam.managed_policy_document(
        {"Policy": {"DefaultVersionId": "v2"}},
        {"PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow"}]}}},
    )
    assert document == {"Statement": [{"Effect": "Allow"}]}


@pytest.mark.parametrize("version", [None, {}, {"PolicyVersion": {}}, {"PolicyVersion": {"Document": "str"}}])
def test_unreadable_policy_versions_yield_none(version):
    assert iam.managed_policy_document({"Policy": {}}, version) is None


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/aws-service-role/elasticloadbalancing.amazonaws.com/", True),
        ("/", False),
        ("/service-role/", False),
        (None, False),
    ],
)
def test_service_linked_roles_are_identified_by_path(path, expected):
    assert iam.is_service_linked_role({"Path": path}) is expected


def test_group_and_role_records_have_empty_policy_lists_until_filled():
    assert iam.group_record({"GroupName": "g"})["policies"] == []
    assert iam.role_record({"RoleName": "r"})["policies"] == []


def test_role_record_keeps_the_trust_policy():
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}}]}
    assert iam.role_record({"RoleName": "r", "AssumeRolePolicyDocument": trust})["trust_policy"] == trust


def test_group_names_reads_the_list_groups_for_user_shape():
    assert iam.group_names({"Groups": [{"GroupName": "a"}, {"GroupName": "b"}]}) == ["a", "b"]
    assert iam.group_names(None) == []


# ----------------------------------------------------------------------- S3 --


def test_us_east_1_is_reported_as_a_null_location_constraint():
    assert s3.location({"LocationConstraint": None}) == "us-east-1"
    assert s3.location({}) == "us-east-1"
    assert s3.location({"LocationConstraint": "eu-west-2"}) == "eu-west-2"


def test_public_access_block_defaults_missing_flags_to_false():
    result = s3.public_access_block({"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}})
    assert result == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }


def test_encryption_reports_configured_only_when_rules_exist():
    configured = s3.encryption(
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "key-1",
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            }
        }
    )
    assert configured["configured"] is True
    assert configured["rules"][0] == {
        "algorithm": "aws:kms",
        "kms_key_id": "key-1",
        "bucket_key_enabled": True,
    }
    assert s3.encryption({"ServerSideEncryptionConfiguration": {"Rules": []}})["configured"] is False


def test_encryption_states_distinguish_absent_from_unreadable():
    assert s3.no_encryption_configured() == {"configured": False, "known": True, "rules": []}
    assert s3.unknown_encryption() == {"configured": False, "known": False, "rules": []}


def test_bucket_policy_is_parsed_from_its_json_string():
    assert s3.bucket_policy({"Policy": '{"Version": "2012-10-17"}'}) == {"Version": "2012-10-17"}


@pytest.mark.parametrize("value", ["{not json", "[]", "null", '"a string"'])
def test_unparseable_bucket_policies_are_preserved_as_unparsed(value):
    result = s3.bucket_policy({"Policy": value})
    assert "_unparsed" in result


def test_absent_bucket_policy_is_none():
    assert s3.bucket_policy({}) is None
    assert s3.bucket_policy(None) is None


def test_policy_status_reads_is_public():
    assert s3.policy_status({"PolicyStatus": {"IsPublic": True}}) is True
    assert s3.policy_status({}) is None


def test_acl_grants_label_only_the_two_global_groups():
    grants = s3.acl_grants(
        {
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                },
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "WRITE",
                },
                {
                    "Grantee": {"Type": "CanonicalUser", "ID": "abc", "DisplayName": "owner"},
                    "Permission": "FULL_CONTROL",
                },
            ]
        }
    )
    assert [g["group"] for g in grants] == ["AllUsers", None, None]
    assert grants[2]["display_name"] == "owner"


def test_log_delivery_group_is_not_treated_as_public():
    """s3/LogDelivery is an AWS service group, not a global one."""
    grants = s3.acl_grants(
        {
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "WRITE",
                }
            ]
        }
    )
    assert grants[0]["group"] is None


# --------------------------------------------------------------- CloudTrail --


def test_trail_configuration_is_read_but_status_starts_unknown():
    trail = cloudtrail.trail(
        {
            "Name": "t",
            "TrailARN": "arn:x",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
            "S3BucketName": "b",
        }
    )
    assert trail["is_multi_region"] is True and trail["log_file_validation_enabled"] is True
    assert trail["is_logging"] is None and trail["logging_status_known"] is False


def test_trail_defaults_absent_booleans_to_false():
    trail = cloudtrail.trail({"Name": "t"})
    assert trail["is_multi_region"] is False
    assert trail["log_file_validation_enabled"] is False
    assert trail["is_organization_trail"] is False


def test_apply_status_merges_operational_state():
    trail = cloudtrail.apply_status(
        cloudtrail.trail({"Name": "t"}),
        {"IsLogging": True, "LatestDeliveryTime": NOW, "LatestDeliveryError": "AccessDenied"},
    )
    assert trail["is_logging"] is True and trail["logging_status_known"] is True
    assert trail["latest_delivery_error"] == "AccessDenied"
    assert trail["latest_delivery_time"].startswith("2026-01-01")


def test_empty_string_delivery_error_means_no_error():
    """CloudTrail reports 'no event yet' as an empty string, not as absence."""
    trail = cloudtrail.apply_status(
        cloudtrail.trail({"Name": "t"}), {"IsLogging": True, "LatestDeliveryError": ""}
    )
    assert trail["latest_delivery_error"] is None


def test_apply_status_with_no_response_leaves_state_unknown():
    trail = cloudtrail.apply_status(cloudtrail.trail({"Name": "t"}), None)
    assert trail["is_logging"] is None and trail["logging_status_known"] is False
