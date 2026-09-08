"""Collector tests.

Two layers, because they catch different things:

* stub clients, for the failure paths -- AccessDenied, throttling, malformed
  responses -- which are awkward to provoke otherwise and are exactly where a
  scanner quietly turns "could not read" into "nothing found";
* an in-process AWS emulation, for the happy path through real boto3 clients,
  real paginators, and real response parsing.

Neither layer makes a network call.
"""

from __future__ import annotations

import json

import pytest
from botocore.exceptions import ClientError

from auditor.collectors import _common, cloudtrail, iam, s3

# ------------------------------------------------------------------- stubs --


def client_error(code: str, operation: str = "Op") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


class StubPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return list(self._pages)


class StubClient:
    """A boto3 client stand-in driven by a dict of responses or exceptions."""

    def __init__(self, responses=None, pages=None):
        self._responses = responses or {}
        self._pages = pages or {}
        self.calls = []

    def can_paginate(self, operation):
        return operation in self._pages

    def get_paginator(self, operation):
        value = self._pages[operation]
        if isinstance(value, Exception):
            raise value
        return StubPaginator(value)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(**kwargs):
            self.calls.append((name, kwargs))
            value = self._responses.get(name)
            if isinstance(value, Exception):
                raise value
            if value is None:
                raise AssertionError(f"stub has no response for {name}")
            return value

        return call


class StubSession:
    def __init__(self, clients):
        self._clients = clients
        self.region_name = "us-east-1"

    def client(self, name, **kwargs):
        return self._clients[name]


# ------------------------------------------------------------- _common ------


def test_error_codes_are_categorised():
    assert _common.error_code(client_error("AccessDenied")) == "AccessDenied"
    assert _common.error_code(ValueError("x")) == "ValueError"
    assert _common.is_access_denied(client_error("AccessDeniedException"))
    assert _common.is_throttling(client_error("ThrottlingException"))
    assert _common.is_not_configured(client_error("NoSuchBucketPolicy"))
    assert not _common.is_not_configured(client_error("AccessDenied"))


def test_recorded_errors_name_the_missing_permission():
    errors = []
    _common.record_error(
        errors, "IAM", "iam:ListUsers", client_error("AccessDenied"), "acct", ["iam:ListUsers"]
    )
    assert errors[0]["required_permissions"] == ["iam:ListUsers"]
    assert errors[0]["category"] == "access_denied"


def test_throttling_after_retries_is_recorded_as_throttled_not_as_a_permission_problem():
    errors = []
    _common.record_error(errors, "S3", "s3:GetBucketAcl", client_error("Throttling"), "b")
    assert errors[0]["category"] == "throttled"
    assert "required_permissions" not in errors[0]


def test_safe_call_distinguishes_ok_absent_and_denied():
    errors, own = [], []
    assert _common.safe_call(errors, own, "S3", "op", lambda: {"a": 1})[1] == _common.OK
    assert (
        _common.safe_call(
            errors, own, "S3", "op", lambda: (_ for _ in ()).throw(client_error("NoSuchBucketPolicy"))
        )[1]
        == _common.NOT_CONFIGURED
    )
    assert (
        _common.safe_call(
            errors, own, "S3", "op", lambda: (_ for _ in ()).throw(client_error("AccessDenied"))
        )[1]
        == _common.FAILED
    )
    # Only the genuine failure is recorded; "not configured" is data, not an error.
    assert len(errors) == 1 and len(own) == 1


def test_paginate_falls_back_for_unpaginated_operations():
    client = StubClient(responses={"describe_trails": {"trailList": [{"Name": "t"}]}})
    pages = list(_common.paginate(client, "describe_trails", includeShadowTrails=False))
    assert pages == [{"trailList": [{"Name": "t"}]}]


# ----------------------------------------------------------------- IAM ------


def _iam_stub(**overrides):
    pages = {
        "list_users": [{"Users": [{"UserName": "u1", "Arn": "arn:aws:iam::1:user/u1"}]}],
        "list_access_keys": [{"AccessKeyMetadata": []}],
        "list_groups_for_user": [{"Groups": []}],
        "list_attached_user_policies": [{"AttachedPolicies": []}],
        "list_user_policies": [{"PolicyNames": []}],
        "list_groups": [{"Groups": []}],
        "list_roles": [{"Roles": []}],
    }
    responses = {
        "get_login_profile": client_error("NoSuchEntity"),
        "list_mfa_devices": {"MFADevices": []},
    }
    pages.update(overrides.pop("pages", {}))
    responses.update(overrides.pop("responses", {}))
    return StubClient(responses, pages)


def test_iam_collector_normalises_a_programmatic_user():
    client = _iam_stub()
    data = iam.collect(StubSession({"iam": client}), {})
    user = data["users"][0]
    assert user["username"] == "u1"
    assert user["console_access_enabled"] is False  # NoSuchEntity means no password
    assert user["mfa_device_count"] == 0
    assert data["errors"] == []


def test_denied_login_profile_leaves_console_state_unknown_and_records_the_error():
    client = _iam_stub(responses={"get_login_profile": client_error("AccessDenied")})
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"][0]["console_access_enabled"] is None
    assert data["errors"][0]["code"] == "AccessDenied"
    assert data["users"][0]["collection_errors"]


def test_denied_list_users_does_not_abort_the_collector():
    client = _iam_stub(pages={"list_users": client_error("AccessDenied")})
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"] == []
    assert data["errors"][0]["required_permissions"] == ["iam:ListUsers"]


def test_pagination_across_multiple_pages_is_followed():
    client = _iam_stub(
        pages={
            "list_users": [
                {"Users": [{"UserName": "a"}]},
                {"Users": [{"UserName": "b"}, {"UserName": "c"}]},
            ]
        }
    )
    data = iam.collect(StubSession({"iam": client}), {})
    assert [u["username"] for u in data["users"]] == ["a", "b", "c"]


def test_access_key_last_used_denial_marks_the_key_unknown_not_dormant():
    client = _iam_stub(
        pages={"list_access_keys": [{"AccessKeyMetadata": [{"AccessKeyId": "AKIA1", "Status": "Active"}]}]},
        responses={"get_access_key_last_used": client_error("AccessDenied")},
    )
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"][0]["access_keys"][0]["last_used_known"] is False


def test_managed_policy_documents_are_resolved_through_get_policy_version():
    document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    client = _iam_stub(
        pages={
            "list_attached_user_policies": [
                {"AttachedPolicies": [{"PolicyName": "Admin", "PolicyArn": "arn:aws:iam::aws:policy/Admin"}]}
            ]
        },
        responses={
            "get_policy": {"Policy": {"DefaultVersionId": "v1"}},
            "get_policy_version": {"PolicyVersion": {"Document": document}},
        },
    )
    data = iam.collect(StubSession({"iam": client}), {})
    policy = data["users"][0]["policies"][0]
    assert policy["document"] == document and policy["is_aws_managed"] is True


def test_a_denied_policy_document_yields_none_rather_than_an_empty_policy():
    client = _iam_stub(
        pages={
            "list_attached_user_policies": [
                {"AttachedPolicies": [{"PolicyName": "P", "PolicyArn": "arn:aws:iam::1:policy/P"}]}
            ]
        },
        responses={"get_policy": client_error("AccessDenied")},
    )
    data = iam.collect(StubSession({"iam": client}), {})
    assert data["users"][0]["policies"][0]["document"] is None


def test_service_linked_roles_are_skipped_and_counted():
    client = _iam_stub(
        pages={
            "list_roles": [
                {
                    "Roles": [
                        {"RoleName": "app", "Path": "/"},
                        {"RoleName": "slr", "Path": "/aws-service-role/elasticloadbalancing.amazonaws.com/"},
                    ]
                }
            ],
            "list_attached_role_policies": [{"AttachedPolicies": []}],
            "list_role_policies": [{"PolicyNames": []}],
        }
    )
    data = iam.collect(StubSession({"iam": client}), {})
    assert [r["name"] for r in data["roles"]] == ["app"]
    assert data["service_linked_roles_skipped"] == 1


def test_groups_and_roles_can_be_switched_off_by_configuration():
    client = _iam_stub()
    data = iam.collect(
        StubSession({"iam": client}), {"iam": {"include_groups": False, "include_roles": False}}
    )
    assert data["groups"] == [] and data["roles"] == []
    assert not any(call[0] == "list_groups" for call in client.calls)


# ------------------------------------------------------------------ S3 ------


def _s3_stub(**responses):
    base = {
        "list_buckets": {"Buckets": [{"Name": "b1"}]},
        "get_bucket_location": {"LocationConstraint": None},
        "get_public_access_block": client_error("NoSuchPublicAccessBlockConfiguration"),
        "get_bucket_encryption": client_error("ServerSideEncryptionConfigurationNotFoundError"),
        "get_bucket_policy": client_error("NoSuchBucketPolicy"),
        "get_bucket_policy_status": client_error("NoSuchBucketPolicy"),
        "get_bucket_acl": {"Grants": []},
    }
    base.update(responses)
    return StubClient(base)


def test_s3_collector_treats_absent_configuration_as_absent():
    data = s3.collect(StubSession({"s3": _s3_stub()}), {})
    bucket = data["buckets"][0]
    assert bucket["region"] == "us-east-1"
    assert bucket["public_access_block"] is None
    assert bucket["public_access_block_known"] is True
    assert bucket["encryption"] == {"configured": False, "known": True, "rules": []}
    assert data["errors"] == []


def test_a_denied_pab_call_marks_the_field_unknown_rather_than_absent():
    data = s3.collect(StubSession({"s3": _s3_stub(get_public_access_block=client_error("AccessDenied"))}), {})
    bucket = data["buckets"][0]
    assert bucket["public_access_block_known"] is False
    assert bucket["collection_errors"][0]["required_permissions"] == ["s3:GetBucketPublicAccessBlock"]


def test_one_denied_call_degrades_one_field_not_the_whole_bucket():
    data = s3.collect(
        StubSession(
            {
                "s3": _s3_stub(
                    get_bucket_acl=client_error("AccessDenied"),
                    get_bucket_encryption={
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                        }
                    },
                )
            }
        ),
        {},
    )
    bucket = data["buckets"][0]
    assert bucket["acl_known"] is False
    assert bucket["encryption"]["configured"] is True  # unaffected by the ACL denial


def test_denied_list_buckets_marks_the_estate_unreadable():
    data = s3.collect(StubSession({"s3": StubClient({"list_buckets": client_error("AccessDenied")})}), {})
    assert data["buckets_readable"] is False
    assert data["errors"][0]["required_permissions"] == ["s3:ListAllMyBuckets"]


def test_an_unparseable_bucket_policy_is_kept_rather_than_dropped():
    data = s3.collect(StubSession({"s3": _s3_stub(get_bucket_policy={"Policy": "{broken"})}), {})
    assert "_unparsed" in data["buckets"][0]["policy"]


def test_no_buckets_is_a_clean_empty_result():
    data = s3.collect(StubSession({"s3": StubClient({"list_buckets": {"Buckets": []}})}), {})
    assert data == {"buckets": [], "errors": [], "buckets_readable": True}


# ---------------------------------------------------------- CloudTrail ------


def test_cloudtrail_collector_merges_configuration_and_status():
    client = StubClient(
        {
            "describe_trails": {
                "trailList": [{"Name": "t", "TrailARN": "arn:x", "IsMultiRegionTrail": True}]
            },
            "get_trail_status": {"IsLogging": True, "LatestDeliveryError": ""},
        }
    )
    data = cloudtrail.collect(StubSession({"cloudtrail": client}), {})
    trail = data["trails"][0]
    assert data["trails_readable"] is True
    assert trail["is_multi_region"] is True and trail["is_logging"] is True
    assert trail["latest_delivery_error"] is None


def test_denied_describe_trails_marks_trails_unreadable():
    client = StubClient({"describe_trails": client_error("AccessDenied")})
    data = cloudtrail.collect(StubSession({"cloudtrail": client}), {})
    assert data["trails_readable"] is False and data["trails"] == []
    assert data["errors"][0]["required_permissions"] == ["cloudtrail:DescribeTrails"]


def test_denied_trail_status_leaves_logging_unknown_but_keeps_the_trail():
    client = StubClient(
        {
            "describe_trails": {"trailList": [{"Name": "t", "TrailARN": "arn:x"}]},
            "get_trail_status": client_error("AccessDenied"),
        }
    )
    data = cloudtrail.collect(StubSession({"cloudtrail": client}), {})
    assert data["trails"][0]["is_logging"] is None
    assert data["trails"][0]["log_file_validation_enabled"] is False  # config still read


def test_shadow_trails_are_excluded_so_one_trail_is_not_counted_many_times():
    client = StubClient({"describe_trails": {"trailList": []}, "get_trail_status": {"IsLogging": True}})
    cloudtrail.collect(StubSession({"cloudtrail": client}), {})
    assert client.calls[0] == ("describe_trails", {"includeShadowTrails": False})


# ------------------------------------------- emulated AWS (real boto3) ------


@pytest.mark.usefixtures("aws")
def test_collectors_run_against_real_boto3_clients():
    """The happy path through genuine paginators, serialisers, and parsers."""
    import boto3

    session = boto3.session.Session(region_name="us-east-1")
    client = session.client("iam")
    client.create_user(UserName="emulated-user")
    client.put_user_policy(
        UserName="emulated-user",
        PolicyName="p",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )
    key = client.create_access_key(UserName="emulated-user")["AccessKey"]["AccessKeyId"]

    s3_client = session.client("s3")
    s3_client.create_bucket(Bucket="emulated-bucket")

    iam_data = iam.collect(session, {})
    user = iam_data["users"][0]
    assert user["username"] == "emulated-user"
    assert user["access_keys"][0]["access_key_id"] == key
    assert user["policies"][0]["document"]["Statement"][0]["Action"] == "*"

    s3_data = s3.collect(session, {})
    assert s3_data["buckets"][0]["name"] == "emulated-bucket"
    assert s3_data["buckets"][0]["public_access_block"] is None

    ct_data = cloudtrail.collect(session, {})
    assert ct_data["trails_readable"] is True and ct_data["trails"] == []
