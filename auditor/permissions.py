"""The auditor's API surface, declared once and used for three purposes.

1. It generates the least-privilege IAM policy in ``policies/``. The policy is
   derived from this inventory rather than maintained by hand, so it cannot
   drift from what the code calls (a test asserts the committed file matches).
2. It backs the runtime read-only guard in ``auditor.readonly``: a botocore hook
   rejects any API operation that is not in this inventory, so an accidental
   write call fails before it reaches AWS rather than after.
3. It documents, per call, why the permission is needed and why its resource
   scope is what it is.

Every entry here is a read operation. There is no write path in the auditor,
and ``assert_all_read_only()`` -- exercised by the test suite -- states that as
an executable claim rather than a promise in a README.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

# Read-only verbs. An AWS API operation whose name does not start with one of
# these mutates something, so it may not appear in the inventory below.
READ_ONLY_VERBS: tuple[str, ...] = ("Get", "List", "Describe", "Head", "Lookup", "Select", "Batch Get")

# IAM ARN patterns. The account segment is left as "*" because the policy is
# published as a template; scoping it to one account is a documented, optional
# tightening step (see docs/least-privilege.md).
_IAM_USERS = "arn:aws:iam::*:user/*"
_IAM_GROUPS = "arn:aws:iam::*:group/*"
_IAM_ROLES = "arn:aws:iam::*:role/*"
_IAM_POLICIES = ("arn:aws:iam::*:policy/*", "arn:aws:iam::aws:policy/*")
_S3_BUCKETS = "arn:aws:s3:::*"
_CT_TRAILS = "arn:aws:cloudtrail:*:*:trail/*"


@dataclass(frozen=True)
class ApiCall:
    """One AWS API operation the auditor is allowed to make."""

    service: str  # botocore service name, e.g. "iam"
    operation: str  # wire operation name, e.g. "ListUsers"
    boto3_method: str  # the client method the code calls
    iam_action: str  # the IAM action that authorises it
    statement_id: str  # which policy statement it lands in
    resources: tuple[str, ...]
    purpose: str
    used_by: tuple[str, ...]  # collector module(s) that make the call

    @property
    def key(self) -> str:
        """``service:Operation`` -- how the runtime guard identifies a call."""
        return f"{self.service}:{self.operation}"

    @property
    def is_read_only(self) -> bool:
        return self.operation.startswith(READ_ONLY_VERBS)


API_CALLS: tuple[ApiCall, ...] = (
    # ---------------------------------------------------------------- STS ---
    ApiCall(
        service="sts",
        operation="GetCallerIdentity",
        boto3_method="get_caller_identity",
        iam_action="sts:GetCallerIdentity",
        statement_id="AuditorIdentity",
        resources=("*",),
        purpose="Resolve the account ID and caller ARN for the report header, and fail fast on bad credentials.",
        used_by=("auditor.aws_session",),
    ),
    # ---------------------------------------------------------------- IAM ---
    ApiCall(
        service="iam",
        operation="ListUsers",
        boto3_method="list_users",
        iam_action="iam:ListUsers",
        statement_id="AuditorListPrincipals",
        resources=("*",),
        purpose="Enumerate IAM users for IAM-001/002/003/004/005/006.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListGroups",
        boto3_method="list_groups",
        iam_action="iam:ListGroups",
        statement_id="AuditorListPrincipals",
        resources=("*",),
        purpose="Enumerate IAM groups so group-inherited policies are covered by IAM-004/005.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListRoles",
        boto3_method="list_roles",
        iam_action="iam:ListRoles",
        statement_id="AuditorListPrincipals",
        resources=("*",),
        purpose="Enumerate IAM roles so role policies are covered by IAM-004/005.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="GetLoginProfile",
        boto3_method="get_login_profile",
        iam_action="iam:GetLoginProfile",
        statement_id="AuditorReadUsers",
        resources=(_IAM_USERS,),
        purpose="Determine whether a user has console access (IAM-001 vs IAM-006).",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListMFADevices",
        boto3_method="list_mfa_devices",
        iam_action="iam:ListMFADevices",
        statement_id="AuditorReadUsers",
        resources=(_IAM_USERS,),
        purpose="Count registered MFA devices for IAM-001 and IAM-006.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListAccessKeys",
        boto3_method="list_access_keys",
        iam_action="iam:ListAccessKeys",
        statement_id="AuditorReadUsers",
        resources=(_IAM_USERS,),
        purpose="Read access key IDs, status, and creation dates for IAM-002 and IAM-003.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="GetAccessKeyLastUsed",
        boto3_method="get_access_key_last_used",
        iam_action="iam:GetAccessKeyLastUsed",
        statement_id="AuditorReadUsers",
        resources=(_IAM_USERS,),
        purpose="Read last-used timestamps so IAM-003 can distinguish a dormant key from an active one.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListGroupsForUser",
        boto3_method="list_groups_for_user",
        iam_action="iam:ListGroupsForUser",
        statement_id="AuditorReadUsers",
        resources=(_IAM_USERS,),
        purpose="Record group membership so a group-level finding names the users it affects.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListAttachedUserPolicies",
        boto3_method="list_attached_user_policies",
        iam_action="iam:ListAttachedUserPolicies",
        statement_id="AuditorReadUsers",
        resources=(_IAM_USERS,),
        purpose="Find managed policies attached directly to a user (IAM-004/005).",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListUserPolicies",
        boto3_method="list_user_policies",
        iam_action="iam:ListUserPolicies",
        statement_id="AuditorReadUsers",
        resources=(_IAM_USERS,),
        purpose="Find inline user policies (IAM-004/005).",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="GetUserPolicy",
        boto3_method="get_user_policy",
        iam_action="iam:GetUserPolicy",
        statement_id="AuditorReadUsers",
        resources=(_IAM_USERS,),
        purpose="Read an inline user policy document for wildcard analysis.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListAttachedGroupPolicies",
        boto3_method="list_attached_group_policies",
        iam_action="iam:ListAttachedGroupPolicies",
        statement_id="AuditorReadGroups",
        resources=(_IAM_GROUPS,),
        purpose="Find managed policies attached to a group (IAM-004/005).",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListGroupPolicies",
        boto3_method="list_group_policies",
        iam_action="iam:ListGroupPolicies",
        statement_id="AuditorReadGroups",
        resources=(_IAM_GROUPS,),
        purpose="Find inline group policies (IAM-004/005).",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="GetGroupPolicy",
        boto3_method="get_group_policy",
        iam_action="iam:GetGroupPolicy",
        statement_id="AuditorReadGroups",
        resources=(_IAM_GROUPS,),
        purpose="Read an inline group policy document for wildcard analysis.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="GetGroup",
        boto3_method="get_group",
        iam_action="iam:GetGroup",
        statement_id="AuditorReadGroups",
        resources=(_IAM_GROUPS,),
        purpose="List group members so a group finding reports which users inherit the policy.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListAttachedRolePolicies",
        boto3_method="list_attached_role_policies",
        iam_action="iam:ListAttachedRolePolicies",
        statement_id="AuditorReadRoles",
        resources=(_IAM_ROLES,),
        purpose="Find managed policies attached to a role (IAM-004/005).",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="ListRolePolicies",
        boto3_method="list_role_policies",
        iam_action="iam:ListRolePolicies",
        statement_id="AuditorReadRoles",
        resources=(_IAM_ROLES,),
        purpose="Find inline role policies (IAM-004/005).",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="GetRolePolicy",
        boto3_method="get_role_policy",
        iam_action="iam:GetRolePolicy",
        statement_id="AuditorReadRoles",
        resources=(_IAM_ROLES,),
        purpose="Read an inline role policy document for wildcard analysis.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="GetPolicy",
        boto3_method="get_policy",
        iam_action="iam:GetPolicy",
        statement_id="AuditorReadPolicyDocuments",
        resources=_IAM_POLICIES,
        purpose="Resolve a managed policy's default version ID.",
        used_by=("auditor.collectors.iam",),
    ),
    ApiCall(
        service="iam",
        operation="GetPolicyVersion",
        boto3_method="get_policy_version",
        iam_action="iam:GetPolicyVersion",
        statement_id="AuditorReadPolicyDocuments",
        resources=_IAM_POLICIES,
        purpose="Read the managed policy document itself for wildcard analysis.",
        used_by=("auditor.collectors.iam",),
    ),
    # ----------------------------------------------------------------- S3 ---
    ApiCall(
        service="s3",
        operation="ListBuckets",
        boto3_method="list_buckets",
        iam_action="s3:ListAllMyBuckets",
        statement_id="AuditorListBuckets",
        resources=("*",),
        purpose="Enumerate buckets. s3:ListAllMyBuckets is account-scoped and does not support resource-level conditions.",
        used_by=("auditor.collectors.s3",),
    ),
    ApiCall(
        service="s3",
        operation="GetBucketLocation",
        boto3_method="get_bucket_location",
        iam_action="s3:GetBucketLocation",
        statement_id="AuditorReadBuckets",
        resources=(_S3_BUCKETS,),
        purpose="Record each bucket's region in the report.",
        used_by=("auditor.collectors.s3",),
    ),
    ApiCall(
        service="s3",
        operation="GetPublicAccessBlock",
        boto3_method="get_public_access_block",
        iam_action="s3:GetBucketPublicAccessBlock",
        statement_id="AuditorReadBuckets",
        resources=(_S3_BUCKETS,),
        purpose="Read the four Block Public Access settings for S3-001, and for the severity of S3-002/S3-003.",
        used_by=("auditor.collectors.s3",),
    ),
    ApiCall(
        service="s3",
        operation="GetBucketAcl",
        boto3_method="get_bucket_acl",
        iam_action="s3:GetBucketAcl",
        statement_id="AuditorReadBuckets",
        resources=(_S3_BUCKETS,),
        purpose="Detect global-group ACL grants for S3-002.",
        used_by=("auditor.collectors.s3",),
    ),
    ApiCall(
        service="s3",
        operation="GetBucketPolicy",
        boto3_method="get_bucket_policy",
        iam_action="s3:GetBucketPolicy",
        statement_id="AuditorReadBuckets",
        resources=(_S3_BUCKETS,),
        purpose="Read the bucket policy document for S3-003.",
        used_by=("auditor.collectors.s3",),
    ),
    ApiCall(
        service="s3",
        operation="GetBucketPolicyStatus",
        boto3_method="get_bucket_policy_status",
        iam_action="s3:GetBucketPolicyStatus",
        statement_id="AuditorReadBuckets",
        resources=(_S3_BUCKETS,),
        purpose="Cross-check the auditor's own policy analysis against S3's IsPublic verdict.",
        used_by=("auditor.collectors.s3",),
    ),
    ApiCall(
        service="s3",
        operation="GetBucketEncryption",
        boto3_method="get_bucket_encryption",
        iam_action="s3:GetEncryptionConfiguration",
        statement_id="AuditorReadBuckets",
        resources=(_S3_BUCKETS,),
        purpose="Detect the absence of an explicit default encryption configuration for S3-004.",
        used_by=("auditor.collectors.s3",),
    ),
    # --------------------------------------------------------- CloudTrail ---
    ApiCall(
        service="cloudtrail",
        operation="DescribeTrails",
        boto3_method="describe_trails",
        iam_action="cloudtrail:DescribeTrails",
        statement_id="AuditorReadCloudTrail",
        resources=("*",),
        purpose="Enumerate trail configuration for CT-001/002/003. Does not support resource-level conditions.",
        used_by=("auditor.collectors.cloudtrail",),
    ),
    ApiCall(
        service="cloudtrail",
        operation="GetTrailStatus",
        boto3_method="get_trail_status",
        iam_action="cloudtrail:GetTrailStatus",
        statement_id="AuditorReadTrailStatus",
        resources=(_CT_TRAILS,),
        purpose="Read operational logging status and delivery errors for CT-004.",
        used_by=("auditor.collectors.cloudtrail",),
    ),
)

# ``service:Operation`` keys the runtime guard admits.
ALLOWED_OPERATIONS: frozenset = frozenset(call.key for call in API_CALLS)

# IAM actions the generated policy grants.
ALLOWED_IAM_ACTIONS: tuple[str, ...] = tuple(sorted({call.iam_action for call in API_CALLS}))

# Statement order in the generated policy, most general first.
_STATEMENT_ORDER = (
    "AuditorIdentity",
    "AuditorListPrincipals",
    "AuditorReadUsers",
    "AuditorReadGroups",
    "AuditorReadRoles",
    "AuditorReadPolicyDocuments",
    "AuditorListBuckets",
    "AuditorReadBuckets",
    "AuditorReadCloudTrail",
    "AuditorReadTrailStatus",
)


class ReadOnlyViolation(RuntimeError):
    """A non-read-only or undeclared AWS operation was attempted."""


def assert_all_read_only() -> None:
    """Fail loudly if a write operation was ever added to the inventory.

    This is the executable form of the project's central claim. It is called by
    the test suite and by ``auditor validate-policy``.
    """
    offenders = [call.key for call in API_CALLS if not call.is_read_only]
    if offenders:
        raise ReadOnlyViolation(
            "Non-read-only operations declared in the API inventory: " + ", ".join(offenders)
        )


def is_allowed(service: str, operation: str) -> bool:
    return f"{service}:{operation}" in ALLOWED_OPERATIONS


def calls_for(service: str) -> list[ApiCall]:
    return [call for call in API_CALLS if call.service == service]


def generate_policy(sid_prefix: str = "") -> dict[str, Any]:
    """Build the least-privilege policy document from the inventory.

    One statement per (statement_id, resource set), actions sorted, no wildcard
    actions anywhere. This is the function that writes
    ``policies/auditor-readonly-policy.json``.
    """
    grouped: dict[str, dict[str, Any]] = {}
    for call in API_CALLS:
        entry = grouped.setdefault(call.statement_id, {"actions": set(), "resources": list(call.resources)})
        entry["actions"].add(call.iam_action)
        for resource in call.resources:
            if resource not in entry["resources"]:
                entry["resources"].append(resource)

    statements: list[dict[str, Any]] = []
    for statement_id in _STATEMENT_ORDER:
        if statement_id not in grouped:  # pragma: no cover - guards a typo above
            continue
        entry = grouped[statement_id]
        resources = entry["resources"]
        statements.append(
            {
                "Sid": f"{sid_prefix}{statement_id}",
                "Effect": "Allow",
                "Action": sorted(entry["actions"]),
                "Resource": resources[0] if len(resources) == 1 else sorted(resources),
            }
        )

    missing = set(grouped) - set(_STATEMENT_ORDER)
    if missing:  # pragma: no cover - guards a typo above
        raise RuntimeError(f"Statement id(s) missing from _STATEMENT_ORDER: {sorted(missing)}")

    return {"Version": "2012-10-17", "Statement": statements}


def inventory_rows() -> list[dict[str, Any]]:
    """The code -> IAM action -> statement table, for docs and `list-permissions`."""
    return [
        {
            "service": call.service,
            "boto3_call": f"{call.service}.{call.boto3_method}()",
            "aws_operation": call.operation,
            "iam_action": call.iam_action,
            "statement": call.statement_id,
            "resource_scope": list(call.resources),
            "read_only": call.is_read_only,
            "purpose": call.purpose,
            "used_by": list(call.used_by),
        }
        for call in API_CALLS
    ]


def unused_permissions(required: Sequence[str]) -> list[str]:
    """Actions granted by the policy that no rule declares a need for."""
    return sorted(set(ALLOWED_IAM_ACTIONS) - set(required))
