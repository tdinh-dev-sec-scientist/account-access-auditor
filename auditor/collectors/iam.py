"""IAM collector: users, groups, roles, credentials, and attached policies.

Coverage note: policies are collected from all three principal types, including
group-inherited policies, so an over-broad policy attached to a group is found
once at the group rather than missed entirely. Service-linked roles are skipped
because their policies are AWS-defined and not editable; the count of skipped
roles is reported so the omission is visible rather than silent.
"""

from __future__ import annotations

import logging
from typing import Any

from ..normalize import iam as normalize
from ._common import AWS_EXCEPTIONS, NOT_CONFIGURED, OK, paginate, record_error, safe_call

log = logging.getLogger(__name__)

SERVICE = "IAM"

REQUIRED_PERMISSIONS = [
    "iam:ListUsers",
    "iam:ListGroups",
    "iam:ListRoles",
    "iam:GetLoginProfile",
    "iam:ListMFADevices",
    "iam:ListAccessKeys",
    "iam:GetAccessKeyLastUsed",
    "iam:ListGroupsForUser",
    "iam:ListAttachedUserPolicies",
    "iam:ListUserPolicies",
    "iam:GetUserPolicy",
    "iam:ListAttachedGroupPolicies",
    "iam:ListGroupPolicies",
    "iam:GetGroupPolicy",
    "iam:GetGroup",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
]


def collect(session, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return normalized IAM state.

    ``{"users": [...], "groups": [...], "roles": [...], "errors": [...]}``
    """
    settings = (config or {}).get("iam", {})
    client = session.client("iam")
    errors: list[dict[str, Any]] = []

    log.info("Starting IAM collection")
    users = _collect_users(client, errors)
    groups = _collect_groups(client, errors) if settings.get("include_groups", True) else []
    roles, skipped_roles = _collect_roles(client, errors) if settings.get("include_roles", True) else ([], 0)

    log.info(
        "IAM collection complete: %d users, %d groups, %d roles (%d service-linked roles skipped)",
        len(users),
        len(groups),
        len(roles),
        skipped_roles,
    )
    return {
        "users": users,
        "groups": groups,
        "roles": roles,
        "service_linked_roles_skipped": skipped_roles,
        "errors": errors,
    }


# -------------------------------------------------------------------- users --


def _collect_users(client, errors) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    try:
        for page in paginate(client, "list_users"):
            for raw in page.get("Users", []):
                users.append(_collect_user(client, raw, errors))
    except AWS_EXCEPTIONS as exc:
        record_error(errors, SERVICE, "iam:ListUsers", exc, required_permissions=["iam:ListUsers"])
    return users


def _collect_user(client, raw: dict[str, Any], errors) -> dict[str, Any]:
    user = normalize.user_identity(raw)
    username = user["username"]
    own = user["collection_errors"]

    # Console access. NoSuchEntity is the documented way IAM says "no password",
    # so it is data, not an error; a denied call leaves the field unknown.
    _, outcome = safe_call(
        errors,
        own,
        SERVICE,
        "iam:GetLoginProfile",
        lambda: client.get_login_profile(UserName=username),
        username,
        ["iam:GetLoginProfile"],
    )
    if outcome == OK:
        user["console_access_enabled"] = True
    elif outcome == NOT_CONFIGURED:
        user["console_access_enabled"] = False

    response, outcome = safe_call(
        errors,
        own,
        SERVICE,
        "iam:ListMFADevices",
        lambda: client.list_mfa_devices(UserName=username),
        username,
        ["iam:ListMFADevices"],
    )
    if outcome == OK:
        user.update(normalize.mfa_devices(response))

    user["access_keys"] = _collect_access_keys(client, username, errors, own)
    user["group_names"] = _collect_group_names(client, username, errors, own)
    user["policies"] = _collect_user_policies(client, username, errors, own)
    return user


def _collect_access_keys(client, username, errors, own) -> list[dict[str, Any]]:
    keys: list[dict[str, Any]] = []
    try:
        for page in paginate(client, "list_access_keys", UserName=username):
            for metadata in page.get("AccessKeyMetadata", []):
                keys.append(_collect_access_key(client, metadata, errors, own))
    except AWS_EXCEPTIONS as exc:
        record_error(errors, SERVICE, "iam:ListAccessKeys", exc, username, ["iam:ListAccessKeys"])
        own.append(errors[-1])
    return keys


def _collect_access_key(client, metadata, errors, own) -> dict[str, Any]:
    key_id = metadata.get("AccessKeyId")
    last_used, outcome = safe_call(
        errors,
        own,
        SERVICE,
        "iam:GetAccessKeyLastUsed",
        lambda: client.get_access_key_last_used(AccessKeyId=key_id),
        key_id,
        ["iam:GetAccessKeyLastUsed"],
    )
    # last_used_known=False tells IAM-003 to stay silent rather than call a key
    # dormant on the basis of data it never received.
    return normalize.access_key(metadata, last_used, last_used_known=outcome == OK)


def _collect_group_names(client, username, errors, own) -> list[str]:
    names: list[str] = []
    try:
        for page in paginate(client, "list_groups_for_user", UserName=username):
            names.extend(normalize.group_names(page))
    except AWS_EXCEPTIONS as exc:
        record_error(errors, SERVICE, "iam:ListGroupsForUser", exc, username, ["iam:ListGroupsForUser"])
        own.append(errors[-1])
    return names


def _collect_user_policies(client, username, errors, own) -> list[dict[str, Any]]:
    return _collect_policies(
        client,
        errors,
        own,
        principal=username,
        list_attached=("iam:ListAttachedUserPolicies", "list_attached_user_policies", {"UserName": username}),
        list_inline=("iam:ListUserPolicies", "list_user_policies", {"UserName": username}),
        get_inline=(
            "iam:GetUserPolicy",
            lambda name: client.get_user_policy(UserName=username, PolicyName=name),
        ),
    )


# ------------------------------------------------------------------- groups --


def _collect_groups(client, errors) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    try:
        for page in paginate(client, "list_groups"):
            for raw in page.get("Groups", []):
                groups.append(_collect_group(client, raw, errors))
    except AWS_EXCEPTIONS as exc:
        record_error(errors, SERVICE, "iam:ListGroups", exc, required_permissions=["iam:ListGroups"])
    return groups


def _collect_group(client, raw, errors) -> dict[str, Any]:
    group = normalize.group_record(raw)
    name = group["name"]
    own = group["collection_errors"]

    group["policies"] = _collect_policies(
        client,
        errors,
        own,
        principal=name,
        list_attached=("iam:ListAttachedGroupPolicies", "list_attached_group_policies", {"GroupName": name}),
        list_inline=("iam:ListGroupPolicies", "list_group_policies", {"GroupName": name}),
        get_inline=(
            "iam:GetGroupPolicy",
            lambda pname: client.get_group_policy(GroupName=name, PolicyName=pname),
        ),
    )

    members, outcome = safe_call(
        errors,
        own,
        SERVICE,
        "iam:GetGroup",
        lambda: client.get_group(GroupName=name),
        name,
        ["iam:GetGroup"],
    )
    if outcome == OK:
        group["member_usernames"] = [u.get("UserName") for u in (members or {}).get("Users", [])]
    return group


# -------------------------------------------------------------------- roles --


def _collect_roles(client, errors):
    roles: list[dict[str, Any]] = []
    skipped = 0
    try:
        for page in paginate(client, "list_roles"):
            for raw in page.get("Roles", []):
                if normalize.is_service_linked_role(raw):
                    skipped += 1
                    continue
                roles.append(_collect_role(client, raw, errors))
    except AWS_EXCEPTIONS as exc:
        record_error(errors, SERVICE, "iam:ListRoles", exc, required_permissions=["iam:ListRoles"])
    return roles, skipped


def _collect_role(client, raw, errors) -> dict[str, Any]:
    role = normalize.role_record(raw)
    name = role["name"]
    own = role["collection_errors"]
    role["policies"] = _collect_policies(
        client,
        errors,
        own,
        principal=name,
        list_attached=("iam:ListAttachedRolePolicies", "list_attached_role_policies", {"RoleName": name}),
        list_inline=("iam:ListRolePolicies", "list_role_policies", {"RoleName": name}),
        get_inline=(
            "iam:GetRolePolicy",
            lambda pname: client.get_role_policy(RoleName=name, PolicyName=pname),
        ),
    )
    return role


# ----------------------------------------------------------------- policies --


def _collect_policies(client, errors, own, principal, list_attached, list_inline, get_inline):
    """Managed + inline policies for one principal, shared by all three types."""
    policies: list[dict[str, Any]] = []

    attached_action, attached_method, attached_kwargs = list_attached
    try:
        for page in paginate(client, attached_method, **attached_kwargs):
            for attached in page.get("AttachedPolicies", []):
                arn = attached.get("PolicyArn")
                document = _managed_policy_document(client, arn, errors, own)
                policies.append(normalize.policy_record(attached.get("PolicyName"), document, "managed", arn))
    except AWS_EXCEPTIONS as exc:
        record_error(errors, SERVICE, attached_action, exc, principal, [attached_action])
        own.append(errors[-1])

    inline_action, inline_method, inline_kwargs = list_inline
    get_action, get_document = get_inline
    try:
        for page in paginate(client, inline_method, **inline_kwargs):
            for name in page.get("PolicyNames", []):
                response, outcome = safe_call(
                    errors,
                    own,
                    SERVICE,
                    get_action,
                    lambda n=name: get_document(n),
                    f"{principal}/{name}",
                    [get_action],
                )
                document = (response or {}).get("PolicyDocument") if outcome == OK else None
                policies.append(normalize.policy_record(name, document, "inline"))
    except AWS_EXCEPTIONS as exc:
        record_error(errors, SERVICE, inline_action, exc, principal, [inline_action])
        own.append(errors[-1])

    return policies


def _managed_policy_document(client, policy_arn, errors, own) -> dict[str, Any] | None:
    policy, outcome = safe_call(
        errors,
        own,
        SERVICE,
        "iam:GetPolicy",
        lambda: client.get_policy(PolicyArn=policy_arn),
        policy_arn,
        ["iam:GetPolicy"],
    )
    if outcome != OK:
        return None

    version_id = (policy or {}).get("Policy", {}).get("DefaultVersionId")
    if not version_id:
        return None

    version, outcome = safe_call(
        errors,
        own,
        SERVICE,
        "iam:GetPolicyVersion",
        lambda: client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id),
        policy_arn,
        ["iam:GetPolicyVersion"],
    )
    if outcome != OK:
        return None
    return normalize.managed_policy_document(policy, version)
