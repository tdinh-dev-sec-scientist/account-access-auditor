"""The project's security claims, as tests.

Three claims are asserted here, each against the real AWS API surface rather
than a hand-written list of "bad words":

1. No source file under ``auditor/`` references a write operation of any AWS
   service the tool uses. The set of write operations is derived from botocore's
   own service models, so it stays correct as botocore adds APIs.
2. Every AWS operation the auditor's source does reference is declared in
   ``auditor.permissions.API_CALLS`` -- so the generated IAM policy cannot fall
   behind the code.
3. The runtime guard blocks an undeclared operation before it is sent.

Also checked: no credential material is committed, and the generated policy
grants no wildcard action.
"""

from __future__ import annotations

import ast
import os
import re

import boto3
import pytest

from auditor import permissions
from auditor.permissions import ReadOnlyViolation
from auditor.readonly import ReadOnlyGuard, install_read_only_guard

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDITOR_DIR = os.path.join(REPO_ROOT, "auditor")
SERVICES = ["iam", "s3", "cloudtrail", "sts"]

# Operation-name prefixes that only read. Everything else in a service model is
# treated as a write and must not appear in auditor/.
READ_PREFIXES = ("Get", "List", "Describe", "Head", "Lookup", "Select")


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower().replace("__", "_")


def _service_operations() -> dict[str, dict[str, str]]:
    """{service: {snake_method: OperationName}} from botocore's own models."""
    # boto3 exposes the loader through the underlying botocore session.
    session = boto3.session.Session()._session
    result: dict[str, dict[str, str]] = {}
    for service in SERVICES:
        model = session.get_service_model(service)
        result[service] = {_snake(op): op for op in model.operation_names}
    return result


SERVICE_OPERATIONS = _service_operations()

WRITE_METHODS: set[str] = {
    method
    for operations in SERVICE_OPERATIONS.values()
    for method, operation in operations.items()
    if not operation.startswith(READ_PREFIXES)
}

ALL_METHODS: set[str] = {method for operations in SERVICE_OPERATIONS.values() for method in operations}

# Names that collide with ordinary Python, not with an AWS call.
_NOT_API_CALLS = {"get_paginator", "can_paginate", "get_available_subresources"}


def _auditor_sources():
    for root, _, files in os.walk(AUDITOR_DIR):
        for name in sorted(files):
            if name.endswith(".py"):
                yield os.path.join(root, name)


def _referenced_identifiers(path: str) -> set[str]:
    """Attribute names and string literals in a module.

    Both forms matter: collectors call ``client.list_users()`` directly and also
    pass ``"list_users"`` to the pagination helper as a string.
    """
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.add(node.value)
    return names


def test_botocore_model_lookup_found_real_operations():
    """Sanity-check the derivation before trusting the assertions built on it."""
    assert "create_user" in WRITE_METHODS
    assert "delete_bucket" in WRITE_METHODS
    assert "put_bucket_policy" in WRITE_METHODS
    assert "attach_user_policy" in WRITE_METHODS
    assert "stop_logging" in WRITE_METHODS
    assert "list_users" not in WRITE_METHODS
    assert "get_bucket_acl" not in WRITE_METHODS
    assert len(WRITE_METHODS) > 200


@pytest.mark.parametrize("path", list(_auditor_sources()), ids=lambda p: os.path.relpath(p, REPO_ROOT))
def test_no_write_operation_appears_in_auditor_source(path):
    offenders = sorted(_referenced_identifiers(path) & WRITE_METHODS)
    assert not offenders, (
        f"{os.path.relpath(path, REPO_ROOT)} references AWS write operation(s): {offenders}. "
        "The auditor must never modify an account."
    )


def test_every_api_call_in_source_is_declared_in_the_permission_inventory():
    declared = {call.boto3_method for call in permissions.API_CALLS}
    referenced: set[str] = set()
    for path in _auditor_sources():
        referenced |= _referenced_identifiers(path) & ALL_METHODS
    referenced -= _NOT_API_CALLS

    undeclared = sorted(referenced - declared)
    assert not undeclared, (
        f"AWS calls made by the code but missing from auditor/permissions.py: {undeclared}. "
        "The generated IAM policy is derived from that inventory, so an undeclared call "
        "would fail at runtime with AccessDenied."
    )


def test_declared_inventory_contains_only_read_operations():
    permissions.assert_all_read_only()
    for call in permissions.API_CALLS:
        assert call.operation not in WRITE_METHODS
        assert call.is_read_only, call.key


def test_inventory_has_no_permission_the_rules_do_not_need():
    """No permission is granted 'just in case'."""
    from auditor.collectors import REQUIRED_PERMISSIONS

    needed = {"sts:GetCallerIdentity"}
    for actions in REQUIRED_PERMISSIONS.values():
        needed.update(actions)

    unused = permissions.unused_permissions(sorted(needed))
    assert not unused, f"policy grants actions no collector declares: {unused}"


def test_generated_policy_has_no_wildcard_action():
    document = permissions.generate_policy()
    for statement in document["Statement"]:
        assert statement["Effect"] == "Allow"
        for action in statement["Action"]:
            assert action != "*", "the auditor policy must never grant Action *"
            assert not action.endswith(":*"), f"service-wide wildcard in the policy: {action}"


def test_committed_policy_matches_the_generated_one():
    """The policy file is derived from the code, so it cannot silently drift."""
    import json

    path = os.path.join(REPO_ROOT, "policies", "auditor-readonly-policy.json")
    with open(path, encoding="utf-8") as handle:
        committed = json.load(handle)
    assert committed == permissions.generate_policy(), (
        "policies/auditor-readonly-policy.json is out of date. "
        "Regenerate it with: python -m auditor.cli generate-policy --write"
    )


def test_runtime_guard_blocks_an_undeclared_operation():
    guard = ReadOnlyGuard()

    class FakeServiceModel:
        service_name = "iam"

    class FakeOperationModel:
        name = "CreateUser"
        service_model = FakeServiceModel()

    with pytest.raises(ReadOnlyViolation, match="iam:CreateUser"):
        guard(model=FakeOperationModel())
    assert guard.observed == ["iam:CreateUser"]


def test_runtime_guard_allows_a_declared_operation():
    guard = ReadOnlyGuard()

    class FakeServiceModel:
        service_name = "iam"

    class FakeOperationModel:
        name = "ListUsers"
        service_model = FakeServiceModel()

    guard(model=FakeOperationModel())
    assert guard.counts_by_operation() == {"iam:ListUsers": 1}
    guard.reset()
    assert guard.call_count == 0


def test_guard_installs_on_a_real_session():
    session = boto3.session.Session(region_name="us-east-1")
    guard = install_read_only_guard(session)
    assert guard.allowed == permissions.ALLOWED_OPERATIONS


def test_no_credential_material_is_committed():
    """A committed key is a live incident, so this is checked, not assumed."""
    patterns = [
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
        (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "AWS temporary access key ID"),
        (re.compile(r"aws_secret_access_key\s*=\s*\S+", re.I), "aws_secret_access_key assignment"),
        (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    ]
    # The placeholder "AKIAEXAMPLE" and friends are shorter than a real key ID,
    # so the 16-character patterns above do not match them by construction.
    skip_dirs = {".git", "__pycache__", ".venv", "venv", ".pytest_cache", "htmlcov", "reports"}
    offenders = []

    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            path = os.path.join(root, name)
            if os.path.splitext(name)[1] not in {
                ".py",
                ".json",
                ".yaml",
                ".yml",
                ".md",
                ".txt",
                ".cfg",
                ".ini",
                "",
            }:
                continue
            try:
                with open(path, encoding="utf-8") as handle:
                    content = handle.read()
            except (OSError, UnicodeDecodeError):  # pragma: no cover
                continue
            for pattern, label in patterns:
                if pattern.search(content):
                    offenders.append(f"{os.path.relpath(path, REPO_ROOT)}: {label}")

    assert not offenders, f"possible credential material committed: {offenders}"


def test_lab_write_code_is_not_importable_from_the_auditor():
    """The auditor must not depend on the package that makes write calls."""
    for path in _auditor_sources():
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        assert "import lab" not in source and "from lab" not in source, (
            f"{os.path.relpath(path, REPO_ROOT)} imports the lab provisioner"
        )
