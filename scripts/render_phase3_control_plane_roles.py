#!/usr/bin/env python3
"""Render the GitHub OIDC plan and apply roles for the Phase 3 control-plane stack.

    python scripts/render_phase3_control_plane_roles.py --profile vorrin-admin \\
        --state-bucket vorrin-tfstate-1234abcd --lock-table vorrin-tf-locks --bucket-prefix vorrin

The control plane runs in the organization's management account. With
--profile, that account and the demo account are discovered with read-only
calls (sts:GetCallerIdentity and organizations Describe/List); pass
--account-id and --demo-account-id to render offline.

Three kinds of document are rendered to build/phase3/roles/control-plane/
(gitignored, because they contain account IDs):

* plan and apply trust policies, pinned to the protected GitHub environments;
* the plan role's inline policy: configuration reads, never data reads or writes;
* the apply role's inline core plus managed write policies (IAM caps one role's
  inline policies at 10,240 characters, so the scoped writes are split out);
* the workload permissions boundary. Every role Terraform creates must carry
  it, and it removes all IAM and Organizations permissions from those roles,
  so the apply role cannot create a role more powerful than itself.

The script prints the aws iam commands and never changes AWS itself.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from string import Template
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.render_phase3_org_roles import (  # noqa: E402
    _PATTERNS,
    POLICIES,
    RenderError,
    render_role_set,
    write_documents,
)

DEFAULT_OUTPUT = ROOT / "build/phase3/roles/control-plane"
ROLES = {
    "plan": ("Phase3ControlPlaneTerraformPlan", "phase3-control-plane-plan", "control-plane-plan.json"),
    "apply": ("Phase3ControlPlaneTerraformApply", "phase3-control-plane-apply", "control-plane-apply.json"),
}
BOUNDARY_TEMPLATE = "control-plane-workload-boundary.json"
DEFAULT_BOUNDARY = "Phase3ControlPlaneWorkloadBoundary"
MANAGED_PREFIX = "Phase3ControlPlaneTerraformApplyManage"
INLINE_LIMIT = 10_240
MANAGED_LIMIT = 6_144
_VALUE_PATTERNS = {
    "account_id": _PATTERNS["account_id"],
    "demo_account_id": _PATTERNS["demo_account_id"],
    "state_bucket": _PATTERNS["state_bucket"],
    "lock_table": _PATTERNS["lock_table"],
    "region": _PATTERNS["region"],
    "bucket_prefix": r"[a-z0-9][a-z0-9-]{2,20}",
    "boundary_name": r"[A-Za-z0-9+=,.@_-]{1,128}",
}


def managed_templates() -> list[Path]:
    return sorted(POLICIES.glob("control-plane-apply-manage-*.json"))


def _size(document: dict[str, Any]) -> int:
    return len(json.dumps(document, separators=(",", ":")))


def render_documents(values: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Return every filled document, keyed by its output file stem."""
    for name, pattern in _VALUE_PATTERNS.items():
        value = values.get(name)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise RenderError(f"{name} is missing or invalid")
    if values["account_id"] == values["demo_account_id"]:
        raise RenderError("demo_account_id must differ from the control-plane account")
    filled = {name: values[name] for name in _VALUE_PATTERNS}
    documents = render_role_set(ROLES, filled)
    for index, template in enumerate(managed_templates(), 1):
        documents[f"apply-manage-{index}"] = _fill(template, filled)
    documents["workload-boundary"] = _fill(POLICIES / BOUNDARY_TEMPLATE, filled)

    inline_total = _size(documents["apply-permissions"])
    if inline_total > INLINE_LIMIT or _size(documents["plan-permissions"]) > INLINE_LIMIT:
        raise RenderError("an inline policy exceeds the IAM 10,240-character role limit")
    for name, document in documents.items():
        managed = name.startswith("apply-manage-") or name == "workload-boundary"
        if managed and _size(document) > MANAGED_LIMIT:
            raise RenderError(f"{name} exceeds the IAM 6,144-character managed policy limit")
    return documents


def _fill(path: Path, values: dict[str, str]) -> dict[str, Any]:
    rendered = Template(path.read_text(encoding="utf-8")).substitute(values)
    if "${" in rendered:
        raise RenderError(f"{path.name} still contains an unfilled placeholder")
    return json.loads(rendered)


def discover(profile: str, demo_account_name: str) -> dict[str, str]:
    """Read the management and demo account IDs; makes no changes."""
    import boto3

    session = boto3.session.Session(profile_name=profile)
    organizations = session.client("organizations")
    account_id = session.client("sts").get_caller_identity()["Account"]
    organization = organizations.describe_organization()["Organization"]
    if organization["MasterAccountId"] != account_id:
        raise RenderError(
            "the control plane runs in the management account; use a management-account profile"
        )
    matches = [
        account["Id"]
        for page in organizations.get_paginator("list_accounts").paginate()
        for account in page["Accounts"]
        if account["Name"] == demo_account_name and account["Status"] == "ACTIVE"
    ]
    if len(matches) != 1:
        raise RenderError(f"expected exactly one ACTIVE account named {demo_account_name}")
    return {"account_id": account_id, "demo_account_id": matches[0]}


def commands(output: Path, profile: str | None, values: dict[str, str], managed_count: int) -> list[str]:
    flag = f" --profile {profile}" if profile else ""
    policy_arn = f"arn:aws:iam::{values['account_id']}:policy"
    lines = [
        "# 1. The workload boundary every Terraform-created role must carry",
        f"aws iam create-policy{flag} --policy-name {values['boundary_name']} "
        f'--description "Phase 3 control-plane workload boundary: no IAM or Organizations" '
        f"--policy-document file://{output / 'workload-boundary.json'} --query Policy.Arn --output text",
    ]
    for phase, (role, _environment, _file) in ROLES.items():
        lines.append(f"# {'2' if phase == 'plan' else '3'}. The {phase} role")
        lines.append(
            f"aws iam create-role{flag} --role-name {role} --max-session-duration 3600 "
            f"--assume-role-policy-document file://{output / f'{phase}-trust.json'} "
            f'--description "Phase 3 control-plane Terraform {phase} role for GitHub OIDC" '
            "--query Role.Arn --output text"
        )
        lines.append(
            f"aws iam put-role-policy{flag} --role-name {role} --policy-name {role} "
            f"--policy-document file://{output / f'{phase}-permissions.json'}"
        )
    apply_role = ROLES["apply"][0]
    for index in range(1, managed_count + 1):
        name = f"{MANAGED_PREFIX}{index}"
        lines.append(
            f"aws iam create-policy{flag} --policy-name {name} "
            f"--policy-document file://{output / f'apply-manage-{index}.json'} --query Policy.Arn --output text"
        )
        lines.append(
            f"aws iam attach-role-policy{flag} --role-name {apply_role} --policy-arn {policy_arn}/{name}"
        )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", help="Management-account profile, used only for read-only discovery.")
    parser.add_argument("--demo-account-name", default="vorrin-demo")
    parser.add_argument("--account-id", help="Management (control-plane) account ID.")
    parser.add_argument("--demo-account-id", help="Demo account ID the scanner reads.")
    parser.add_argument("--state-bucket", required=True)
    parser.add_argument("--lock-table", required=True)
    parser.add_argument("--bucket-prefix", required=True, help="The PHASE3_BUCKET_PREFIX value, e.g. vorrin.")
    parser.add_argument("--boundary-name", default=DEFAULT_BOUNDARY)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    values = {
        "account_id": args.account_id,
        "demo_account_id": args.demo_account_id,
        "state_bucket": args.state_bucket,
        "lock_table": args.lock_table,
        "region": args.region,
        "bucket_prefix": args.bucket_prefix,
        "boundary_name": args.boundary_name,
    }
    try:
        if args.profile:
            discovered = discover(args.profile, args.demo_account_name)
            values.update({key: value for key, value in discovered.items() if not values.get(key)})
        documents = render_documents(values)
    except RenderError as exc:
        parser.error(str(exc))
    output = args.output_dir.resolve()
    write_documents(documents, output)
    managed = sum(1 for name in documents if name.startswith("apply-manage-"))
    print(f"Rendered {len(documents)} documents to {output}")
    print("Review them, then run these commands in order:\n")
    for line in commands(output, args.profile, values, managed):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
