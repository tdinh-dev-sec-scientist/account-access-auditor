#!/usr/bin/env python3
"""Render the GitHub OIDC plan and apply roles for the Phase 3 org stack.

    python scripts/render_phase3_org_roles.py --profile vorrin-admin \\
        --state-bucket vorrin-tfstate-1234abcd --lock-table vorrin-tf-locks \\
        --demo-account-name vorrin-demo

With --profile, the management account, organization, root, and demo account
IDs are discovered with read-only calls (sts:GetCallerIdentity and
organizations Describe/List). Pass them explicitly to render offline. The
rendered documents go to build/phase3/roles/org/ (gitignored, because they
contain account IDs) and the script prints the aws iam commands to create the
roles. It never creates or changes anything in AWS itself.
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
POLICIES = ROOT / "infra/phase3/policies"
DEFAULT_OUTPUT = ROOT / "build/phase3/roles/org"
sys.path.insert(0, str(ROOT))

from phase3.role_evidence import GITHUB_SUBJECT_REPOSITORY  # noqa: E402

ROLES = {
    "plan": ("Phase3OrgTerraformPlan", "phase3-org-plan", "org-terraform-plan.json"),
    "apply": ("Phase3OrgTerraformApply", "phase3-org-apply", "org-terraform-apply.json"),
}
_PATTERNS = {
    "account_id": r"[0-9]{12}",
    "demo_account_id": r"[0-9]{12}",
    "organization_id": r"o-[a-z0-9]{10,32}",
    "root_id": r"r-[a-z0-9]{4,32}",
    "state_bucket": r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",
    "lock_table": r"[A-Za-z0-9_.-]{3,255}",
    "region": r"[a-z]{2}(?:-[a-z]+)+-[0-9]",
}


class RenderError(ValueError):
    """An input or template could not be rendered safely."""


def render_documents(values: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Return {"plan-trust": ..., "plan-permissions": ..., ...} with every placeholder filled."""
    for name, pattern in _PATTERNS.items():
        value = values.get(name)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise RenderError(f"{name} is missing or invalid")
    documents: dict[str, dict[str, Any]] = {}
    trust_template = (POLICIES / "github-oidc-trust.json").read_text(encoding="utf-8")
    for phase, (_role, environment, permission_file) in ROLES.items():
        substitutions = {
            **values,
            "github_subject_repository": GITHUB_SUBJECT_REPOSITORY,
            "github_environment": environment,
        }
        permission_template = (POLICIES / permission_file).read_text(encoding="utf-8")
        for kind, template in (("trust", trust_template), ("permissions", permission_template)):
            rendered = Template(template).substitute(substitutions)
            if "${" in rendered:
                raise RenderError(f"{phase} {kind} still contains an unfilled placeholder")
            documents[f"{phase}-{kind}"] = json.loads(rendered)
    return documents


def discover(profile: str, demo_account_name: str) -> dict[str, str]:
    """Read the account, organization, root, and demo account IDs; makes no changes."""
    import boto3

    session = boto3.session.Session(profile_name=profile)
    organizations = session.client("organizations")
    account_id = session.client("sts").get_caller_identity()["Account"]
    organization = organizations.describe_organization()["Organization"]
    if organization["MasterAccountId"] != account_id:
        raise RenderError("the profile must belong to the organization's management account")
    roots = organizations.list_roots()["Roots"]
    if len(roots) != 1:
        raise RenderError("expected exactly one organization root")
    matches = [
        account["Id"]
        for page in organizations.get_paginator("list_accounts").paginate()
        for account in page["Accounts"]
        if account["Name"] == demo_account_name and account["Status"] == "ACTIVE"
    ]
    if len(matches) != 1:
        raise RenderError(f"expected exactly one ACTIVE account named {demo_account_name}")
    return {
        "account_id": account_id,
        "organization_id": organization["Id"],
        "root_id": roots[0]["Id"],
        "demo_account_id": matches[0],
    }


def write_documents(documents: dict[str, dict[str, Any]], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name, document in documents.items():
        (output / f"{name}.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def commands(output: Path, profile: str | None) -> list[str]:
    flag = f" --profile {profile}" if profile else ""
    lines = []
    for phase, (role, _environment, _file) in ROLES.items():
        lines.append(
            f"aws iam create-role{flag} --role-name {role} --max-session-duration 3600 "
            f"--assume-role-policy-document file://{output / f'{phase}-trust.json'} "
            f'--description "Phase 3 org Terraform {phase} role for GitHub OIDC" --query Role.Arn --output text'
        )
        lines.append(
            f"aws iam put-role-policy{flag} --role-name {role} --policy-name {role} "
            f"--policy-document file://{output / f'{phase}-permissions.json'}"
        )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--profile", help="AWS profile in the management account, used only for read-only discovery."
    )
    parser.add_argument("--demo-account-name", default="vorrin-demo")
    parser.add_argument("--account-id", help="Management account ID (discovered with --profile).")
    parser.add_argument("--organization-id", help="Organization ID, o-... (discovered with --profile).")
    parser.add_argument("--root-id", help="Organization root ID, r-... (discovered with --profile).")
    parser.add_argument("--demo-account-id", help="Demo account ID (discovered with --profile).")
    parser.add_argument("--state-bucket", required=True)
    parser.add_argument("--lock-table", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    values = {
        "account_id": args.account_id,
        "organization_id": args.organization_id,
        "root_id": args.root_id,
        "demo_account_id": args.demo_account_id,
        "state_bucket": args.state_bucket,
        "lock_table": args.lock_table,
        "region": args.region,
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
    print(f"Rendered {len(documents)} documents to {output}")
    print("Review them, then create the roles:\n")
    for line in commands(output, args.profile):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
