#!/usr/bin/env python3
"""Render the GitHub OIDC plan and apply roles for the Phase 3 demo-bootstrap stack.

    python scripts/render_phase3_demo_bootstrap_roles.py --profile vorrin-demo-admin \\
        --state-bucket vorrin-demo-tfstate-1234abcd --lock-table vorrin-demo-tf-locks

The roles live in the demo account, so --profile must be a demo-account
profile; the script refuses the organization's management account. The demo
account ID is discovered with read-only calls (sts:GetCallerIdentity and
organizations:DescribeOrganization), or passed with --account-id to render
offline. The filled documents go to build/phase3/roles/demo-bootstrap/
(gitignored) and the script prints the aws iam commands. It never creates or
changes anything in AWS itself.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.render_phase3_org_roles import (  # noqa: E402
    _PATTERNS,
    RenderError,
    commands,
    render_role_set,
    write_documents,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "build/phase3/roles/demo-bootstrap"
STATE_KEY = "phase3/demo-bootstrap/terraform.tfstate"
ROLES = {
    "plan": ("Phase3DemoBootstrapPlan", "phase3-demo-bootstrap-plan", "demo-bootstrap-plan.json"),
    "apply": ("Phase3DemoBootstrapApply", "phase3-demo-bootstrap-apply", "demo-bootstrap-apply.json"),
}


def render_documents(values: dict[str, str]) -> dict[str, dict[str, Any]]:
    import re

    for name in ("account_id", "state_bucket", "lock_table", "region"):
        value = values.get(name)
        if not isinstance(value, str) or not re.fullmatch(_PATTERNS[name], value):
            raise RenderError(f"{name} is missing or invalid")
    account, bucket = values["account_id"], values["state_bucket"]
    return render_role_set(
        ROLES,
        {
            "account_id": account,
            "demo_account_id": account,
            "bootstrap_state_bucket_arn": f"arn:aws:s3:::{bucket}",
            "bootstrap_state_object_arn": f"arn:aws:s3:::{bucket}/{STATE_KEY}",
            "bootstrap_state_lock_table_arn": (
                f"arn:aws:dynamodb:{values['region']}:{account}:table/{values['lock_table']}"
            ),
        },
    )


def discover(profile: str) -> str:
    """Return the demo account ID; refuse the organization's management account."""
    import boto3

    session = boto3.session.Session(profile_name=profile)
    account_id = session.client("sts").get_caller_identity()["Account"]
    organization = session.client("organizations").describe_organization()["Organization"]
    if organization["MasterAccountId"] == account_id:
        raise RenderError(
            "demo-bootstrap roles belong in the demo account; this profile is the management account"
        )
    return account_id


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--profile", help="AWS profile in the demo account, used only for read-only discovery."
    )
    parser.add_argument("--account-id", help="Demo account ID (discovered with --profile).")
    parser.add_argument("--state-bucket", required=True, help="State bucket in the demo account.")
    parser.add_argument("--lock-table", required=True, help="Lock table in the demo account.")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        account_id = args.account_id or (discover(args.profile) if args.profile else None)
        documents = render_documents(
            {
                "account_id": account_id,
                "state_bucket": args.state_bucket,
                "lock_table": args.lock_table,
                "region": args.region,
            }
        )
    except RenderError as exc:
        parser.error(str(exc))
    output = args.output_dir.resolve()
    write_documents(documents, output)
    print(f"Rendered {len(documents)} documents to {output}")
    print("Review them, then create the roles in the demo account:\n")
    for line in commands(output, args.profile, roles=ROLES, stack="demo-bootstrap"):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
