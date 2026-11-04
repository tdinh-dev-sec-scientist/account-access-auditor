#!/usr/bin/env python3
"""Block privileged Phase 3 stacks until the exact OIDC role is reviewed."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phase3.role_evidence import RoleEvidenceError, validate_role_scope_evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--stack", choices=("org", "demo-bootstrap", "demo-account", "control-plane"), required=True)
    parser.add_argument("--phase", choices=("plan", "apply"), required=True)
    args = parser.parse_args()
    try:
        validate_role_scope_evidence(
            root=args.root,
            stack=args.stack,
            phase=args.phase,
            role_arn=os.environ.get("PHASE3_TERRAFORM_ROLE_ARN", ""),
        )
    except RoleEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"{args.stack} {args.phase} Terraform role-scope evidence matches the checked-in review manifest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
