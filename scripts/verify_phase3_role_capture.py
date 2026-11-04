#!/usr/bin/env python3
"""Verify private Phase 3 role captures against their sanitized projections."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phase3.role_capture import RoleCaptureError, verify_role_capture


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--stack", choices=("org", "control-plane"), required=True)
    parser.add_argument("--phase", choices=("plan", "apply"), required=True)
    parser.add_argument(
        "--role-arn", required=True, help="Exact role ARN from the protected workflow environment"
    )
    args = parser.parse_args()

    try:
        digests = verify_role_capture(
            root=args.root,
            stack=args.stack,
            phase=args.phase,
            role_arn=args.role_arn,
        )
    except RoleCaptureError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for path, digest in sorted(digests["source_evidence_sha256"].items()):
        print(f"verified-private-source {path}  sha256:{digest}")
    for path, digest in sorted(digests["evidence_sha256"].items()):
        print(f"verified-redacted-projection {path}  sha256:{digest}")
    print("Source and projection digests verified; the role-scope manifest was not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
