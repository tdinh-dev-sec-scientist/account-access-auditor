#!/usr/bin/env python3
"""Record a completed human review of one Phase 3 Terraform role.

Run this only after you have read the role's private source captures under
docs/evidence/.private-role-captures/ and accept its trust and permissions:

    python scripts/record_phase3_role_review.py --stack org --phase plan \\
        --role-arn "$ORG_PLAN_ROLE_ARN" --reviewer "Truong Dinh" --confirm-reviewed

It re-runs the capture verifier, writes the role fingerprint, reviewer,
timestamp, and both digest sets into docs/evidence/phase3-role-scope.json,
and then runs the same role-evidence gate the Terraform workflow runs. If
that gate rejects the record, the manifest is restored unchanged. The ARN is
stored only as a SHA-256 fingerprint, never in plain text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phase3.role_capture import RoleCaptureError, verify_role_capture  # noqa: E402
from phase3.role_evidence import RoleEvidenceError, validate_role_scope_evidence  # noqa: E402

MANIFEST = Path("docs/evidence/phase3-role-scope.json")


class RecordError(ValueError):
    """The review could not be recorded safely."""


def record_review(
    *,
    root: Path,
    stack: str,
    phase: str,
    role_arn: str,
    reviewer: str,
    reviewed_at: datetime | None = None,
    re_review: bool = False,
) -> dict:
    reviewer = reviewer.strip()
    if not reviewer or len(reviewer) > 120:
        raise RecordError("reviewer must be a name of 1 to 120 characters")
    digests = verify_role_capture(root=root, stack=stack, phase=phase, role_arn=role_arn)

    manifest_path = root / MANIFEST
    original = manifest_path.read_bytes()
    manifest = json.loads(original)
    record = manifest["roles"][stack][phase]
    status = record.get("status")
    if status != "pending" and not (re_review and status == "reviewed"):
        raise RecordError(
            f"{stack} {phase} is already {status}; pass --re-review after the role changed to replace it"
        )

    timestamp = (reviewed_at or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    record.update(
        {
            "status": "reviewed",
            "role_arn_sha256": hashlib.sha256(role_arn.encode("utf-8")).hexdigest(),
            "reviewed_by": reviewer,
            "reviewed_at": timestamp.isoformat(),
            "evidence": sorted(digests["evidence_sha256"]),
            "evidence_sha256": dict(sorted(digests["evidence_sha256"].items())),
            "source_evidence_sha256": dict(sorted(digests["source_evidence_sha256"].items())),
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    try:
        validate_role_scope_evidence(root=root, stack=stack, phase=phase, role_arn=role_arn)
        verify_role_capture(root=root, stack=stack, phase=phase, role_arn=role_arn)
    except (RoleEvidenceError, RoleCaptureError) as exc:
        manifest_path.write_bytes(original)
        raise RecordError(f"the gate rejected this role, so nothing was recorded: {exc}") from None
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--stack", choices=("org", "control-plane"), required=True)
    parser.add_argument("--phase", choices=("plan", "apply"), required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument(
        "--confirm-reviewed",
        action="store_true",
        help="Confirm that you read the private source captures and accept the role's trust and permissions.",
    )
    parser.add_argument(
        "--re-review",
        action="store_true",
        help="Replace an existing review after the role's policies changed and were captured again.",
    )
    args = parser.parse_args()
    if not args.confirm_reviewed:
        parser.error("read the private captures first, then pass --confirm-reviewed to record your review")
    try:
        record = record_review(
            root=args.root.resolve(),
            stack=args.stack,
            phase=args.phase,
            role_arn=args.role_arn,
            reviewer=args.reviewer,
            re_review=args.re_review,
        )
    except (RecordError, RoleCaptureError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        f"Recorded the {args.stack} {args.phase} review by {record['reviewed_by']} at {record['reviewed_at']}."
    )
    print(
        "The role-evidence gate accepts it. Commit docs/evidence/phase3-role-scope.json and docs/evidence/terraform-roles/."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
