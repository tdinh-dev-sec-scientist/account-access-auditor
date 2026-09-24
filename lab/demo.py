"""Run the auditor end to end against the emulated lab account.

    python -m lab.demo
    python -m lab.demo --output-dir reports --profile no-trail

This is the demonstration path: it provisions the deliberately misconfigured
account in memory with moto, scans it through the ordinary audit code, prints
the same terminal report a real scan prints, and writes the report in every
output format the tool supports. It needs no AWS account, no credentials, and
no network.

What makes it a demonstration rather than a mock-up: only the account is
emulated. The auditor reaches it through real boto3 clients, real botocore
signing and response parsing, real paginators, and the same read-only guard --
so the 101 API calls counted below are calls the guard actually admitted.

``lab.run_benchmark`` is the scored version of this, used by CI. This one is for
a person to look at.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import uuid

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)

from auditor import __version__  # noqa: E402
from auditor.aws_session import build_session, describe_caller  # noqa: E402
from auditor.cli import ALL_SERVICES, SERVICE_LABELS, run_scan  # noqa: E402
from auditor.config import load_config  # noqa: E402
from auditor.models.report import build_report  # noqa: E402
from auditor.redaction import redact_report  # noqa: E402
from auditor.reporters import EXTENSIONS, WRITERS, terminal  # noqa: E402
from auditor.rules import registry  # noqa: E402
from lab.provision import build_lab_session, provision  # noqa: E402
from lab.resources import PROFILES  # noqa: E402

OUTPUTS = ["json", "csv", "tickets", "html"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lab.demo",
        description="Audit the emulated lab account and write a report. No AWS account needed.",
    )
    parser.add_argument("--profile", choices=sorted(PROFILES), default="misconfigured")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument(
        "--output",
        default=",".join(OUTPUTS),
        help=f"Comma-separated formats (default: all of {','.join(OUTPUTS)}).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)-7s %(message)s")
    formats = [item.strip().lower() for item in args.output.split(",") if item.strip()]
    unknown = [item for item in formats if item not in WRITERS]
    if unknown:
        parser.error(f"Unknown output format(s): {', '.join(unknown)}")

    from moto import mock_aws

    config = load_config(None)
    run_id = uuid.uuid4().hex[:12]
    environment = f"lab/{args.profile} (moto emulated account, not a live AWS account)"

    with mock_aws():
        lab_session = build_lab_session("moto", args.region)
        account_id = lab_session.client("sts").get_caller_identity()["Account"]
        provision(lab_session, args.profile, account_id, suffix="", backend="moto")

        # A separate, guarded session for the audit, exactly as the CLI builds
        # one -- so the API-call count below belongs to the scan and not to the
        # provisioning that set the account up.
        audit_session, guard = build_session(region=args.region)
        scanned_account, caller_arn = describe_caller(audit_session)

        terminal.print_header(scanned_account, args.region, caller_arn, environment)
        started = time.perf_counter()
        findings, errors, resource_counts = run_scan(
            audit_session, ALL_SERVICES, config, run_id, on_progress=terminal.print_scan_line
        )
        duration = time.perf_counter() - started

    report = build_report(
        account_id=scanned_account,
        region=args.region,
        findings=findings,
        collection_errors=errors,
        services_scanned=[SERVICE_LABELS[service] for service in ALL_SERVICES],
        tool_version=__version__,
        run_id=run_id,
        rules_evaluated=registry.rule_ids(),
        resource_counts=resource_counts,
        duration_seconds=duration,
        api_call_count=guard.call_count if guard else None,
        environment_label=environment,
    )
    # The demo report is meant to be shared, so access key IDs are masked.
    report = redact_report(report, access_keys=True)

    written = [
        WRITERS[fmt](report, os.path.join(args.output_dir, f"audit-demo.{EXTENSIONS[fmt]}"))
        for fmt in OUTPUTS
        if fmt in formats
    ]
    terminal.print_summary(report, written)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
