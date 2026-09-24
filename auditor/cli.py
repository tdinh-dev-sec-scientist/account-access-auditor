"""Command-line interface.

    auditor audit --services iam,s3,cloudtrail --output json,csv
    auditor list-rules --service s3
    auditor list-permissions
    auditor validate-policy policies/auditor-readonly-policy.json
    auditor generate-policy --write

There is no write mode. The audit path builds sessions through
``aws_session.build_session``, which always installs the read-only guard, and
the guard rejects any operation outside the declared inventory.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from datetime import date
from typing import Any

from . import __version__, permissions
from .aws_session import SessionError, build_session, describe_caller
from .config import ConfigError, load_config
from .models.finding import Finding
from .models.report import build_report, exceeds
from .redaction import redact_report
from .severity import ordered_names
from .utils.logging import setup_logging

log = logging.getLogger("auditor")

ALL_SERVICES = ["iam", "s3", "cloudtrail"]
SERVICE_LABELS = {"iam": "IAM", "s3": "S3", "cloudtrail": "CloudTrail"}
OUTPUT_FORMATS = ["json", "csv", "tickets", "html"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

DEFAULT_POLICY_PATH = os.path.join("policies", "auditor-readonly-policy.json")


# ------------------------------------------------------------------ parsing --


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description=(
            "Read-only auditor for AWS account access configuration (IAM, S3, CloudTrail). "
            "The tool never modifies AWS resources."
        ),
    )
    parser.add_argument("--version", action="version", version=f"account-access-auditor {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Log errors only.")

    sub = parser.add_subparsers(dest="command")

    audit = sub.add_parser("audit", help="Scan an AWS account and report findings (read-only).")
    audit.add_argument(
        "--services",
        "--service",
        dest="services",
        default="all",
        help="Comma-separated services to scan: iam,s3,cloudtrail or 'all' (default: all).",
    )
    audit.add_argument(
        "--output",
        default="json,csv",
        help="Comma-separated output formats: json,csv,tickets,html,none (default: json,csv).",
    )
    audit.add_argument(
        "--output-dir", default="reports", help="Directory for report files (default: reports/)."
    )
    audit.add_argument("--config", default="config.yaml", help="Path to config.yaml (default: config.yaml).")
    audit.add_argument(
        "--strict-config",
        action="store_true",
        help="Fail on unknown or malformed configuration keys instead of warning.",
    )
    audit.add_argument("--profile", help="AWS named profile to use.")
    audit.add_argument("--region", help="AWS region to use.")
    audit.add_argument(
        "--severity",
        default="info",
        choices=[s.lower() for s in ordered_names()],
        help="Minimum severity to report (default: info, i.e. everything).",
    )
    audit.add_argument("--rules", help="Only evaluate these rule IDs (comma-separated, e.g. IAM-004,S3-002).")
    audit.add_argument("--exclude-rules", help="Suppress these rule IDs (comma-separated).")
    audit.add_argument(
        "--fail-on",
        choices=[s.lower() for s in ordered_names()],
        help="Exit 1 if any finding is at or above this severity.",
    )
    audit.add_argument("--environment-label", help="Free-text label recorded in the report metadata.")
    audit.add_argument(
        "--redact",
        action="store_true",
        help="Mask access key IDs in the written reports (for sharing outside the account).",
    )
    audit.add_argument(
        "--redact-account-id",
        action="store_true",
        help="Also mask the 12-digit account ID. Implies --redact.",
    )

    rules = sub.add_parser("list-rules", help="List the security rules and their CIS mappings.")
    rules.add_argument("--service", help="Filter by service: iam, s3, or cloudtrail.")
    rules.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON instead of a table.")

    perms = sub.add_parser(
        "list-permissions", help="Show the code -> IAM action -> policy statement inventory."
    )
    perms.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON instead of a table.")

    validate = sub.add_parser(
        "validate-policy",
        help="Run the auditor's own IAM policy rules against a policy document (self-audit).",
    )
    validate.add_argument(
        "path",
        nargs="?",
        default=DEFAULT_POLICY_PATH,
        help=f"Policy JSON to inspect (default: {DEFAULT_POLICY_PATH}).",
    )
    validate.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON instead of text.")

    generate = sub.add_parser(
        "generate-policy", help="Generate the least-privilege IAM policy from the code."
    )
    generate.add_argument("--write", action="store_true", help=f"Write to {DEFAULT_POLICY_PATH}.")
    generate.add_argument("--path", default=DEFAULT_POLICY_PATH, help="Destination when --write is used.")

    return parser


def parse_services(value: str) -> list[str]:
    if value.strip().lower() == "all":
        return list(ALL_SERVICES)
    requested = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not requested:
        raise ValueError("No services requested.")
    unknown = [item for item in requested if item not in ALL_SERVICES]
    if unknown:
        raise ValueError(f"Unknown service(s): {', '.join(unknown)}. Valid: {', '.join(ALL_SERVICES)}")
    # Preserve the canonical order regardless of how they were typed.
    return [service for service in ALL_SERVICES if service in requested]


def parse_outputs(value: str) -> list[str]:
    valid = set(OUTPUT_FORMATS) | {"none"}
    requested = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = [item for item in requested if item not in valid]
    if unknown:
        raise ValueError(f"Unknown output format(s): {', '.join(unknown)}. Valid: {', '.join(sorted(valid))}")
    return [] if "none" in requested else [f for f in OUTPUT_FORMATS if f in requested]


def parse_rule_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip().upper() for item in value.split(",") if item.strip()]


# --------------------------------------------------------------- scan logic --


def run_scan(
    session,
    services: list[str],
    config: dict[str, Any],
    run_id: str | None = None,
    on_progress=None,
) -> tuple[list[Finding], list[dict[str, Any]], dict[str, int]]:
    """Collect and evaluate. Returns (findings, collection_errors, resource_counts)."""
    from .collectors import COLLECTORS
    from .rules import engine

    findings: list[Finding] = []
    errors: list[dict[str, Any]] = []
    resource_counts: dict[str, int] = {}

    for service in services:
        label = SERVICE_LABELS[service]
        try:
            data = COLLECTORS[service](session, config)
        except Exception as exc:  # a broken collector must not kill the run
            log.exception("Unhandled error while collecting %s", label)
            errors.append(
                {
                    "service": label,
                    "operation": "collect",
                    "resource": None,
                    "code": exc.__class__.__name__,
                    "category": "error",
                    "message": str(exc)[:500],
                }
            )
            if on_progress:
                on_progress(label, "FAILED")
            continue

        errors.extend(data.get("errors", []))
        resource_counts.update(_count_resources(service, data))
        findings.extend(engine.evaluate_service(service, data, config, run_id))
        if on_progress:
            on_progress(label, "DONE" if not data.get("errors") else "DONE (partial)")

    return findings, errors, resource_counts


def _count_resources(service: str, data: dict[str, Any]) -> dict[str, int]:
    if service == "iam":
        return {
            "iam_users": len(data.get("users", [])),
            "iam_groups": len(data.get("groups", [])),
            "iam_roles": len(data.get("roles", [])),
            "iam_policies": sum(
                len(p.get("policies", [])) for key in ("users", "groups", "roles") for p in data.get(key, [])
            ),
            "iam_access_keys": sum(len(u.get("access_keys", [])) for u in data.get("users", [])),
        }
    if service == "s3":
        return {"s3_buckets": len(data.get("buckets", []))}
    if service == "cloudtrail":
        return {"cloudtrail_trails": len(data.get("trails", []))}
    return {}  # pragma: no cover - guarded by parse_services


# ---------------------------------------------------------------- commands --


def command_audit(args) -> int:
    from .reporters import EXTENSIONS, WRITERS, terminal
    from .rules import engine, registry

    try:
        services = parse_services(args.services)
        outputs = parse_outputs(args.output)
        include_rules = parse_rule_list(args.rules)
        exclude_rules = parse_rule_list(args.exclude_rules)
    except ValueError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    try:
        config = load_config(args.config, strict=args.strict_config)
    except ConfigError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    try:
        session, guard = build_session(profile=args.profile, region=args.region)
        account_id, caller_arn = describe_caller(session)
    except SessionError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    run_id = uuid.uuid4().hex[:12]
    region = session.region_name
    terminal.print_header(account_id, region, caller_arn, args.environment_label)

    started = time.perf_counter()
    findings, collection_errors, resource_counts = run_scan(
        session, services, config, run_id, on_progress=terminal.print_scan_line
    )
    duration = time.perf_counter() - started

    try:
        findings = engine.filter_findings(
            findings,
            min_severity=args.severity,
            rule_ids=include_rules,
            exclude_rule_ids=exclude_rules,
        )
    except ValueError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    evaluated = [
        spec.rule_id
        for spec in registry.all_rules()
        if spec.service.lower() in {SERVICE_LABELS[s].lower() for s in services}
        and (include_rules is None or spec.rule_id in include_rules)
        and (exclude_rules is None or spec.rule_id not in exclude_rules)
    ]

    report = build_report(
        account_id=account_id,
        region=region,
        findings=findings,
        collection_errors=collection_errors,
        services_scanned=[SERVICE_LABELS[s] for s in services],
        tool_version=__version__,
        run_id=run_id,
        rules_evaluated=evaluated,
        resource_counts=resource_counts,
        duration_seconds=duration,
        api_call_count=guard.call_count if guard else None,
        environment_label=args.environment_label,
    )

    if args.redact or args.redact_account_id:
        # Redaction happens after detection, so it cannot change what was found.
        report = redact_report(report, access_keys=True, account_ids=args.redact_account_id)

    stamp = date.today().isoformat()
    written: list[str] = []
    for fmt in outputs:
        name = ("tickets" if fmt == "tickets" else "audit") + f"-{stamp}.{EXTENSIONS[fmt]}"
        written.append(WRITERS[fmt](report, os.path.join(args.output_dir, name)))

    terminal.print_summary(report, written)

    if args.fail_on and exceeds(findings, args.fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def command_list_rules(args) -> int:
    from .reporters import terminal
    from .rules import registry

    try:
        specs = registry.by_service(args.service) if args.service else registry.all_rules()
    except Exception as exc:  # pragma: no cover - defensive
        log.error("%s", exc)
        return EXIT_ERROR

    if args.service and not specs:
        log.error("No rules for service '%s'. Valid: %s", args.service, ", ".join(ALL_SERVICES))
        return EXIT_ERROR

    payload = [spec.to_dict() for spec in specs]
    if args.as_json:
        print(json.dumps(payload, indent=2))
    else:
        terminal.print_rules(payload)
    return EXIT_OK


def command_list_permissions(args) -> int:
    rows = permissions.inventory_rows()
    if args.as_json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK

    print(f"{'AWS OPERATION':<34} {'IAM ACTION':<38} {'RO':<4} STATEMENT")
    for row in rows:
        print(
            f"{row['service'] + ':' + row['aws_operation']:<34} {row['iam_action']:<38} "
            f"{'yes' if row['read_only'] else 'NO':<4} {row['statement']}"
        )
    print()
    print(f"{len(rows)} API operations, all read-only: {all(r['read_only'] for r in rows)}")
    return EXIT_OK


def command_validate_policy(args) -> int:
    """Self-audit: run IAM-004/IAM-005 against a policy document."""
    from .rules import iam_rules

    try:
        with open(args.path, encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as exc:
        log.error("Could not read policy file %s: %s", args.path, exc)
        return EXIT_ERROR
    except ValueError as exc:
        log.error("Policy file %s is not valid JSON: %s", args.path, exc)
        return EXIT_ERROR

    findings = iam_rules.evaluate(
        {
            "users": [
                {
                    "username": os.path.basename(args.path),
                    "arn": None,
                    "console_access_enabled": None,
                    "mfa_device_count": None,
                    "access_keys": [],
                    "policies": [
                        {
                            "name": os.path.basename(args.path),
                            "arn": None,
                            "type": "inline",
                            "is_aws_managed": False,
                            "document": document,
                        }
                    ],
                }
            ]
        },
        load_config(None),
    )

    try:
        permissions.assert_all_read_only()
        read_only_ok = True
        read_only_detail = "All declared API operations are read-only."
    except permissions.ReadOnlyViolation as exc:
        read_only_ok = False
        read_only_detail = str(exc)

    result = {
        "policy_path": args.path,
        "statements": len(document.get("Statement", []) if isinstance(document, dict) else []),
        "wildcard_findings": [f.to_dict() for f in findings],
        "passes_wildcard_rules": not findings,
        "declared_operations_all_read_only": read_only_ok,
        "read_only_detail": read_only_detail,
        "passed": not findings and read_only_ok,
    }

    if args.as_json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Self-audit of {args.path}")
        print(f"  statements:                  {result['statements']}")
        print(
            f"  IAM-004 (Action * on *):     {'PASS' if not [f for f in findings if f.rule_id == 'IAM-004'] else 'FAIL'}"
        )
        print(
            f"  IAM-005 (service-wide on *): {'PASS' if not [f for f in findings if f.rule_id == 'IAM-005'] else 'FAIL'}"
        )
        print(f"  declared calls read-only:    {'PASS' if read_only_ok else 'FAIL'} ({read_only_detail})")
        for finding in findings:
            print(f"  ! {finding.rule_id} {finding.severity.value}: {finding.title}")
            print(f"    {finding.evidence.get('statements')}")
        print()
        print("RESULT: " + ("PASS" if result["passed"] else "FAIL"))

    return EXIT_OK if result["passed"] else EXIT_FINDINGS


def command_generate_policy(args) -> int:
    document = permissions.generate_policy()
    payload = json.dumps(document, indent=2) + "\n"
    if args.write:
        os.makedirs(os.path.dirname(os.path.abspath(args.path)), exist_ok=True)
        with open(args.path, "w", encoding="utf-8") as handle:
            handle.write(payload)
        print(f"Wrote {args.path}")
    else:
        print(payload, end="")
    return EXIT_OK


COMMANDS = {
    "audit": command_audit,
    "list-rules": command_list_rules,
    "list-permissions": command_list_permissions,
    "validate-policy": command_validate_policy,
    "generate-policy": command_generate_policy,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    if not args.command:
        parser.print_help()
        return EXIT_ERROR

    return COMMANDS[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
