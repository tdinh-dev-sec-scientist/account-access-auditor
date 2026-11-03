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
from datetime import UTC, date, datetime
from typing import Any

from . import __version__, permissions
from .aws_session import (
    SessionError,
    build_access_analyzer_session,
    build_session,
    describe_caller,
)
from .config import ConfigError, load_config
from .fleet import FleetConfigError, load_fleet_config
from .fleet_scan import run_fleet_scan
from .history import HistoryError, HistoryStore
from .models.contracts import GateStatus
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
EXIT_UNKNOWN = 3

DEFAULT_POLICY_PATH = os.path.join("policies", "auditor-readonly-policy.json")
DEFAULT_HISTORY_DIR = os.path.join("~", ".local", "state", "account-access-auditor", "history")


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

    validate_aa = sub.add_parser(
        "validate-access-analyzer",
        help="Optionally validate one local IAM policy through AWS IAM Access Analyzer.",
    )
    validate_aa.add_argument("path", help="IAM policy JSON file to validate.")
    validate_aa.add_argument("--profile", help="AWS profile for the separate validation session.")
    validate_aa.add_argument("--region", required=True, help="AWS region for IAM Access Analyzer.")
    validate_aa.add_argument(
        "--policy-type",
        default="IDENTITY_POLICY",
        choices=["IDENTITY_POLICY", "RESOURCE_POLICY", "SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"],
        help="Access Analyzer policy type (default: IDENTITY_POLICY).",
    )
    validate_aa.add_argument(
        "--resource-type",
        choices=[
            "AWS::S3::Bucket",
            "AWS::S3::AccessPoint",
            "AWS::S3::MultiRegionAccessPoint",
            "AWS::S3ObjectLambda::AccessPoint",
            "AWS::IAM::AssumeRolePolicyDocument",
            "AWS::DynamoDB::Table",
        ],
        help="Resource type when validating a resource-based policy.",
    )
    validate_aa.add_argument(
        "--fail-on",
        type=str.upper,
        choices=ordered_names(),
        default="HIGH",
        help="Fail on findings at or above this severity (default: HIGH).",
    )

    iac = sub.add_parser(
        "scan-iac",
        help="Scan local Terraform, IAM policy, Kubernetes, and rendered Helm files without AWS access.",
    )
    iac.add_argument("paths", nargs="+", help="Files or directories to scan.")
    iac.add_argument(
        "--helm-rendered",
        action="store_true",
        help="Treat YAML inputs as already rendered Helm manifests.",
    )
    iac.add_argument("--policy-dir", help="Override the bundled Conftest/Rego policy pack.")
    iac.add_argument(
        "--fail-on",
        type=str.upper,
        choices=ordered_names(),
        default="INFO",
        help="Fail when a finding is at or above this severity (default: INFO).",
    )
    iac.add_argument(
        "--exceptions",
        dest="exceptions_path",
        help="Load strict, expiring exceptions from a YAML file.",
    )
    iac.add_argument(
        "--exclude",
        dest="exclude_paths",
        action="append",
        default=[],
        help="Exclude a relative glob from directory scans; repeat as needed.",
    )
    iac.add_argument(
        "--allow-empty",
        action="store_true",
        help="Pass when no supported IaC inputs are found (input and scanner errors still fail).",
    )
    iac.add_argument(
        "--sarif-output",
        help="Write a SARIF 2.1.0 report to this path.",
    )
    iac.add_argument(
        "--output",
        dest="report_path",
        default="-",
        help="Write the JSON report to this path (default: stdout).",
    )

    annotate = sub.add_parser("annotate-iac", help="Emit GitHub Actions annotations from an IaC JSON report.")
    annotate.add_argument("report", help="Path to an IaC JSON report.")

    gate = sub.add_parser("gate-iac", help="Return the gate exit code recorded in an IaC JSON report.")
    gate.add_argument("report", help="Path to an IaC JSON report.")

    fleet = sub.add_parser(
        "fleet-scan", help="Read-only scan configured accounts and regions; save a local drift snapshot."
    )
    fleet.add_argument("--fleet-config", required=True, help="Validated YAML list of read-only target roles.")
    fleet.add_argument("--config", default="config.yaml", help="Audit rules and thresholds configuration.")
    fleet.add_argument("--profile", help="AWS profile allowed to assume configured target roles.")
    fleet.add_argument(
        "--history-dir",
        default=os.environ.get("AUDITOR_HISTORY_DIR", DEFAULT_HISTORY_DIR),
        help="Private local SQLite history directory (default: ~/.local/state/account-access-auditor/history).",
    )
    fleet.add_argument(
        "--fail-on",
        choices=[s.lower() for s in ordered_names()],
        help="Set a fleet finding gate threshold.",
    )

    history = sub.add_parser(
        "history", help="List saved fleet scans and drift, or export a static HTML dashboard."
    )
    history.add_argument(
        "--history-dir",
        default=os.environ.get("AUDITOR_HISTORY_DIR", DEFAULT_HISTORY_DIR),
        help="Private local SQLite history directory.",
    )
    history.add_argument("--format", choices=["json", "html"], default="json")
    history.add_argument("--run-id", help="Limit JSON drift output to one scan run.")
    history.add_argument("--limit", type=int, default=20, help="Recent scans to include (default: 20).")
    history.add_argument("--output", help="Write the export to a file instead of stdout.")

    supply = sub.add_parser(
        "supply-chain-release",
        help="Generate and scan local SBOMs, then sign and verify a container archive (no AWS access).",
    )
    supply.add_argument("--source", default=".", help="Source package directory to catalog (default: .).")
    supply.add_argument(
        "--image-archive", required=True, help="Saved Docker or OCI image archive to release."
    )
    supply.add_argument(
        "--image-format",
        choices=["docker-archive", "oci-archive"],
        default="docker-archive",
        help="Archive format (default: docker-archive).",
    )
    supply.add_argument(
        "--output-dir", required=True, help="New or existing directory for release artifacts."
    )
    supply.add_argument(
        "--signing-key", required=True, help="Cosign private key file; password via COSIGN_PASSWORD."
    )
    supply.add_argument(
        "--public-key", required=True, help="Matching Cosign public key file for offline verification."
    )
    supply.add_argument(
        "--fail-on",
        type=str.upper,
        choices=["NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Fail release if a vulnerability meets or exceeds this tier (default: HIGH).",
    )

    remediation_preview = sub.add_parser(
        "remediation-preview",
        help="Render a reviewable IaC patch preview without changing source files.",
    )
    remediation_preview.add_argument("--source", required=True, help="Source directory containing IaC files.")
    remediation_preview.add_argument("--plan", required=True, help="Strict JSON remediation plan.")

    remediation_sandbox = sub.add_parser(
        "remediation-sandbox",
        help="Apply an approved remediation to a temporary local copy and require a passing IaC rescan.",
    )
    remediation_sandbox.add_argument("--source", required=True, help="Source directory containing IaC files.")
    remediation_sandbox.add_argument(
        "--plan", required=True, help="Approved, preview-bound JSON remediation plan."
    )
    remediation_sandbox.add_argument(
        "--output-dir", required=True, help="Directory for patch and rescan evidence."
    )
    remediation_sandbox.add_argument(
        "--fail-on",
        type=str.upper,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="HIGH",
        help="Rescan finding threshold (default: HIGH).",
    )
    remediation_sandbox.add_argument(
        "--confirm-sandbox",
        action="store_true",
        required=True,
        help="Explicitly confirm that changes are applied only to a temporary local copy.",
    )

    ai_analyze = sub.add_parser(
        "ai-analyze",
        help="Optionally explain a saved scan report; advisory output never changes the scan gate or accesses AWS.",
    )
    ai_analyze.add_argument("--report", required=True, help="Saved scan report JSON to explain.")
    ai_analyze.add_argument(
        "--provider",
        choices=["openai"],
        default="openai",
        help="Optional configured provider (default: openai). No call occurs without OPENAI_API_KEY and a model.",
    )
    ai_analyze.add_argument(
        "--model",
        help="Provider model; defaults to AUDITOR_AI_MODEL or OPENAI_MODEL.",
    )
    ai_analyze.add_argument(
        "--source",
        help="Local IaC source tree required before an AI patch proposal can be returned after rescan.",
    )
    ai_analyze.add_argument(
        "--fail-on",
        type=str.upper,
        choices=ordered_names(),
        default="HIGH",
        help="Gate threshold for temporary-copy proposal rescans (default: HIGH).",
    )

    generate = sub.add_parser(
        "generate-policy", help="Generate the least-privilege IAM policy from the code."
    )
    generate.add_argument("--write", action="store_true", help=f"Write to {DEFAULT_POLICY_PATH}.")
    generate.add_argument("--path", default=DEFAULT_POLICY_PATH, help="Destination when --write is used.")
    generate.add_argument(
        "--include-optional-access-analyzer",
        action="store_true",
        help="Include access-analyzer:ValidatePolicy for the separate opt-in validation path.",
    )

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

    scan_started_at = datetime.now(UTC).isoformat(timespec="seconds")
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

    if args.fail_on:
        gate_status = GateStatus.FAIL if exceeds(findings, args.fail_on) else GateStatus.PASS
    else:
        gate_status = GateStatus.NOT_CONFIGURED

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
        scan_source="cli",
        scan_started_at=scan_started_at,
        gate_status=gate_status,
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
    return report["contract"]["scan_run"]["exit_code"]


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


def command_validate_access_analyzer(args) -> int:
    """Use the separately guarded, optional IAM Access Analyzer validation call."""
    from .access_analyzer import MAX_POLICY_BYTES, validate_policy_document
    from .models.contracts import CONTRACT_VERSION, GateStatus, ScanRun, classify_scan
    from .severity import Severity

    try:
        if os.path.getsize(args.path) > MAX_POLICY_BYTES:
            raise ValueError("policy document exceeds the 1 MiB size limit")
        with open(args.path, encoding="utf-8") as handle:
            policy_document = json.load(handle)
        if not isinstance(policy_document, dict):
            raise ValueError("policy document must be a JSON object")
    except (OSError, UnicodeError, ValueError) as exc:
        log.error("Could not read policy document %s: %s", args.path, exc)
        return EXIT_ERROR

    run_id = uuid.uuid4().hex[:12]
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    try:
        session, guard = build_access_analyzer_session(profile=args.profile, region=args.region)
        account_id, _caller_arn = describe_caller(session)
    except SessionError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    findings, errors = validate_policy_document(
        session,
        policy_document,
        policy_type=args.policy_type,
        source_file=os.path.relpath(os.path.abspath(args.path), os.getcwd()),
        validate_policy_resource_type=args.resource_type,
        account_ref={"provider": "aws", "id": account_id} if account_id else None,
        region=args.region,
    )
    threshold = Severity.from_string(args.fail_on)
    gate_status = (
        GateStatus.FAIL
        if any(Severity.from_string(item["severity"]).at_least(threshold) for item in findings)
        else GateStatus.PASS
    )
    outcome = classify_scan(errors, gate_status)
    completed_at = datetime.now(UTC).isoformat(timespec="seconds")
    scan_run = ScanRun(
        schema_version=CONTRACT_VERSION,
        run_id=run_id,
        scan_source="aws-access-analyzer",
        commit_ref=None,
        workflow_ref=None,
        account_refs=([{"provider": "aws", "id": account_id}] if account_id else []),
        regions=[args.region],
        scanner_versions={"account-access-auditor": __version__, "access-analyzer-api": "2019-11-01"},
        policy_pack_version=None,
        started_at=started_at,
        completed_at=completed_at,
        status=outcome.status,
        gate_status=outcome.gate_status,
        exit_code=outcome.exit_code,
        finding_count=len(findings),
        collection_error_count=len(errors),
        gate_threshold=threshold.value,
    ).to_dict()
    report = {
        "metadata": {
            "tool": "account-access-auditor",
            "tool_version": __version__,
            "run_id": run_id,
            "scan_source": "aws-access-analyzer",
            "read_only": True,
            "aws_accessed": True,
            "account_id": account_id,
            "region": args.region,
            "generated_at": completed_at,
            "api_call_count": guard.call_count,
        },
        "summary": {
            "total_findings": len(findings),
            "status": outcome.status.value,
            "gate_status": outcome.gate_status.value,
            "gate_threshold": threshold.value,
            "collection_errors": len(errors),
        },
        "collection_errors": errors,
        "findings": findings,
        "contract": {
            "schema_version": CONTRACT_VERSION,
            "scan_run": scan_run,
            "findings": findings,
        },
    }
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return outcome.exit_code


def command_fleet_scan(args) -> int:
    """Run a guarded multi-account scan and persist an immutable local snapshot."""
    try:
        fleet_config = load_fleet_config(args.fleet_config)
        audit_config = load_config(args.config)
        source_session, source_guard = build_session(profile=args.profile, region=fleet_config.regions[0])
        report = run_fleet_scan(
            fleet_config,
            audit_config,
            source_session,
            source_guard=source_guard,
            fail_on=args.fail_on,
        )
        report = HistoryStore(args.history_dir).record_scan(report)
    except (FleetConfigError, ConfigError, SessionError, HistoryError, OSError, ValueError) as exc:
        log.error("Fleet scan failed: %s", str(exc)[:500])
        return EXIT_ERROR
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report["contract"]["scan_run"]["exit_code"]


def command_history(args) -> int:
    """Render a bounded JSON summary or static drift dashboard from local history."""
    try:
        if args.limit < 1 or args.limit > 1000:
            raise HistoryError("history limit must be between 1 and 1000")
        store = HistoryStore(args.history_dir)
        if args.format == "html":
            payload = store.dashboard_html(limit=args.limit)
        else:
            result = {
                "runs": store.list_runs(limit=args.limit),
                "drift": store.list_drift(run_id=args.run_id, limit=min(args.limit * 100, 10000)),
            }
            payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            destination = os.path.abspath(args.output)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(destination, flags, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    descriptor = -1
                    handle.write(payload)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        else:
            sys.stdout.write(payload)
    except (HistoryError, OSError, ValueError) as exc:
        log.error("Could not render fleet history: %s", str(exc)[:500])
        return EXIT_ERROR
    return EXIT_OK


def command_supply_chain_release(args) -> int:
    """Create local SBOMs and reports, enforcing signing and verification."""
    from .supply_chain import SupplyChainError, run_release

    try:
        result = run_release(
            source_dir=args.source,
            image_archive=args.image_archive,
            image_format=args.image_format,
            output_dir=args.output_dir,
            signing_key=args.signing_key,
            public_key=args.public_key,
            fail_on=args.fail_on,
        )
    except (SupplyChainError, OSError, ValueError) as exc:
        log.error("Supply-chain release could not start: %s", exc)
        return EXIT_ERROR

    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return {
        "PASS": EXIT_OK,
        "FAIL": EXIT_FINDINGS,
        "ERROR": EXIT_ERROR,
        "UNKNOWN": EXIT_UNKNOWN,
    }.get(result.get("status"), EXIT_ERROR)


def command_remediation_preview(args) -> int:
    """Emit a deterministic, non-mutating patch preview for human review."""
    from .remediation import RemediationError, create_remediation_preview

    try:
        result = create_remediation_preview(source_dir=args.source, plan=args.plan)
    except (RemediationError, OSError, ValueError) as exc:
        log.error("Remediation preview could not be created: %s", exc)
        return EXIT_ERROR
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return EXIT_OK


def command_remediation_sandbox(args) -> int:
    """Apply an approved patch in a disposable local copy and require a rescan."""
    from .remediation import RemediationError, run_sandbox_remediation

    try:
        result = run_sandbox_remediation(
            source_dir=args.source,
            plan=args.plan,
            output_dir=args.output_dir,
            fail_on=args.fail_on,
        )
    except (RemediationError, OSError, ValueError) as exc:
        log.error("Sandbox remediation could not start: %s", exc)
        return EXIT_ERROR
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return EXIT_OK if result.get("status") == "PASS" else EXIT_FINDINGS


def command_ai_analyze(args) -> int:
    """Emit optional advisory text without changing the deterministic scan result."""
    from .ai_analyst import AIAnalystError, analyze_report, load_report

    try:
        report = load_report(args.report)
        result = analyze_report(
            report,
            provider=args.provider,
            model=args.model,
            source_dir=args.source,
            fail_on=args.fail_on,
        )
    except (AIAnalystError, OSError, ValueError) as exc:
        log.error("AI analysis could not run: %s", exc)
        return EXIT_ERROR
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    # The advisory path never changes the already-recorded scan or gate exit code.
    return EXIT_OK


def command_scan_iac(args) -> int:
    """Run credential-free static scanners and emit the shared finding contract."""
    from .iac.scanning import scan_paths

    report = scan_paths(
        args.paths,
        helm_rendered=args.helm_rendered,
        policy_dir=args.policy_dir,
        fail_on=args.fail_on,
        exceptions_path=args.exceptions_path,
        allow_empty=args.allow_empty,
        exclude_paths=args.exclude_paths,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.sarif_output:
        try:
            from .reporters.sarif import to_sarif

            sarif_payload = json.dumps(to_sarif(report), indent=2, sort_keys=True) + "\n"
            destination = os.path.abspath(args.sarif_output)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(destination, "w", encoding="utf-8") as handle:
                handle.write(sarif_payload)
        except (OSError, TypeError, ValueError) as exc:
            _record_iac_output_error(
                report,
                code="SarifWriteError",
                message=f"could not write SARIF report ({exc.__class__.__name__})",
            )
            payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
            log.error("Could not write SARIF report %s: %s", args.sarif_output, exc)
            sarif_error = True
        else:
            sarif_error = False
    else:
        sarif_error = False
    if args.report_path == "-":
        sys.stdout.write(payload)
    else:
        try:
            destination = os.path.abspath(args.report_path)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(destination, "w", encoding="utf-8") as handle:
                handle.write(payload)
        except OSError as exc:
            log.error("Could not write IaC scan report %s: %s", args.report_path, exc)
            return EXIT_ERROR
    return EXIT_ERROR if sarif_error else report["contract"]["scan_run"]["exit_code"]


def _record_iac_output_error(report: dict[str, Any], *, code: str, message: str) -> None:
    error = {
        "service": "IaC",
        "operation": "report-output",
        "resource": None,
        "code": code,
        "category": "scanner_error",
        "message": message,
    }
    report.setdefault("collection_errors", []).append(error)
    summary = report.setdefault("summary", {})
    summary["collection_errors"] = len(report["collection_errors"])
    summary["status"] = "ERROR"
    scan_run = report.setdefault("contract", {}).setdefault("scan_run", {})
    scan_run["status"] = "ERROR"
    scan_run["exit_code"] = EXIT_ERROR
    scan_run["collection_error_count"] = len(report["collection_errors"])


def _read_iac_report(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"could not read a valid IaC JSON report ({exc.__class__.__name__})") from None
    if not isinstance(report, dict):
        raise ValueError("JSON file is not an IaC scan report")
    contract = report.get("contract")
    if not isinstance(contract, dict) or not isinstance(contract.get("scan_run"), dict):
        raise ValueError("JSON file is not an IaC scan report")
    if not isinstance(report.get("metadata"), dict):
        raise ValueError("IaC report metadata must be an object")
    for key in ("findings", "collection_errors"):
        records = report.get(key)
        if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
            raise ValueError(f"IaC report {key} must be a list of objects")
    return report


def command_annotate_iac(args) -> int:
    from .reporters.github_actions import annotations_for_report

    try:
        report = _read_iac_report(args.report)
    except ValueError as exc:
        print(f"::error title=IaC report error::{exc}")
        return EXIT_ERROR
    sys.stdout.write(annotations_for_report(report))
    return EXIT_OK


def command_gate_iac(args) -> int:
    try:
        report = _read_iac_report(args.report)
        scan_run = report["contract"]["scan_run"]
        status = scan_run.get("status")
        exit_code = scan_run.get("exit_code")
        expected_codes = {
            "PASS": EXIT_OK,
            "FAIL": EXIT_FINDINGS,
            "ERROR": EXIT_ERROR,
            "UNKNOWN": EXIT_UNKNOWN,
        }
        if (
            not isinstance(status, str)
            or isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
            or status not in expected_codes
            or exit_code != expected_codes[status]
        ):
            raise ValueError("IaC report has an invalid status and exit-code pair")
        return exit_code
    except ValueError as exc:
        log.error("%s", exc)
        return EXIT_ERROR


def command_generate_policy(args) -> int:
    document = permissions.generate_policy(include_optional=args.include_optional_access_analyzer)
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
    "validate-access-analyzer": command_validate_access_analyzer,
    "fleet-scan": command_fleet_scan,
    "history": command_history,
    "supply-chain-release": command_supply_chain_release,
    "remediation-preview": command_remediation_preview,
    "remediation-sandbox": command_remediation_sandbox,
    "ai-analyze": command_ai_analyze,
    "scan-iac": command_scan_iac,
    "annotate-iac": command_annotate_iac,
    "gate-iac": command_gate_iac,
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
