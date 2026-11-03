"""Credential-free IaC scanning and normalization for Checkov and Conftest."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .. import __version__
from ..config import load_config
from ..exceptions import ExceptionConfigError, evaluate_exceptions, load_exceptions
from ..models.contracts import (
    CONTRACT_VERSION,
    GateStatus,
    ScanRun,
    classify_scan,
    finding_record,
    scanner_finding_record,
)
from ..models.finding import Finding
from ..redaction import redact_report
from ..rules import iam_rules
from ..severity import Severity, counts
from ..utils.process import credential_safe_environment

POLICY_PACK_VERSION = "1.0.0"
CHECKOV_CHECKS = {
    "terraform": ["CKV_AWS_20", "CKV_AWS_21", "CKV_AWS_145", "CKV2_AWS_6"],
    "kubernetes": ["CKV_K8S_20", "CKV_K8S_29", "CKV_K8S_43"],
}
DEFAULT_POLICY_DIR = Path(__file__).with_name("policies")
SCANNER_TIMEOUT_SECONDS = 120
_SOURCE_SEVERITIES = {severity.value for severity in Severity}
_CONFTTEST_VERSION = re.compile(r"^Conftest:\s*([^\s]+)", re.MULTILINE | re.IGNORECASE)
_OPA_VERSION = re.compile(r"^OPA:\s*([^\s]+)", re.MULTILINE | re.IGNORECASE)


class InputError(ValueError):
    """An input could not be safely classified as a supported scan document."""


class ScannerOutputError(ValueError):
    """A scanner returned malformed or incomplete output."""


@dataclass(frozen=True)
class ScanInput:
    path: Path
    source_type: str
    parser: str
    checkov_framework: str | None
    checkov_scope: Path | None = None


def classify_input(path: str | Path, *, helm_rendered: bool = False, strict: bool = True) -> ScanInput | None:
    """Classify one supported Terraform, IAM, Kubernetes, or rendered Helm file."""
    source = Path(path)
    if source.is_symlink():
        raise InputError("symbolic-link inputs are not supported")
    if not source.exists() or not source.is_file():
        raise InputError("input is not a readable regular file")

    name = source.name.lower()
    suffix = source.suffix.lower()
    if name.endswith(".tf.json"):
        raise InputError("Terraform JSON input is not supported; use an HCL .tf file")
    if suffix == ".tf":
        return ScanInput(source, "terraform", "hcl2", "terraform")
    if suffix in {".yaml", ".yml"}:
        if not _validate_kubernetes_yaml(source, strict=strict):
            return None
        return ScanInput(source, "helm" if helm_rendered else "kubernetes", "yaml", "kubernetes")
    if suffix == ".json":
        document = _load_json(source)
        if "Statement" in document:
            return ScanInput(source, "iam", "json", None)
        if "apiVersion" in document or "kind" in document:
            if not all(
                isinstance(document.get(key), str) and document[key].strip() for key in ("apiVersion", "kind")
            ):
                raise InputError("Kubernetes JSON requires non-empty apiVersion and kind strings")
            return ScanInput(source, "kubernetes", "json", "kubernetes")
        if "resource" in document or "data" in document:
            raise InputError("Terraform JSON input is not supported; use an HCL .tf file")
        if not strict:
            return None
        raise InputError("JSON input is not an IAM policy, Kubernetes manifest, or Terraform JSON file")
    raise InputError(
        "supported inputs are Terraform HCL .tf, IAM/Kubernetes .json, and Kubernetes .yaml/.yml"
    )


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, UnicodeError):
        raise InputError("JSON input could not be read as UTF-8") from None
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON at line {exc.lineno}, column {exc.colno}") from None
    if not isinstance(document, dict):
        raise InputError("JSON input must be an object")
    return document


def _validate_kubernetes_yaml(path: Path, *, strict: bool) -> bool:
    try:
        with path.open(encoding="utf-8") as handle:
            documents = list(yaml.safe_load_all(handle))
    except (OSError, UnicodeError):
        raise InputError("YAML input could not be read as UTF-8") from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        if mark is None:
            raise InputError("invalid YAML input") from None
        raise InputError(f"invalid YAML at line {mark.line + 1}, column {mark.column + 1}") from None
    if not any(document is not None for document in documents):
        if not strict:
            return False
        raise InputError("YAML input contains no Kubernetes documents")
    manifests = [document for document in documents if document is not None]
    if not strict and all(
        isinstance(document, dict) and "apiVersion" not in document and "kind" not in document
        for document in manifests
    ):
        return False
    for document in documents:
        if document is None:
            continue
        if (
            not isinstance(document, dict)
            or not isinstance(document.get("apiVersion"), str)
            or not document["apiVersion"].strip()
            or not isinstance(document.get("kind"), str)
            or not document["kind"].strip()
        ):
            raise InputError(
                "YAML documents must be Kubernetes objects with non-empty apiVersion and kind strings"
            )
    return True


def map_checkov_severity(source_severity: Any) -> str:
    """Map Checkov tiers to the project scale; unknown tiers map to MEDIUM."""
    if isinstance(source_severity, str):
        candidate = source_severity.strip().upper()
        if candidate in _SOURCE_SEVERITIES:
            return candidate
    return Severity.MEDIUM.value


def _map_policy_severity(source_severity: Any) -> str:
    if isinstance(source_severity, str):
        candidate = source_severity.strip().upper()
        if candidate in _SOURCE_SEVERITIES:
            return candidate
    return Severity.MEDIUM.value


def _safe_relative_path(value: Any, root: Path) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value)
    try:
        resolved_root = root.resolve()
        resolved_path = (
            candidate.resolve() if candidate.is_absolute() else (resolved_root / candidate).resolve()
        )
        return resolved_path.relative_to(resolved_root).as_posix()
    except (OSError, ValueError):
        return candidate.name or None


def _source_location(file: str | None, line: Any = None) -> dict[str, Any] | None:
    if not file:
        return None
    result: dict[str, Any] = {"file": file}
    if isinstance(line, int) and not isinstance(line, bool) and line > 0:
        result["line"] = line
    return result


def _valid_json_payload(stdout: str, scanner: str) -> Any:
    try:
        return json.loads(stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ScannerOutputError(f"{scanner} did not return valid JSON") from exc


def _is_valid_empty_checkov_summary(payload: Any) -> bool:
    """Recognize Checkov's summary-only JSON when no selected checks apply."""
    if not isinstance(payload, dict):
        return False
    counters = ("passed", "failed", "skipped", "parsing_errors", "resource_count")
    if not all(
        isinstance(payload.get(key), int) and not isinstance(payload.get(key), bool) and payload[key] == 0
        for key in counters
    ):
        return False
    return isinstance(payload.get("checkov_version"), str) and bool(payload["checkov_version"].strip())


def parse_checkov_output(
    stdout: str,
    *,
    source_type: str,
    root: Path,
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize failed Checkov checks while retaining source identity and evidence."""
    payload = _valid_json_payload(stdout, "Checkov")
    if _is_valid_empty_checkov_summary(payload):
        return []
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        raise ScannerOutputError("Checkov JSON is missing results")
    results = payload["results"]
    failed_checks = results.get("failed_checks")
    if not isinstance(failed_checks, list):
        raise ScannerOutputError("Checkov JSON results.failed_checks must be a list")

    findings: list[dict[str, Any]] = []
    for check in failed_checks:
        if not isinstance(check, dict):
            raise ScannerOutputError("Checkov returned a malformed failed check")
        check_id = check.get("check_id")
        if not isinstance(check_id, str) or not check_id.strip():
            raise ScannerOutputError("Checkov failed check has no check_id")
        resource = check.get("resource")
        if not isinstance(resource, str) or not resource.strip():
            resource = None
        file_value = check.get("file_abs_path") or check.get("repo_file_path") or check.get("file_path")
        file = _safe_relative_path(file_value, root)
        ranges = check.get("file_line_range")
        line = ranges[0] if isinstance(ranges, list) and ranges else None
        location = _source_location(file, line)
        if resource is None and location is None:
            raise ScannerOutputError(f"Checkov finding {check_id} has no source identity")

        source_severity = check.get("severity")
        if not isinstance(source_severity, str):
            source_severity = None
        check_name = check.get("check_name")
        if not isinstance(check_name, str) or not check_name.strip():
            check_name = check_id
        evaluated_keys = check.get("evaluated_keys")
        evidence = {
            "check_name": check_name,
            "evaluated_keys": evaluated_keys if isinstance(evaluated_keys, list) else [],
        }
        check_result = check.get("check_result")
        if isinstance(check_result, dict) and isinstance(check_result.get("result"), str):
            evidence["result"] = check_result["result"]
        for key in ("bc_check_id", "bc_category"):
            if isinstance(check.get(key), str) and check[key].strip():
                evidence[key] = check[key]

        short_description = check.get("short_description") or check.get("description")
        description = short_description if isinstance(short_description, str) else check_name
        guideline = check.get("guideline")
        remediation = guideline if isinstance(guideline, str) else ""
        findings.append(
            scanner_finding_record(
                control_id=f"CHECKOV-{check_id}",
                scanner="checkov",
                scanner_rule_id=check_id,
                source_type=source_type,
                severity=map_checkov_severity(source_severity),
                source_severity=source_severity,
                title=check_name[:240],
                description=description[:2000],
                evidence=evidence,
                remediation=remediation[:2000],
                resource_reference=resource,
                source_location=location,
                run_id=run_id,
            )
        )
    return findings


def _conftest_location(failure: dict[str, Any], metadata: dict[str, Any], filename: str, root: Path):
    location = (
        failure.get("_loc") or metadata.get("_loc") or metadata.get("loc") or metadata.get("source_location")
    )
    if not isinstance(location, dict):
        location = {}
    file_value = location.get("file") or filename
    file = _safe_relative_path(file_value, root)
    line = location.get("line")
    return _source_location(file, line)


def parse_conftest_output(
    stdout: str,
    *,
    source_type: str,
    root: Path,
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize Conftest JSON failures and project metadata into shared findings."""
    payload = _valid_json_payload(stdout, "Conftest")
    if not isinstance(payload, list):
        raise ScannerOutputError("Conftest JSON must be a result list")
    if not payload:
        raise ScannerOutputError("Conftest returned no file results")
    findings: list[dict[str, Any]] = []
    for result in payload:
        if not isinstance(result, dict) or not isinstance(result.get("filename"), str):
            raise ScannerOutputError("Conftest returned a malformed file result")
        namespace = result.get("namespace")
        if not isinstance(namespace, str) or not namespace.strip():
            namespace = "main"
        failures = result.get("failures", [])
        if not isinstance(failures, list):
            raise ScannerOutputError("Conftest result failures must be a list")
        for failure in failures:
            if not isinstance(failure, dict) or not isinstance(failure.get("msg"), str):
                raise ScannerOutputError("Conftest returned a malformed policy failure")
            output_metadata = failure.get("metadata")
            if not isinstance(output_metadata, dict):
                output_metadata = {}
            query = output_metadata.get("query")
            if not isinstance(query, str) or not query.strip():
                query = f"data.{namespace}.deny"
            custom = output_metadata.get("metadata")
            if not isinstance(custom, dict):
                custom = {}
            rule_id = custom.get("rule_id")
            if not isinstance(rule_id, str) or not rule_id.strip():
                rule_id = query
            control_id = custom.get("control_id")
            if not isinstance(control_id, str) or not control_id.strip():
                control_id = f"CONFTEST-{namespace}-{rule_id}"
            title = custom.get("title")
            if not isinstance(title, str) or not title.strip():
                title = failure["msg"]
            remediation = custom.get("remediation")
            if not isinstance(remediation, str):
                remediation = ""
            source_severity = custom.get("severity")
            if not isinstance(source_severity, str):
                source_severity = None
            resource = custom.get("resource_reference")
            if not isinstance(resource, str) or not resource.strip():
                resource = None
            location = _conftest_location(failure, custom, result["filename"], root)
            if resource is None and location is None:
                raise ScannerOutputError(f"Conftest finding {rule_id} has no source identity")
            findings.append(
                scanner_finding_record(
                    control_id=control_id,
                    scanner="conftest",
                    scanner_rule_id=rule_id,
                    source_type=source_type,
                    severity=_map_policy_severity(source_severity),
                    source_severity=source_severity,
                    title=title[:240],
                    description=failure["msg"][:2000],
                    evidence={
                        "message": failure["msg"][:2000],
                        "namespace": namespace,
                        "query": query,
                    },
                    remediation=remediation[:2000],
                    resource_reference=resource,
                    source_location=location,
                    run_id=run_id,
                )
            )
    return findings


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge repeated observations only when scanner, control, and source identity agree."""
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        location = finding.get("source_location") or {}
        identity = finding.get("resource_reference") or (location.get("file"), location.get("line"))
        key = (
            finding.get("scanner"),
            finding.get("control_id"),
            finding.get("source_type"),
            identity,
        )
        existing = unique.get(key)
        if existing is None:
            unique[key] = dict(finding)
            continue
        first_evidence = existing.get("evidence", {})
        next_evidence = finding.get("evidence", {})
        if first_evidence == next_evidence:
            continue
        observations = existing.get("evidence", {}).get("observations")
        if not isinstance(observations, list):
            observations = [first_evidence]
        if next_evidence not in observations:
            observations.append(next_evidence)
        existing["evidence"] = {"observations": observations}

    return sorted(
        unique.values(),
        key=lambda f: (
            str(f.get("source_type", "")),
            str(f.get("control_id", "")),
            str(f.get("scanner", "")),
            str(f.get("resource_reference") or ""),
            str((f.get("source_location") or {}).get("file", "")),
            (f.get("source_location") or {}).get("line") or 0,
        ),
    )


def _error(path: str | Path | None, root: Path, operation: str, code: str, message: str) -> dict[str, Any]:
    file = _safe_relative_path(str(path), root) if path is not None else None
    return {
        "service": "IaC",
        "operation": operation,
        "resource": file,
        "code": code,
        "category": "scanner_error",
        "message": message[:500],
    }


def _matches_exclude(path: Path, root: Path, patterns: list[str]) -> bool:
    try:
        relative = Path(os.path.abspath(path)).relative_to(root).as_posix()
    except ValueError:
        return False
    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/").removeprefix("./")
        if fnmatch.fnmatchcase(relative, pattern):
            return True
        if pattern.endswith("/**"):
            prefix = pattern[:-3].rstrip("/")
            if relative == prefix or relative.startswith(prefix + "/"):
                return True
    return False


def _directory_candidates(
    directory: Path,
    root: Path,
    helm_rendered: bool,
    exclude_paths: list[str] | None = None,
) -> tuple[list[ScanInput], list[dict[str, Any]]]:
    candidates: list[ScanInput] = []
    errors: list[dict[str, Any]] = []
    excludes = exclude_paths or []

    def on_walk_error(exc: OSError) -> None:
        errors.append(
            _error(
                getattr(exc, "filename", None) or directory,
                root,
                "scan-input",
                "DirectoryReadError",
                f"could not read input directory ({exc.__class__.__name__})",
            )
        )

    for current, directories, filenames in os.walk(directory, followlinks=False, onerror=on_walk_error):
        current_path = Path(current)
        directories[:] = [
            name for name in directories if not _matches_exclude(current_path / name, root, excludes)
        ]
        symlink_directories = sorted(name for name in directories if (current_path / name).is_symlink())
        for name in symlink_directories:
            errors.append(
                _error(
                    current_path / name,
                    root,
                    "scan-input",
                    "UnsupportedInput",
                    "symbolic-link directory skipped",
                )
            )
        directories[:] = sorted(name for name in directories if name not in symlink_directories)
        for name in sorted(filenames):
            path = current_path / name
            if _matches_exclude(path, root, excludes):
                continue
            lower = name.lower()
            if path.is_symlink():
                if lower.endswith((".tf", ".tf.json", ".json", ".yaml", ".yml")):
                    errors.append(
                        _error(path, root, "scan-input", "UnsupportedInput", "symbolic-link input skipped")
                    )
                continue
            is_known_extension = lower.endswith((".tf", ".tf.json", ".yaml", ".yml"))
            if not is_known_extension and path.suffix.lower() != ".json":
                continue
            try:
                item = classify_input(path, helm_rendered=helm_rendered, strict=False)
            except InputError as exc:
                if path.suffix.lower() == ".json" and not is_known_extension:
                    # Repositories commonly contain unrelated JSON. Only policy and resource JSON
                    # is in scope; an explicitly supplied JSON file remains a hard input error.
                    try:
                        document = _load_json(path)
                    except InputError as json_exc:
                        if "invalid JSON" in str(json_exc) and any(
                            word in lower for word in ("iam", "policy")
                        ):
                            errors.append(_error(path, root, "scan-input", "InvalidInput", str(json_exc)))
                    else:
                        if any(key in document for key in ("apiVersion", "kind", "resource", "data")):
                            errors.append(_error(path, root, "scan-input", "UnsupportedInput", str(exc)))
                    continue
                errors.append(_error(path, root, "scan-input", "InvalidInput", str(exc)))
                continue
            if item is None:
                continue
            candidates.append(replace(item, checkov_scope=directory))
    return candidates, errors


def _discover_inputs(
    paths: list[str | Path],
    *,
    helm_rendered: bool,
    root: Path,
    exclude_paths: list[str] | None = None,
) -> tuple[list[ScanInput], list[dict[str, Any]]]:
    candidates: list[ScanInput] = []
    errors: list[dict[str, Any]] = []
    seen: dict[Path, int] = {}
    for raw_path in paths:
        path = Path(raw_path)
        try:
            if path.is_symlink():
                raise InputError("symbolic-link inputs are not supported")
            if not path.exists():
                raise InputError("input path does not exist")
            if path.is_dir():
                discovered, discovery_errors = _directory_candidates(path, root, helm_rendered, exclude_paths)
                for item in discovered:
                    resolved = item.path.resolve()
                    candidate_index = seen.get(resolved)
                    if candidate_index is None:
                        seen[resolved] = len(candidates)
                        candidates.append(item)
                    else:
                        existing_scope = candidates[candidate_index].checkov_scope
                        incoming_scope = item.checkov_scope
                        if incoming_scope is not None and (
                            existing_scope is None
                            or existing_scope.resolve().is_relative_to(incoming_scope.resolve())
                        ):
                            candidates[candidate_index] = item
                errors.extend(discovery_errors)
                if not discovered:
                    errors.append(
                        _error(
                            path,
                            root,
                            "scan-input",
                            "NoSupportedInputs",
                            "directory contains no supported inputs",
                        )
                    )
                continue
            item = classify_input(path, helm_rendered=helm_rendered)
        except (OSError, InputError) as exc:
            errors.append(_error(path, root, "scan-input", "InvalidInput", str(exc)))
            continue
        resolved = item.path.resolve()
        if resolved not in seen:
            seen[resolved] = len(candidates)
            candidates.append(item)
    candidates.sort(key=lambda item: item.path.as_posix())
    return candidates, errors


def _scanner_environment() -> dict[str, str]:
    return credential_safe_environment()


def _run(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=SCANNER_TIMEOUT_SECONDS,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"scanner timed out after {SCANNER_TIMEOUT_SECONDS} seconds") from exc
    except OSError as exc:
        raise RuntimeError(f"scanner could not start ({exc.__class__.__name__})") from exc


def _resolve_executable(name: str, explicit: str | None) -> str:
    executable = explicit or shutil.which(name)
    if not executable:
        raise RuntimeError(f"required scanner '{name}' was not found on PATH")
    return executable


def _get_version(name: str, executable: str, environment: dict[str, str]) -> str:
    result = _run([executable, "--version"], environment)
    if result.returncode != 0:
        raise RuntimeError(f"{name} version check exited with status {result.returncode}")
    output = (result.stdout or "").strip()
    match = re.search(r"(?m)^\s*(\d+\.\d+(?:\.\d+)?(?:[-+][\w.-]+)?)\s*$", output)
    if not match:
        raise ScannerOutputError("Checkov version output was not recognized")
    return match.group(1)


def _get_conftest_versions(executable: str, environment: dict[str, str]) -> tuple[str, str | None]:
    result = _run([executable, "--version"], environment)
    if result.returncode != 0:
        raise RuntimeError(f"conftest version check exited with status {result.returncode}")
    output = (result.stdout or "").strip()
    conftest_match = _CONFTTEST_VERSION.search(output)
    if not conftest_match:
        raise ScannerOutputError("Conftest version output was not recognized")
    opa_match = _OPA_VERSION.search(output)
    return conftest_match.group(1), opa_match.group(1) if opa_match else None


def _run_checkov(
    item: ScanInput,
    executable: str,
    environment: dict[str, str],
    root: Path,
    run_id: str,
    exclude_paths: list[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    source_arguments = (
        ["-d", str(item.checkov_scope)] if item.checkov_scope is not None else ["-f", str(item.path)]
    )
    command = [
        executable,
        *source_arguments,
        "--framework",
        item.checkov_framework or "terraform",
        *[
            argument
            for check in CHECKOV_CHECKS[item.checkov_framework or "terraform"]
            for argument in ("--check", check)
        ],
        "--output",
        "json",
        "--soft-fail",
        "--skip-download",
        "--skip-results-upload",
    ]
    for pattern in exclude_paths or []:
        normalized = pattern.replace("\\", "/").removeprefix("./")
        candidate = (root / normalized).resolve()
        try:
            checkov_path = candidate.relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            checkov_path = candidate.as_posix()
        command.extend(("--skip-path", fnmatch.translate(checkov_path)))
    result = _run(command, environment)
    try:
        findings = parse_checkov_output(result.stdout, source_type=item.source_type, root=root, run_id=run_id)
        payload = json.loads(result.stdout)
    except (ScannerOutputError, json.JSONDecodeError) as exc:
        return [], [_error(item.path, root, "checkov", "InvalidScannerOutput", str(exc))]

    errors = []
    parsing_errors = payload.get("results", {}).get("parsing_errors", [])
    if isinstance(parsing_errors, list) and parsing_errors:
        errors.append(
            _error(
                item.path,
                root,
                "checkov",
                "ParseFailure",
                f"Checkov reported {len(parsing_errors)} parsing error(s)",
            )
        )
    elif not isinstance(parsing_errors, list):
        errors.append(
            _error(
                item.path, root, "checkov", "InvalidScannerOutput", "Checkov parsing_errors must be a list"
            )
        )
    if result.returncode != 0:
        errors.append(
            _error(
                item.path, root, "checkov", "ScannerExit", f"Checkov exited with status {result.returncode}"
            )
        )
    return findings, errors


def _run_conftest(
    item: ScanInput,
    executable: str,
    policy_dir: Path,
    environment: dict[str, str],
    root: Path,
    run_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    command = [
        executable,
        "test",
        "--all-namespaces",
        "--no-color",
        "--output",
        "json",
        "--parser",
        item.parser,
        "--rego-version",
        "v1",
        "--policy",
        str(policy_dir),
        str(item.path),
    ]
    result = _run(command, environment)
    try:
        findings = parse_conftest_output(
            result.stdout, source_type=item.source_type, root=root, run_id=run_id
        )
    except ScannerOutputError as exc:
        return [], [_error(item.path, root, "conftest", "InvalidScannerOutput", str(exc))]

    errors = []
    has_failures = bool(findings)
    payload = json.loads(result.stdout)
    if any(
        bool(file_result.get("errors") or file_result.get("exceptions"))
        for file_result in payload
        if isinstance(file_result, dict)
    ):
        errors.append(
            _error(
                item.path, root, "conftest", "PolicyEvaluationError", "Conftest reported evaluation errors"
            )
        )
    if result.returncode not in ({0, 1} if has_failures else {0}):
        errors.append(
            _error(
                item.path, root, "conftest", "ScannerExit", f"Conftest exited with status {result.returncode}"
            )
        )
    return findings, errors


def _scan_iam_policy(item: ScanInput, root: Path, run_id: str) -> list[dict[str, Any]]:
    document = _load_json(item.path)
    _validate_iam_document(document)
    username = item.path.name[:128] or "policy"
    data = {
        "users": [
            {
                "username": username,
                "arn": None,
                "console_access_enabled": None,
                "mfa_device_count": None,
                "access_keys": [],
                "policies": [
                    {
                        "name": username,
                        "arn": None,
                        "type": "inline",
                        "is_aws_managed": False,
                        "document": document,
                    }
                ],
            }
        ]
    }
    findings: list[Finding] = iam_rules.evaluate(data, load_config(None), run_id)
    file = _safe_relative_path(str(item.path), root)
    if file is None:
        raise InputError("IAM policy source path could not be represented")
    records: list[dict[str, Any]] = []
    for finding in findings:
        record = finding_record(
            finding,
            source_type="iam",
            scanner="account-access-auditor",
            resource_reference_is_stable=False,
            source_location={"file": file},
            run_id=run_id,
        )
        for statement in record.get("evidence", {}).get("statements", []):
            if isinstance(statement, dict):
                statement.pop("sid", None)
        records.append(record)
    return records


def _validate_iam_document(document: dict[str, Any]) -> None:
    if "Statement" not in document:
        raise InputError("IAM policy JSON must contain Statement")
    if "Version" in document:
        version = document["Version"]
        if not isinstance(version, str) or version not in {"2008-10-17", "2012-10-17"}:
            raise InputError("IAM policy Version must be 2008-10-17 or 2012-10-17")
    raw_statements = document["Statement"]
    statements = raw_statements if isinstance(raw_statements, list) else [raw_statements]
    if not statements or not all(isinstance(statement, dict) for statement in statements):
        raise InputError("IAM policy Statement must be an object or a list of objects")
    for statement in statements:
        effect = statement.get("Effect")
        if not isinstance(effect, str) or effect not in {"Allow", "Deny"}:
            raise InputError("each IAM statement must have Effect Allow or Deny")
        if ("Action" in statement) == ("NotAction" in statement):
            raise InputError("each IAM statement must contain Action or NotAction, but not both")
        if ("Resource" in statement) == ("NotResource" in statement):
            raise InputError("each IAM statement must contain Resource or NotResource, but not both")
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key not in statement:
                continue
            values = statement[key] if isinstance(statement[key], list) else [statement[key]]
            if not values or not all(isinstance(value, str) and value.strip() for value in values):
                raise InputError(f"IAM statement {key} must be a non-empty string or list of strings")
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            raise InputError("IAM statement Condition must be an object")


def _ordered_scanner_versions(
    used_checkov: bool,
    checkov_version: str | None,
    conftest_version: str | None,
    opa_version: str | None,
) -> dict[str, str]:
    versions = {"account-access-auditor": __version__}
    if used_checkov and checkov_version:
        versions["checkov"] = checkov_version
    if conftest_version:
        versions["conftest"] = conftest_version
    if opa_version:
        versions["opa"] = opa_version
    return versions


def scan_paths(
    paths: list[str | Path],
    *,
    helm_rendered: bool = False,
    policy_dir: str | Path | None = None,
    run_id: str | None = None,
    root: str | Path | None = None,
    checkov_executable: str | None = None,
    conftest_executable: str | None = None,
    fail_on: str = "INFO",
    exceptions_path: str | Path | None = None,
    allow_empty: bool = False,
    exclude_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Scan local inputs without constructing an AWS session or passing AWS credentials."""
    threshold = Severity.from_string(fail_on).value
    scan_root = Path(root).resolve() if root is not None else Path.cwd().resolve()
    policy_path = Path(policy_dir).resolve() if policy_dir is not None else DEFAULT_POLICY_DIR
    actual_run_id = run_id or uuid.uuid4().hex[:12]
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if not paths:
        candidates = []
        errors.append(
            _error(None, scan_root, "scan-input", "EmptyInput", "at least one file or directory is required")
        )
    else:
        candidates, discovery_errors = _discover_inputs(
            paths,
            helm_rendered=helm_rendered,
            root=scan_root,
            exclude_paths=exclude_paths,
        )
        if allow_empty:
            discovery_errors = [
                error for error in discovery_errors if error.get("code") != "NoSupportedInputs"
            ]
        errors.extend(discovery_errors)
    exceptions: list[dict[str, Any]] = []
    if exceptions_path is not None:
        try:
            exceptions = load_exceptions(exceptions_path)
        except ExceptionConfigError as exc:
            errors.append(
                _error(
                    exceptions_path,
                    scan_root,
                    "exceptions",
                    "InvalidExceptionFile",
                    str(exc),
                )
            )
    used_checkov = any(item.checkov_framework for item in candidates)
    environment = _scanner_environment()
    checkov_path = None
    conftest_path = None
    checkov_version = None
    conftest_version = None
    opa_version = None

    if candidates:
        try:
            conftest_path = _resolve_executable("conftest", conftest_executable)
            conftest_version, opa_version = _get_conftest_versions(conftest_path, environment)
        except (RuntimeError, ScannerOutputError) as exc:
            conftest_path = None
            errors.append(_error(None, scan_root, "conftest-version", "ScannerUnavailable", str(exc)))
        if used_checkov:
            try:
                checkov_path = _resolve_executable("checkov", checkov_executable)
                checkov_version = _get_version("checkov", checkov_path, environment)
            except (RuntimeError, ScannerOutputError) as exc:
                checkov_path = None
                errors.append(_error(None, scan_root, "checkov-version", "ScannerUnavailable", str(exc)))

    checked_scopes: set[tuple[str, str]] = set()
    for item in candidates:
        if item.source_type == "iam":
            try:
                findings.extend(_scan_iam_policy(item, scan_root, actual_run_id))
            except (InputError, OSError, ValueError) as exc:
                errors.append(_error(item.path, scan_root, "iam-policy", "InvalidInput", str(exc)))
        if item.checkov_framework and checkov_path:
            scope = item.checkov_scope or item.path
            scope_key = (scope.resolve().as_posix(), item.checkov_framework)
            if scope_key not in checked_scopes:
                checked_scopes.add(scope_key)
                try:
                    new_findings, scanner_errors = _run_checkov(
                        item,
                        checkov_path,
                        environment,
                        scan_root,
                        actual_run_id,
                        exclude_paths,
                    )
                except RuntimeError as exc:
                    errors.append(_error(scope, scan_root, "checkov", "ScannerFailure", str(exc)))
                else:
                    findings.extend(new_findings)
                    errors.extend(scanner_errors)
        if conftest_path:
            if not policy_path.is_dir():
                errors.append(
                    _error(
                        item.path,
                        scan_root,
                        "conftest",
                        "PolicyPackUnavailable",
                        "project policy pack was not found",
                    )
                )
                continue
            try:
                new_findings, scanner_errors = _run_conftest(
                    item, conftest_path, policy_path, environment, scan_root, actual_run_id
                )
            except RuntimeError as exc:
                errors.append(_error(item.path, scan_root, "conftest", "ScannerFailure", str(exc)))
            else:
                findings.extend(new_findings)
                errors.extend(scanner_errors)

    ordered_findings = deduplicate_findings(findings)
    ordered_findings, exception_evaluations, gate_violation_count = evaluate_exceptions(
        ordered_findings, exceptions, threshold=threshold
    )
    has_errors = bool(errors)
    gate = (
        GateStatus.FAIL
        if gate_violation_count
        else GateStatus.PASS
        if not has_errors
        else GateStatus.NOT_CONFIGURED
    )
    outcome = classify_scan(errors, gate)
    completed_at = datetime.now(UTC).isoformat(timespec="seconds")
    scanner_versions = _ordered_scanner_versions(used_checkov, checkov_version, conftest_version, opa_version)
    scan_run = ScanRun(
        schema_version=CONTRACT_VERSION,
        run_id=actual_run_id,
        scan_source="local-iac",
        commit_ref=None,
        workflow_ref=None,
        account_refs=[],
        regions=[],
        scanner_versions=scanner_versions,
        policy_pack_version=POLICY_PACK_VERSION,
        started_at=started_at,
        completed_at=completed_at,
        status=outcome.status,
        gate_status=outcome.gate_status,
        exit_code=outcome.exit_code,
        finding_count=len(ordered_findings),
        collection_error_count=len(errors),
        gate_threshold=threshold,
    ).to_dict()
    report = {
        "metadata": {
            "tool": "account-access-auditor",
            "tool_version": __version__,
            "run_id": actual_run_id,
            "scan_source": "local-iac",
            "read_only": True,
            "aws_accessed": False,
            "policy_pack_version": POLICY_PACK_VERSION,
            "scanner_versions": scanner_versions,
            "generated_at": completed_at,
        },
        "summary": {
            "total_findings": len(ordered_findings),
            "by_severity": counts([finding["severity"] for finding in ordered_findings]),
            "status": outcome.status.value,
            "gate_status": outcome.gate_status.value,
            "collection_errors": len(errors),
            "gate_threshold": threshold,
            "gate_violations": gate_violation_count,
            "exception_count": len(exception_evaluations),
        },
        "collection_errors": errors,
        "findings": ordered_findings,
        "contract": {
            "schema_version": CONTRACT_VERSION,
            "scan_run": scan_run,
            "findings": ordered_findings,
            "exceptions": exception_evaluations,
        },
    }
    return redact_report(report, access_keys=True)
