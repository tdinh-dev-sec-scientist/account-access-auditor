"""Safe GitHub Actions workflow-command annotations for normalized reports."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any


def escape_command_data(value: Any) -> str:
    """Escape GitHub workflow command properties."""
    normalized = "".join(char if ord(char) >= 32 or char in "\r\n" else " " for char in str(value))
    return (
        normalized.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _escape_message(value: Any) -> str:
    normalized = "".join(char if ord(char) >= 32 or char in "\r\n" else " " for char in str(value))
    return normalized.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _safe_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def annotations_for_report(report: dict[str, Any]) -> str:
    """Render findings and scan errors as escaped GitHub Actions annotations."""
    lines: list[str] = []
    for finding in report.get("findings", []):
        gated = bool(finding.get("gate"))
        severity = str(finding.get("severity", "MEDIUM"))
        level = "error" if gated else "warning" if severity in {"CRITICAL", "HIGH", "MEDIUM"} else "notice"
        title = str(finding.get("control_id") or "IaC finding")[:200]
        parts = [str(finding.get("title") or title), str(finding.get("description") or "")]
        for exception in finding.get("exceptions", []):
            if isinstance(exception, dict):
                parts.append(
                    "Exception "
                    f"{exception.get('id', 'unknown')} ({exception.get('state', 'UNKNOWN')}, "
                    f"owner {exception.get('owner', 'unknown')}, expires {exception.get('expires_at', 'unknown')}): "
                    f"{exception.get('reason', '')}"
                )
        message = " — ".join(part for part in parts if part)
        properties = []
        location = finding.get("source_location")
        if isinstance(location, dict):
            path = _safe_path(location.get("file"))
            if path:
                properties.append(f"file={escape_command_data(path)}")
            line = location.get("line")
            if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                properties.append(f"line={line}")
        properties.append(f"title={escape_command_data(title)}")
        prefix = f"::{level} {','.join(properties)}::" if properties else f"::{level}::"
        lines.append(prefix + _escape_message(message))

    for error in report.get("collection_errors", []):
        service = str(error.get("service") or "IaC")
        operation = str(error.get("operation") or "scan")
        message = str(error.get("message") or "scanner failed")
        lines.append(
            "::error title=IaC scanner error::" + _escape_message(f"{service} {operation}: {message}")
        )

    status = report.get("contract", {}).get("scan_run", {}).get("status")
    if isinstance(status, str) and status in {"ERROR", "UNKNOWN"} and not report.get("collection_errors"):
        lines.append(
            "::error title=IaC scan incomplete::" + _escape_message(f"IaC scan finished with status {status}")
        )
    return "\n".join(lines) + ("\n" if lines else "")
