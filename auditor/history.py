"""Private local persistence for immutable fleet snapshots and drift transitions."""

from __future__ import annotations

import copy
import html
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_FINGERPRINT = re.compile(r"^[a-f0-9]{16}$")
_DRIFT_STATES = ("new", "persistent", "changed", "resolved", "unknown")
_SERVICES = {"iam", "s3", "cloudtrail"}


class HistoryError(ValueError):
    """A snapshot cannot be stored or safely read."""


class HistoryStore:
    """Store immutable JSON snapshots in a private SQLite database.

    This local backend makes history usable offline and adds no AWS write
    capability. A directory with broader permissions is refused rather than
    silently changing permissions on a user-selected path.
    """

    def __init__(self, directory: str | Path):
        requested = Path(directory).expanduser()
        if requested.is_symlink():
            raise HistoryError("history directory must not be a symbolic link")
        try:
            requested.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            raise HistoryError("history directory could not be created") from None
        try:
            directory_mode = stat.S_IMODE(requested.stat().st_mode)
        except OSError:
            raise HistoryError("history directory could not be inspected") from None
        if directory_mode & 0o077:
            raise HistoryError("history directory permissions must be private (0700)")
        self.directory = requested.resolve()
        self.database_path = self.directory / "history.sqlite3"
        if self.database_path.is_symlink():
            raise HistoryError("history database must not be a symbolic link")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.database_path, timeout=10)
        except sqlite3.Error:
            raise HistoryError("history database could not be opened") from None
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 10000")
        except sqlite3.Error:
            connection.close()
            raise HistoryError("history database could not be prepared") from None
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Commit or roll back a unit of work and always close its connection."""
        connection = self._connect()
        try:
            try:
                with connection:
                    yield connection
            except sqlite3.Error:
                raise HistoryError("history database operation failed") from None
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    completed_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    report_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS coverage (
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    account_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    region TEXT NOT NULL,
                    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
                    PRIMARY KEY (run_id, account_id, service, region)
                );
                CREATE INDEX IF NOT EXISTS coverage_scope_idx
                    ON coverage(account_id, service, region, complete);
                CREATE TABLE IF NOT EXISTS findings (
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    fingerprint TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    region TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS finding_scope_idx
                    ON findings(account_id, service, region, run_id);
                CREATE TABLE IF NOT EXISTS drift (
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    fingerprint TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    region TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('new', 'persistent', 'changed', 'resolved', 'unknown')),
                    finding_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, fingerprint)
                );
                """
            )
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            raise HistoryError("history database permissions could not be restricted") from None

    def record_scan(self, report: dict[str, Any]) -> dict[str, Any]:
        """Persist a fleet snapshot and return it with its computed drift view."""
        run, coverage, findings = _validate_report(report)
        run_id = run["run_id"]
        try:
            report_json = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            raise HistoryError("scan report is not valid JSON data") from None
        transitions: list[dict[str, Any]] = []

        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT report_json FROM runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                if existing is not None:
                    if existing["report_json"] != report_json:
                        raise HistoryError("run ID already exists with different contents")
                    return _enrich(report, self._read_drift(connection, run_id))

                connection.execute(
                    "INSERT INTO runs(run_id, completed_at, status, report_json) VALUES (?, ?, ?, ?)",
                    (run_id, run["completed_at"], run["status"], report_json),
                )
                for item in coverage:
                    connection.execute(
                        "INSERT INTO coverage(run_id, account_id, service, region, complete) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (
                            run_id,
                            item["account_id"],
                            item["service"],
                            item["region"],
                            int(item["complete"]),
                        ),
                    )

                current_by_scope: dict[tuple[str, str, str], dict[str, dict[str, Any]]] = {}
                for finding in findings:
                    account_id = finding["account_ref"]["id"]
                    scope = (account_id, finding["service"], finding["region"])
                    current_by_scope.setdefault(scope, {})[finding["fingerprint"]] = finding
                    connection.execute(
                        "INSERT INTO findings(run_id, fingerprint, account_id, service, region, finding_json) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            run_id,
                            finding["fingerprint"],
                            *scope,
                            json.dumps(finding, sort_keys=True, separators=(",", ":"), allow_nan=False),
                        ),
                    )

                for scope_record in coverage:
                    scope = (
                        scope_record["account_id"],
                        scope_record["service"],
                        scope_record["region"],
                    )
                    current = current_by_scope.get(scope, {})
                    previous = self._previous_findings(connection, scope, run_id)
                    for fingerprint, finding in current.items():
                        previous_finding = previous.get(fingerprint)
                        if previous_finding is None:
                            state = "new"
                        elif _finding_signature(previous_finding) == _finding_signature(finding):
                            state = "persistent"
                        else:
                            state = "changed"
                        transitions.append(_transition(state, finding))
                    for fingerprint, finding in previous.items():
                        if fingerprint in current:
                            continue
                        state = "resolved" if scope_record["complete"] else "unknown"
                        transitions.append(_transition(state, finding))

                for transition in transitions:
                    finding = transition["finding"]
                    connection.execute(
                        "INSERT INTO drift(run_id, fingerprint, account_id, service, region, state, finding_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            run_id,
                            transition["fingerprint"],
                            transition["account_id"],
                            transition["service"],
                            transition["region"],
                            transition["state"],
                            json.dumps(finding, sort_keys=True, separators=(",", ":"), allow_nan=False),
                        ),
                    )
        except HistoryError:
            raise
        except (sqlite3.Error, OSError, ValueError):
            raise HistoryError("scan snapshot could not be stored") from None
        return _enrich(report, transitions)

    def _previous_findings(
        self,
        connection: sqlite3.Connection,
        scope: tuple[str, str, str],
        run_id: str,
    ) -> dict[str, dict[str, Any]]:
        account_id, service, region = scope
        baseline = connection.execute(
            "SELECT c.run_id FROM coverage c JOIN runs r ON r.run_id = c.run_id "
            "WHERE c.account_id = ? AND c.service = ? AND c.region = ? AND c.complete = 1 "
            "AND c.run_id != ? ORDER BY r.completed_at DESC, r.run_id DESC LIMIT 1",
            (account_id, service, region, run_id),
        ).fetchone()
        if baseline is None:
            return {}
        rows = connection.execute(
            "SELECT fingerprint, finding_json FROM findings "
            "WHERE run_id = ? AND account_id = ? AND service = ? AND region = ?",
            (baseline["run_id"], account_id, service, region),
        ).fetchall()
        return {row["fingerprint"]: json.loads(row["finding_json"]) for row in rows}

    def _read_drift(self, connection: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT fingerprint, account_id, service, region, state, finding_json "
            "FROM drift WHERE run_id = ? ORDER BY state, service, region, fingerprint",
            (run_id,),
        ).fetchall()
        return [
            {
                "fingerprint": row["fingerprint"],
                "account_id": row["account_id"],
                "service": row["service"],
                "region": row["region"],
                "state": row["state"],
                "finding": json.loads(row["finding_json"]),
            }
            for row in rows
        ]

    def list_runs(self, *, limit: int = 20) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise HistoryError("history limit must be between 1 and 1000")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT run_id, completed_at, status, report_json FROM runs "
                "ORDER BY completed_at DESC, run_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            result = []
            for row in rows:
                report = json.loads(row["report_json"])
                transitions = self._read_drift(connection, row["run_id"])
                by_state = dict.fromkeys(_DRIFT_STATES, 0)
                for transition in transitions:
                    by_state[transition["state"]] += 1
                result.append(
                    {
                        "run_id": row["run_id"],
                        "completed_at": row["completed_at"],
                        "status": row["status"],
                        "accounts": report.get("metadata", {}).get("accounts", []),
                        "regions": report.get("metadata", {}).get("regions", []),
                        "finding_count": len(report.get("contract", {}).get("findings", [])),
                        "drift": by_state,
                    }
                )
            return result

    def list_drift(self, *, run_id: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise HistoryError("drift limit must be between 1 and 10000")
        with self._connection() as connection:
            if run_id is None:
                rows = connection.execute(
                    "SELECT d.run_id, d.fingerprint, d.account_id, d.service, d.region, d.state, d.finding_json "
                    "FROM drift d JOIN runs r ON r.run_id = d.run_id "
                    "ORDER BY r.completed_at DESC, d.run_id DESC, d.state, d.service, d.region LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT run_id, fingerprint, account_id, service, region, state, finding_json "
                    "FROM drift WHERE run_id = ? ORDER BY state, service, region LIMIT ?",
                    (run_id, limit),
                ).fetchall()
        return [
            {
                "run_id": row["run_id"],
                "fingerprint": row["fingerprint"],
                "account_id": row["account_id"],
                "service": row["service"],
                "region": row["region"],
                "state": row["state"],
                "finding": json.loads(row["finding_json"]),
            }
            for row in rows
        ]

    def dashboard_html(self, *, limit: int = 20) -> str:
        runs = self.list_runs(limit=limit)
        transitions = self.list_drift(limit=1000)
        run_rows = "".join(
            "<tr>"
            f"<td>{html.escape(item['completed_at'])}</td>"
            f"<td><code>{html.escape(item['run_id'])}</code></td>"
            f"<td>{html.escape(item['status'])}</td>"
            f"<td>{item['finding_count']}</td>"
            f"<td>{html.escape(', '.join(account['id'] for account in item['accounts']))}</td>"
            f"<td>{html.escape(', '.join(item['regions']))}</td>"
            "</tr>"
            for item in runs
        )
        drift_rows = "".join(
            "<tr>"
            f"<td>{html.escape(item['state'])}</td>"
            f"<td>{html.escape(item['service'])}</td>"
            f"<td>{html.escape(item['region'])}</td>"
            f"<td>{html.escape(item['account_id'])}</td>"
            f"<td>{html.escape(str(item['finding'].get('control_id', '')))}</td>"
            f"<td>{html.escape(str(item['finding'].get('title', '')))}</td>"
            "</tr>"
            for item in transitions
        )
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>AWS posture history</title><style>"
            "body{font:16px system-ui,sans-serif;margin:2rem;color:#172033;background:#f6f8fb}"
            "main{max-width:1200px;margin:auto}section{background:white;padding:1rem 1.25rem;margin:1rem 0;border:1px solid #d8dee8;border-radius:8px}"
            "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.55rem;border-bottom:1px solid #e4e8ef}"
            "th{font-size:.84rem;color:#526071}code{font-size:.9em}"
            "</style></head><body><main><h1>AWS posture history</h1>"
            "<p>Read-only fleet scan snapshots and finding transitions.</p>"
            f"<section><h2>Recent scans ({len(runs)})</h2><table><thead><tr>"
            "<th>Completed</th><th>Run</th><th>Status</th><th>Findings</th><th>Accounts</th><th>Regions</th>"
            f"</tr></thead><tbody>{run_rows}</tbody></table></section>"
            f"<section><h2>Recent drift ({len(transitions)})</h2><table><thead><tr>"
            "<th>State</th><th>Service</th><th>Region</th><th>Account</th><th>Control</th><th>Finding</th>"
            f"</tr></thead><tbody>{drift_rows}</tbody></table></section></main></body></html>"
        )


def _validate_report(report: dict[str, Any]):
    if not isinstance(report, dict) or report.get("metadata", {}).get("scan_source") != "aws-fleet":
        raise HistoryError("only aws-fleet scan reports can be stored in fleet history")
    contract = report.get("contract")
    run = contract.get("scan_run") if isinstance(contract, dict) else None
    if not isinstance(run, dict) or not all(
        isinstance(run.get(key), str) and run[key] for key in ("run_id", "status", "completed_at")
    ):
        raise HistoryError("scan report has an invalid scan-run contract")
    if run["status"] not in {"PASS", "FAIL", "UNKNOWN", "ERROR"}:
        raise HistoryError("scan report has an unsupported terminal status")
    coverage = report.get("metadata", {}).get("scan_coverage")
    if not isinstance(coverage, list):
        raise HistoryError("scan report must include scope coverage")
    validated_coverage = []
    for item in coverage:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("account_id"), str)
            or not re.fullmatch(r"[0-9]{12}", item["account_id"])
            or item.get("service") not in _SERVICES
            or not isinstance(item.get("region"), str)
            or not item["region"]
            or not isinstance(item.get("complete"), bool)
        ):
            raise HistoryError("scan report contains an invalid coverage scope")
        validated_coverage.append(item)
    raw_findings = contract.get("findings")
    if not isinstance(raw_findings, list):
        raise HistoryError("scan report findings must be a list")
    validated_findings = []
    scopes = {(item["account_id"], item["service"], item["region"]) for item in validated_coverage}
    for finding in raw_findings:
        if (
            not isinstance(finding, dict)
            or not isinstance(finding.get("fingerprint"), str)
            or not _FINGERPRINT.fullmatch(finding["fingerprint"])
            or not isinstance(finding.get("account_ref"), dict)
            or finding["account_ref"].get("provider") != "aws"
            or not re.fullmatch(r"[0-9]{12}", str(finding["account_ref"].get("id", "")))
            or finding.get("service") not in _SERVICES
            or not isinstance(finding.get("region"), str)
        ):
            raise HistoryError("scan report contains an invalid scoped finding")
        scope = (finding["account_ref"]["id"], finding["service"], finding["region"])
        if scope not in scopes:
            raise HistoryError("finding scope is not present in scan coverage")
        validated_findings.append(finding)
    return run, validated_coverage, validated_findings


def _finding_signature(finding: dict[str, Any]) -> str:
    relevant = {
        key: finding.get(key)
        for key in ("severity", "title", "description", "evidence", "remediation", "source_severity")
    }
    return json.dumps(relevant, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _transition(state: str, finding: dict[str, Any]) -> dict[str, Any]:
    account_ref = finding["account_ref"]
    return {
        "fingerprint": finding["fingerprint"],
        "account_id": account_ref["id"],
        "service": finding["service"],
        "region": finding["region"],
        "state": state,
        "finding": copy.deepcopy(finding),
    }


def _enrich(report: dict[str, Any], transitions: list[dict[str, Any]]) -> dict[str, Any]:
    enriched = copy.deepcopy(report)
    enriched["drift"] = transitions
    counts = dict.fromkeys(_DRIFT_STATES, 0)
    for transition in transitions:
        counts[transition["state"]] += 1
    enriched.setdefault("summary", {})["drift"] = counts
    return enriched
