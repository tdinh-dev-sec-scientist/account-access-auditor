"""Rule engine: run rule sets over normalized data and filter the results.

This is the only place that knows how to turn "normalized state for a service"
into "findings for that service". It is deliberately free of AWS and of I/O, so
the entire detection path can run in a unit test.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any

from ..models.finding import Finding
from ..severity import Severity
from . import cloudtrail_rules, iam_rules, s3_rules
from .registry import REGISTRY

RuleSet = Callable[[dict[str, Any], dict[str, Any], str | None], list[Finding]]

RULES: dict[str, RuleSet] = {
    "iam": iam_rules.evaluate,
    "s3": s3_rules.evaluate,
    "cloudtrail": cloudtrail_rules.evaluate,
}


def evaluate_service(
    service: str,
    data: dict[str, Any],
    config: dict[str, Any],
    run_id: str | None = None,
) -> list[Finding]:
    """Evaluate one service's rule set against its normalized data."""
    try:
        ruleset = RULES[service]
    except KeyError as exc:
        raise KeyError(f"No rule set for service '{service}'. Known: {', '.join(sorted(RULES))}") from exc
    return ruleset(data, config, run_id)


def evaluate_all(
    collected: dict[str, dict[str, Any]],
    config: dict[str, Any],
    run_id: str | None = None,
) -> list[Finding]:
    """Evaluate every service present in ``collected``."""
    findings: list[Finding] = []
    for service, data in collected.items():
        findings.extend(evaluate_service(service, data, config, run_id))
    return findings


def filter_findings(
    findings: Iterable[Finding],
    min_severity: str | None = None,
    rule_ids: Sequence[str] | None = None,
    exclude_rule_ids: Sequence[str] | None = None,
    services: Sequence[str] | None = None,
) -> list[Finding]:
    """Apply the CLI's severity/rule/service filters.

    Unknown rule IDs raise rather than silently matching nothing -- a typo in
    ``--rules IAM-04`` should not look like a clean account.
    """
    result = list(findings)

    if min_severity:
        threshold = Severity.from_string(min_severity)
        result = [f for f in result if f.severity.at_least(threshold)]

    if rule_ids:
        wanted = _validated_rule_ids(rule_ids)
        result = [f for f in result if f.rule_id in wanted]

    if exclude_rule_ids:
        unwanted = _validated_rule_ids(exclude_rule_ids)
        result = [f for f in result if f.rule_id not in unwanted]

    if services:
        wanted_services = {s.strip().lower() for s in services}
        result = [f for f in result if f.service.lower() in wanted_services]

    return result


def _validated_rule_ids(rule_ids: Sequence[str]) -> set:
    normalized = {r.strip().upper() for r in rule_ids if r.strip()}
    unknown = sorted(normalized - set(REGISTRY))
    if unknown:
        raise ValueError(
            f"Unknown rule id(s): {', '.join(unknown)}. Known rules: {', '.join(sorted(REGISTRY))}"
        )
    return normalized


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deterministic ordering: severity, then service, rule, resource."""
    return sorted(findings, key=lambda f: f.sort_key)
