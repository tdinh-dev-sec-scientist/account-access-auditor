"""Rules engine.

Rules are pure functions: normalized data in, ``Finding`` objects out. No module
in this package imports boto3, which is what makes the whole detection path
unit-testable against fixtures with no AWS access.
"""

from . import cloudtrail_rules, engine, iam_rules, policy, registry, s3_rules
from .engine import RULES, evaluate_all, evaluate_service, filter_findings, sort_findings
from .registry import REGISTRY, RuleSpec, all_rules, rule_ids

__all__ = [
    "RULES",
    "REGISTRY",
    "RuleSpec",
    "all_rules",
    "rule_ids",
    "evaluate_all",
    "evaluate_service",
    "filter_findings",
    "sort_findings",
    "engine",
    "policy",
    "registry",
    "iam_rules",
    "s3_rules",
    "cloudtrail_rules",
]
