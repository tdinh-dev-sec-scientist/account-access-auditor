"""Regression tests for control-plane variable validations under Terraform 1.9.

Terraform 1.9 evaluates both operands of && and ||, so `x == null || x > 0`
raises "argument must not be null" instead of passing when x is null. Every
plan with the default (null) budgets failed until these used try().
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROL_PLANE = ROOT / "infra/phase3/control-plane"
NULLABLE_NUMBERS = (
    "monthly_budget_usd",
    "aws_pricing_estimate_monthly_usd",
    "provider_monthly_budget_usd",
    "rin_input_cost_per_million_tokens_usd",
    "rin_output_cost_per_million_tokens_usd",
)


def _terraform() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(CONTROL_PLANE.glob("*.tf")))


def test_nullable_numbers_are_never_compared_outside_try():
    for line in _terraform().splitlines():
        for name in NULLABLE_NUMBERS:
            compared = re.search(rf"var\.{name}\s*(?:>|<|>=|<=)\s|(?:>|<|>=|<=)\s*var\.{name}\b", line)
            if compared:
                assert "try(" in line, f"unguarded comparison of nullable var.{name}: {line.strip()}"


def test_retention_days_comparisons_tolerate_null_evidence():
    gate = (CONTROL_PLANE / "stage_gate.tf").read_text(encoding="utf-8")

    for line in gate.splitlines():
        if re.search(r"logging\.retention_days\s*(?:>|<|>=|<=)", line):
            assert "try(" in line or line.strip().startswith("logging.retention_days >= 0"), line.strip()
    assert "logging.retention_days == null ||" not in gate


def test_github_repository_default_satisfies_its_own_validation():
    variables = (CONTROL_PLANE / "variables.tf").read_text(encoding="utf-8")
    block = variables[variables.index('variable "github_repository"') :]
    block = block[: block.index("\n}\n")]
    default = re.search(r'default\s*=\s*"([^"]+)"', block).group(1)
    pattern = re.search(r'can\(regex\("([^"]+)", var\.github_repository\)\)', block).group(1)

    assert re.fullmatch(pattern.replace("\\\\", "\\"), default), (pattern, default)
    assert default == "tdinh-dev-sec-scientist/Vorrin"
