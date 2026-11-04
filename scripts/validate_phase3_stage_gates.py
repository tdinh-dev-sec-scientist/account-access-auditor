#!/usr/bin/env python3
"""Fail a Phase 3 Terraform run when predecessor acceptance evidence is absent."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from decimal import ROUND_FLOOR, Decimal, InvalidOperation
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phase3.stage_gates import StageGateError, validate_stage_gates


def _enabled_stages() -> set[int]:
    enabled = set()
    for stage in (2, 3, 4):
        value = os.environ.get(f"PHASE3_ENABLE_STAGE{stage}", "false").strip().lower()
        if value not in {"true", "false"}:
            raise StageGateError(f"PHASE3_ENABLE_STAGE{stage} must be true or false")
        if value == "true":
            enabled.add(stage)
    return enabled


def _number(name: str, *, default: str | None = None) -> Decimal | None:
    raw = os.environ.get(name, default)
    if raw is None or raw.strip().lower() in {"", "null"}:
        return None
    try:
        value = Decimal(raw)
    except InvalidOperation:
        raise StageGateError(f"{name} must be a finite Terraform number") from None
    if not value.is_finite():
        raise StageGateError(f"{name} must be a finite Terraform number")
    return value


def _runtime_bindings() -> tuple[str | None, int | None, float | None]:
    # Terraform variable names are case-sensitive and the input is declared lowercase.
    account_id = os.environ.get("TF_VAR_demo_account_id", "").strip()  # noqa: SIM112
    if account_id and not re.fullmatch(r"[0-9]{12}", account_id):
        raise StageGateError("TF_VAR_demo_account_id must be a 12-digit AWS account ID")
    account_hash = hashlib.sha256(account_id.encode()).hexdigest() if account_id else None

    monthly = _number("TF_VAR_provider_monthly_budget_usd")
    input_price = _number("TF_VAR_rin_input_cost_per_million_tokens_usd") or Decimal(0)
    output_price = _number("TF_VAR_rin_output_cost_per_million_tokens_usd") or Decimal(0)
    max_input = _number("TF_VAR_rin_max_input_tokens", default="4096")
    max_output = _number("TF_VAR_rin_max_output_tokens", default="600")
    if max_input is None or max_output is None or max_input <= 0 or max_output <= 0:
        raise StageGateError("Rin maximum token settings must be positive numbers")
    request_cost = (max_input * input_price + max_output * output_price) / Decimal(1_000_000)
    if monthly is None or request_cost <= 0:
        daily_cap = 0
    else:
        daily_cap = min(1000, max(0, int(((monthly * Decimal("0.8") / 30) / request_cost).to_integral_value(rounding=ROUND_FLOOR))))
    return account_hash, daily_cap, float(monthly) if monthly is not None else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    manifest_path = root / "docs/evidence/phase3-stage-acceptance.json"
    try:
        account_hash, daily_cap, provider_budget = _runtime_bindings()
        validate_stage_gates(
            manifest_path,
            root=root,
            enabled_stages=_enabled_stages(),
            expected_demo_account_id_sha256=account_hash,
            expected_daily_invocation_limit=daily_cap,
            expected_monthly_budget_usd=provider_budget,
            require_runtime_bindings=True,
        )
    except StageGateError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("Phase 3 stage configuration matches checked-in acceptance evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
