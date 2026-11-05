# Phase 3 access-mode amendment (2026-11-05)

This amendment supplements the Phase 3 acceptance criteria. The owner chose to
run the Phase 3 console and Rin for invited users only instead of the public.
It changes how two existing criteria are evidenced; it does not remove a
criterion or relax any read-only, redaction, or budget control.

## What changed

- `access_mode` is a Terraform variable with values `invite_only` (default)
  and `public`. See [private access](private-access.md).
- In `invite_only` mode a Cognito authorizer protects every API Gateway
  method, WAF is optional (`enable_waf`, default off), and API Gateway stage
  throttling bounds traffic. `public` mode keeps the previous design.

## Acceptance evidence by mode

| Criterion | `public` mode | `invite_only` mode |
| --- | --- | --- |
| Stage 4 release criterion `https_headers_and_waf` | HTTPS, security headers, and WAF rate limits | HTTPS, security headers, the Cognito authorizer, and stage throttling |
| Stage 4 `stage4/load-resilience.json` | `waf_rate_limits_engaged: true` | `access_mode: "invite_only"`, `api_throttling_engaged: true`, and `unauthenticated_requests_rejected: true` |

The criterion keeps its name so existing manifests stay valid. The gate
enforces the table above:

- `phase3/stage_evidence.py` requires exactly the controls for the mode the
  evidence declares. Evidence without `access_mode` is treated as `public`.
- `scripts/validate_phase3_stage_gates.py` binds `TF_VAR_access_mode` (default
  `invite_only`, matching Terraform), so evidence recorded for one mode cannot
  accept a deployment in the other.

## Unchanged

The scanner stays read-only, the publisher remains the only bridge from
private to public results, Rin still requires a published Guardrail, quotas,
and budgets, and the kill switch still forces static mode. No Lambda gained an
IAM permission.
