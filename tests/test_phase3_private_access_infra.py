"""Invite-only access controls in the control-plane Terraform and web bundle.

These static checks pin the security-relevant settings so they cannot be
weakened without a failing test. The full plan was additionally verified with
terraform plan against a local Moto endpoint in both access modes.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROL_PLANE = ROOT / "infra/phase3/control-plane"


def _tf(name: str) -> str:
    return (CONTROL_PLANE / name).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """Collapse whitespace so terraform fmt alignment changes do not matter."""
    return re.sub(r"\s+", " ", text)


def _block(text: str, header: str) -> str:
    start = text.index(header)
    depth = 0
    for index in range(text.index("{", start), len(text)):
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        if depth == 0:
            return text[start : index + 1]
    raise AssertionError(f"unterminated block {header}")


def test_access_mode_defaults_to_invite_only_and_is_validated():
    variables = _tf("variables.tf")
    block = _block(variables, 'variable "access_mode"')

    assert 'default     = "invite_only"' in block
    assert 'contains(["invite_only", "public"], var.access_mode)' in block


def test_user_pool_is_invite_only_with_mandatory_mfa_and_admin_recovery():
    pool = _block(_tf("access.tf"), 'resource "aws_cognito_user_pool" "console"')

    assert "allow_admin_create_user_only = true" in pool
    assert 'mfa_configuration   = "ON"' in pool
    assert 'name     = "admin_only"' in pool
    assert 'deletion_protection = "ACTIVE"' in pool
    assert re.search(r"minimum_length\s*=\s*(1[4-9]|[2-9][0-9])\b", pool)
    for requirement in ("require_lowercase", "require_uppercase", "require_numbers", "require_symbols"):
        assert re.search(rf"{requirement}\s*=\s*true", pool)


def test_console_client_is_a_public_pkce_client_with_short_lived_tokens():
    client = _block(_tf("access.tf"), 'resource "aws_cognito_user_pool_client" "console"')

    assert "generate_secret = false" in client
    assert '["code"]' in client and "implicit" not in client
    assert 'prevent_user_existence_errors = "ENABLED"' in client
    assert "enable_token_revocation       = true" in client
    assert "ALLOW_USER_PASSWORD_AUTH" not in client and "ALLOW_ADMIN_USER_PASSWORD_AUTH" not in client
    assert re.search(r"id_token_validity\s*=\s*60\b", client)
    assert 'id_token      = "minutes"' in client


def test_every_api_method_uses_the_shared_authorization_setting():
    methods = re.findall(
        r'resource "aws_api_gateway_method" "[a-z_]+" \{.*?\n\}', _tf("stage2.tf") + _tf("stage3.tf"), re.S
    )

    assert len(methods) == 3  # GET and HEAD for every public route, and POST /api/rin
    for method in methods:
        assert "authorization = local.api_authorization" in method
        assert "authorizer_id = local.api_authorizer_id" in method
    access = _tf("access.tf")
    assert 'api_authorization = local.invite_only ? "COGNITO_USER_POOLS" : "NONE"' in access
    authorizer = _block(access, 'resource "aws_api_gateway_authorizer" "cognito"')
    assert 'type            = "COGNITO_USER_POOLS"' in authorizer
    assert 'identity_source = "method.request.header.Authorization"' in authorizer


def test_authorizer_changes_trigger_a_new_api_deployment():
    deployment = _block(_tf("stage2.tf"), 'resource "aws_api_gateway_deployment" "public"')

    assert "aws_api_gateway_authorizer.cognito" in deployment
    assert "aws_api_gateway_method.rin_post" in deployment


def test_cloudfront_forwards_authorization_without_caching_api_responses():
    stage3 = _tf("stage3.tf")
    behavior = _block(stage3, "ordered_cache_behavior")

    assert 'path_pattern               = "/api/*"' in behavior
    assert "cache_policy_id            = local.cloudfront_caching_disabled_policy_id" in behavior
    assert "local.invite_only ? local.cloudfront_all_viewer_except_host_policy" in behavior
    assert 'cloudfront_caching_disabled_policy_id = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"' in _flat(stage3)
    assert 'cloudfront_all_viewer_except_host_policy = "b689b0a8-53d0-40ab-baf2-68738e2966ac"' in _flat(
        stage3
    )


def test_csp_allows_only_the_cognito_hosted_ui_beyond_self():
    stage3 = _tf("stage3.tf")

    assert "connect-src ${local.console_connect_src}" in stage3
    assert (
        'console_connect_src                      = trimspace("\'self\' ${local.invite_only ? local.cognito_hosted_ui : ""}")'
        in stage3
    )
    assert (
        'cognito_hosted_ui = var.cognito_domain_prefix == "" ? "" : "https://${var.cognito_domain_prefix}.auth.${var.aws_region}.amazoncognito.com"'
        in _tf("access.tf")
    )


def test_waf_is_optional_only_through_an_explicit_local():
    access = _tf("access.tf")
    stage2 = _tf("stage2.tf")
    stage3 = _tf("stage3.tf")

    assert "waf_enabled = coalesce(var.enable_waf, !local.invite_only)" in _flat(access)
    assert "count       = var.enable_stage2 && local.waf_enabled ? 1 : 0" in stage2
    assert "count        = var.enable_stage2 && local.waf_enabled ? 1 : 0" in stage2
    assert "count       = var.enable_stage3 && local.waf_enabled ? 1 : 0" in stage3
    assert "web_acl_id          = local.waf_enabled ? aws_wafv2_web_acl.cloudfront[0].arn : null" in stage3


def test_api_stage_throttling_is_always_on():
    settings = _block(_tf("access.tf"), 'resource "aws_api_gateway_method_settings" "throttle"')

    assert "count       = var.enable_stage2 ? 1 : 0" in settings
    assert 'method_path = "*/*"' in settings
    assert "throttling_rate_limit  = var.api_throttle_rate_limit" in settings
    assert "throttling_burst_limit = var.api_throttle_burst_limit" in settings
    assert "data_trace_enabled     = false" in settings


def test_lambdas_receive_the_expected_issuer_and_client():
    access = _tf("access.tf")

    assert "PHASE3_ACCESS_MODE       = var.access_mode" in access
    assert (
        'cognito_issuer    = local.auth_enabled ? "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.console[0].id}" : ""'
        in access
    )
    assert _tf("stage2.tf").count("merge(local.access_environment, {") == 1
    assert _tf("stage3.tf").count("merge(local.access_environment, {") == 1


def test_terraform_workflow_passes_access_settings_and_the_csp_origin():
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")

    assert "TF_VAR_access_mode: ${{ vars.PHASE3_ACCESS_MODE || 'invite_only' }}" in workflow
    assert "TF_VAR_cognito_domain_prefix:" in workflow
    assert (
        '--auth-origin "https://${TF_VAR_cognito_domain_prefix}.auth.${TF_VAR_aws_region}.amazoncognito.com"'
        in workflow
    )
