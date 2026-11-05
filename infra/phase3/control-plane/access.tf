# Invite-only access for the Phase 3 API and Rin.
#
# In invite_only mode every API Gateway method requires a Cognito ID token.
# Users cannot sign themselves up: the owner creates each account, MFA is
# mandatory, and only an administrator can recover an account. The console is
# a public client, so it uses the authorization-code flow with PKCE and holds
# no client secret. Lambdas re-check the verified claims as defense in depth.

locals {
  invite_only  = var.access_mode == "invite_only"
  waf_enabled  = coalesce(var.enable_waf, !local.invite_only)
  auth_enabled = var.enable_stage2 && local.invite_only
  console_origin = var.domain_name != "" ? "https://${var.domain_name}" : (
    var.enable_stage3 ? "https://${aws_cloudfront_distribution.web[0].domain_name}" : ""
  )
  auth_callback_urls = distinct(concat(
    var.enable_stage3 ? ["${local.console_origin}/"] : [],
    var.auth_extra_callback_urls
  ))
  cognito_hosted_ui = var.cognito_domain_prefix == "" ? "" : "https://${var.cognito_domain_prefix}.auth.${var.aws_region}.amazoncognito.com"
  api_authorization = local.invite_only ? "COGNITO_USER_POOLS" : "NONE"
  api_authorizer_id = local.auth_enabled ? aws_api_gateway_authorizer.cognito[0].id : null
  cognito_issuer    = local.auth_enabled ? "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.console[0].id}" : ""
  cognito_client_id = local.auth_enabled ? aws_cognito_user_pool_client.console[0].id : ""
  access_environment = {
    PHASE3_ACCESS_MODE       = var.access_mode
    PHASE3_COGNITO_ISSUER    = local.cognito_issuer
    PHASE3_COGNITO_CLIENT_ID = local.cognito_client_id
  }
}

resource "aws_cognito_user_pool" "console" {
  count               = local.auth_enabled ? 1 : 0
  name                = "${var.bucket_prefix}-p3-console-users"
  deletion_protection = "ACTIVE"
  username_attributes = ["email"]
  mfa_configuration   = "ON"

  auto_verified_attributes = ["email"]

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  username_configuration {
    case_sensitive = false
  }

  lifecycle {
    precondition {
      condition     = var.cognito_domain_prefix != ""
      error_message = "invite_only access requires cognito_domain_prefix for the Hosted UI sign-in page."
    }
  }
}

resource "aws_cognito_user_pool_domain" "console" {
  count        = local.auth_enabled ? 1 : 0
  domain       = var.cognito_domain_prefix
  user_pool_id = aws_cognito_user_pool.console[0].id
}

resource "aws_cognito_user_pool_client" "console" {
  count           = local.auth_enabled ? 1 : 0
  name            = "${var.bucket_prefix}-p3-console"
  user_pool_id    = aws_cognito_user_pool.console[0].id
  generate_secret = false

  explicit_auth_flows           = ["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"]
  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true
  auth_session_validity         = 3

  allowed_oauth_flows_user_pool_client = length(local.auth_callback_urls) > 0
  allowed_oauth_flows                  = length(local.auth_callback_urls) > 0 ? ["code"] : []
  allowed_oauth_scopes                 = length(local.auth_callback_urls) > 0 ? ["openid", "email"] : []
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = local.auth_callback_urls
  logout_urls                          = local.auth_callback_urls

  id_token_validity      = 60
  access_token_validity  = 60
  refresh_token_validity = 8
  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "hours"
  }
}

resource "aws_api_gateway_authorizer" "cognito" {
  count           = local.auth_enabled ? 1 : 0
  name            = "${var.bucket_prefix}-p3-console-users"
  rest_api_id     = aws_api_gateway_rest_api.public[0].id
  type            = "COGNITO_USER_POOLS"
  identity_source = "method.request.header.Authorization"
  provider_arns   = [aws_cognito_user_pool.console[0].arn]
}

# Stage-wide throttling applies in both modes. In invite_only mode it replaces
# the per-IP WAF rate rules as the traffic bound.
resource "aws_api_gateway_method_settings" "throttle" {
  count       = var.enable_stage2 ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.public[0].id
  stage_name  = aws_api_gateway_stage.public[0].stage_name
  method_path = "*/*"
  settings {
    throttling_rate_limit  = var.api_throttle_rate_limit
    throttling_burst_limit = var.api_throttle_burst_limit
    metrics_enabled        = true
    logging_level          = "OFF"
    data_trace_enabled     = false
  }
}

# Same-origin runtime configuration for the console. It holds only public
# client identifiers: no secrets, tokens, or account data.
resource "aws_s3_object" "auth_config" {
  count         = var.enable_stage3 ? 1 : 0
  bucket        = aws_s3_bucket.web[0].id
  key           = "auth-config.json"
  content_type  = "application/json; charset=utf-8"
  cache_control = "no-cache, max-age=0, must-revalidate"
  content = local.auth_enabled ? jsonencode({
    mode        = "invite_only"
    clientId    = local.cognito_client_id
    hostedUiUrl = local.cognito_hosted_ui
    redirectUri = "${local.console_origin}/"
    scopes      = ["openid", "email"]
  }) : jsonencode({ mode = "public" })
}
