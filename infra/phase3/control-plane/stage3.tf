locals {
  web_bucket_name = "${var.bucket_prefix}-p3-web-${data.aws_caller_identity.current.account_id}"
  rin_name        = "${var.bucket_prefix}-p3-rin"
  quota_name      = "${var.bucket_prefix}-p3-rin-quota"
  feature_name    = "${var.bucket_prefix}-p3-rin-feature"
  rin_request_cost_usd = (
    var.rin_max_input_tokens * coalesce(var.rin_input_cost_per_million_tokens_usd, 0) +
    var.rin_max_output_tokens * coalesce(var.rin_output_cost_per_million_tokens_usd, 0)
  ) / 1000000
  rin_daily_cap = var.provider_monthly_budget_usd == null || local.rin_request_cost_usd <= 0 ? 0 : min(
    1000,
    max(0, floor((var.provider_monthly_budget_usd * 0.8 / 30) / local.rin_request_cost_usd))
  )
  web_files = var.enable_stage3 ? fileset(var.web_asset_dir, "**") : toset([])
  web_content_types = {
    "index.html"  = "text/html; charset=utf-8"
    "console.css" = "text/css; charset=utf-8"
    "console.js"  = "text/javascript; charset=utf-8"
  }
}

resource "aws_s3_bucket" "web" {
  count         = var.enable_stage3 ? 1 : 0
  bucket        = local.web_bucket_name
  force_destroy = false
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "web" {
  count                   = var.enable_stage3 ? 1 : 0
  bucket                  = aws_s3_bucket.web[0].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "web" {
  count  = var.enable_stage3 ? 1 : 0
  bucket = aws_s3_bucket.web[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "web" {
  count  = var.enable_stage3 ? 1 : 0
  bucket = aws_s3_bucket.web[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "web_assets" {
  for_each      = local.web_files
  bucket        = aws_s3_bucket.web[0].id
  key           = each.value
  source        = "${var.web_asset_dir}/${each.value}"
  source_hash   = filemd5("${var.web_asset_dir}/${each.value}")
  content_type  = lookup(local.web_content_types, each.value, "application/octet-stream")
  cache_control = each.value == "index.html" ? "no-cache, max-age=0, must-revalidate" : "public, max-age=300, must-revalidate"
}

resource "aws_cloudfront_origin_access_control" "web" {
  count                             = var.enable_stage3 ? 1 : 0
  name                              = "${var.bucket_prefix}-p3-web-oac"
  description                       = "Private S3 origin for the Phase 3 static console."
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_cache_policy" "web" {
  count       = var.enable_stage3 ? 1 : 0
  name        = "${var.bucket_prefix}-p3-web-cache"
  min_ttl     = 0
  default_ttl = 60
  max_ttl     = 300
  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true
    cookies_config { cookie_behavior = "none" }
    headers_config { header_behavior = "none" }
    query_strings_config { query_string_behavior = "none" }
  }
}

resource "aws_cloudfront_origin_request_policy" "api" {
  count   = var.enable_stage3 ? 1 : 0
  name    = "${var.bucket_prefix}-p3-api-origin-request"
  comment = "Forward only content negotiation and query parameters to the public API."
  headers_config {
    header_behavior = "whitelist"
    headers {
      items = ["Accept", "Content-Type"]
    }
  }
  cookies_config { cookie_behavior = "none" }
  query_strings_config { query_string_behavior = "all" }
}

resource "aws_cloudfront_response_headers_policy" "security" {
  count = var.enable_stage3 ? 1 : 0
  name  = "${var.bucket_prefix}-p3-security-headers"
  security_headers_config {
    content_type_options { override = true }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_security_policy {
      content_security_policy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
      override                = true
    }
  }
  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = "camera=(), microphone=(), geolocation=()"
      override = true
    }
  }
}

resource "aws_wafv2_web_acl" "cloudfront" {
  count       = var.enable_stage3 ? 1 : 0
  provider    = aws.us_east_1
  name        = "${var.bucket_prefix}-p3-cloudfront"
  description = "Rate limit public console and API traffic at the edge."
  scope       = "CLOUDFRONT"
  default_action {
    allow {}
  }
  rule {
    name     = "RateLimit100PerFiveMinutes"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit                 = 100
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string         = "/api/"
            positional_constraint = "STARTS_WITH"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "phase3-cloudfront-rate-limit"
      sampled_requests_enabled   = false
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "phase3-cloudfront"
    sampled_requests_enabled   = false
  }
}

resource "aws_cloudfront_distribution" "web" {
  count               = var.enable_stage3 ? 1 : 0
  enabled             = true
  comment             = "Guardrails Phase 3 live, sanitized AWS demo"
  default_root_object = "index.html"
  aliases             = var.domain_name == "" ? [] : [var.domain_name]
  price_class         = "PriceClass_100"
  web_acl_id          = aws_wafv2_web_acl.cloudfront[0].arn

  origin {
    domain_name              = aws_s3_bucket.web[0].bucket_regional_domain_name
    origin_id                = "private-web-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.web[0].id
  }

  origin {
    domain_name = "${aws_api_gateway_rest_api.public[0].id}.execute-api.${var.aws_region}.${data.aws_partition.current.dns_suffix}"
    origin_id   = "regional-public-api"
    origin_path = "/v1"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id           = "private-web-s3"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = aws_cloudfront_cache_policy.web[0].id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
    compress                   = true
  }

  ordered_cache_behavior {
    path_pattern               = "/api/*"
    target_origin_id           = "regional-public-api"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "POST"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.api[0].id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id
    compress                   = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.domain_name == ""
    acm_certificate_arn            = var.domain_name == "" ? null : var.certificate_arn
    ssl_support_method             = var.domain_name == "" ? null : "sni-only"
    minimum_protocol_version       = var.domain_name == "" ? null : "TLSv1.2_2021"
  }

  depends_on = [
    aws_s3_bucket_public_access_block.web,
    aws_s3_bucket_server_side_encryption_configuration.web,
    aws_s3_object.web_assets
  ]
}

resource "aws_s3_bucket_policy" "web_oac" {
  count  = var.enable_stage3 ? 1 : 0
  bucket = aws_s3_bucket.web[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontOriginAccessControlOnly"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.web[0].arn}/*"
        Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.web[0].arn } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.web[0].arn, "${aws_s3_bucket.web[0].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_route53_record" "web_alias" {
  count   = var.enable_stage3 && var.domain_name != "" ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_cloudfront_distribution.web[0].domain_name
    zone_id                = aws_cloudfront_distribution.web[0].hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_api_gateway_resource" "rin" {
  count       = var.enable_stage3 ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.public[0].id
  parent_id   = aws_api_gateway_resource.api[0].id
  path_part   = "rin"
}

resource "aws_api_gateway_method" "rin_post" {
  count         = var.enable_stage3 ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.public[0].id
  resource_id   = aws_api_gateway_resource.rin[0].id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_iam_role" "rin" {
  count = var.enable_stage3 ? 1 : 0
  name  = local.rin_name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_dynamodb_table" "rin_feature" {
  count        = var.enable_stage3 ? 1 : 0
  name         = local.feature_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
}

resource "aws_dynamodb_table_item" "platform_config" {
  count      = var.enable_stage3 ? 1 : 0
  table_name = aws_dynamodb_table.rin_feature[0].name
  hash_key   = "pk"
  range_key  = "sk"
  item = jsonencode({
    pk          = { S = "PLATFORM" }
    sk          = { S = "CONFIG" }
    rin_enabled = { BOOL = var.rin_enabled && local.rin_daily_cap > 0 }
    static_mode = { BOOL = false }
  })
  lifecycle {
    ignore_changes = [item]
    precondition {
      condition     = !var.rin_enabled || local.rin_daily_cap > 0
      error_message = "Configured model rates and provider budget produce no safe positive daily invocation cap."
    }
  }
}

resource "aws_dynamodb_table" "rin_quota" {
  count        = var.enable_stage3 ? 1 : 0
  name         = local.quota_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  server_side_encryption { enabled = true }
}

resource "aws_iam_role" "rin_quota" {
  count = var.enable_stage3 ? 1 : 0
  name  = "${var.bucket_prefix}-p3-rin-quota-writer"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "rin_quota_table" {
  count  = var.enable_stage3 ? 1 : 0
  name   = "UpdateOnlyRinQuotaTable"
  role   = aws_iam_role.rin_quota[0].id
  policy = templatefile("${path.module}/../policies/rin-quota-writer.json", { quota_table_arn = aws_dynamodb_table.rin_quota[0].arn })
}

resource "aws_cloudwatch_log_group" "rin_quota" {
  count             = var.enable_stage3 ? 1 : 0
  name              = "/aws/lambda/${var.bucket_prefix}-p3-rin-quota"
  retention_in_days = 30
}

resource "aws_iam_role_policy" "rin_quota_logs" {
  count = var.enable_stage3 ? 1 : 0
  name  = "WriteOnlyOwnLambdaLogs"
  role  = aws_iam_role.rin_quota[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.rin_quota[0].arn}:*"
    }]
  })
}

resource "aws_lambda_function" "rin_quota" {
  count            = var.enable_stage3 ? 1 : 0
  function_name    = "${var.bucket_prefix}-p3-rin-quota"
  role             = aws_iam_role.rin_quota[0].arn
  runtime          = "python3.12"
  handler          = "phase3.quotas.lambda_handler"
  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)
  timeout          = 10
  memory_size      = 256
  publish          = true
  depends_on       = [aws_iam_role_policy.rin_quota_table, aws_iam_role_policy.rin_quota_logs]
  environment {
    variables = {
      PHASE3_RIN_QUOTA_TABLE = aws_dynamodb_table.rin_quota[0].name
      PHASE3_RIN_DAILY_CAP   = tostring(local.rin_daily_cap)
    }
  }
}

resource "aws_sns_topic" "rin_daily_alert" {
  count = var.enable_stage4 && var.rin_enabled ? 1 : 0
  name  = "${var.bucket_prefix}-p3-rin-daily-alert"
}

resource "aws_sns_topic_subscription" "rin_daily_alert_email" {
  count     = var.enable_stage4 && var.rin_enabled ? 1 : 0
  topic_arn = aws_sns_topic.rin_daily_alert[0].arn
  protocol  = "email"
  endpoint  = var.budget_alert_email
}

resource "aws_cloudwatch_metric_alarm" "rin_daily_limit" {
  count               = var.enable_stage4 && var.rin_enabled ? 1 : 0
  alarm_name          = "${var.bucket_prefix}-p3-rin-daily-limit"
  alarm_description   = "A Rin request was blocked by the configured daily provider invocation cap."
  namespace           = "Phase3/Rin"
  metric_name         = "DailyLimitReached"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { Service = "Rin" }
  alarm_actions       = [aws_sns_topic.rin_daily_alert[0].arn]
}

resource "aws_secretsmanager_secret" "rin_provider_key" {
  count                   = var.enable_stage3 ? 1 : 0
  name                    = "${var.bucket_prefix}/phase3/rin-provider-key"
  recovery_window_in_days = 30
}

resource "aws_iam_role_policy" "rin_runtime" {
  count = var.enable_stage3 ? 1 : 0
  name  = "ReadOnlyPublicEvidenceAndInvokeQuota"
  role  = aws_iam_role.rin[0].id
  policy = templatefile("${path.module}/../policies/rin-readonly.json", {
    public_bucket_arn   = aws_s3_bucket.public_results[0].arn
    public_table_arn    = aws_dynamodb_table.public_index[0].arn
    feature_table_arn   = aws_dynamodb_table.rin_feature[0].arn
    provider_secret_arn = aws_secretsmanager_secret.rin_provider_key[0].arn
    quota_function_arn  = aws_lambda_function.rin_quota[0].arn
  })
}

resource "aws_iam_role_policy" "public_api_feature_read" {
  count = var.enable_stage3 ? 1 : 0
  name  = "ReadOnlyPhase3PlatformFlags"
  role  = aws_iam_role.public_api[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "dynamodb:GetItem"
      Resource = aws_dynamodb_table.rin_feature[0].arn
    }]
  })
}

resource "aws_cloudwatch_log_group" "rin" {
  count             = var.enable_stage3 ? 1 : 0
  name              = "/aws/lambda/${local.rin_name}"
  retention_in_days = 30
}

resource "aws_iam_role_policy" "rin_logs" {
  count = var.enable_stage3 ? 1 : 0
  name  = "WriteOnlyOwnLambdaLogs"
  role  = aws_iam_role.rin[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.rin[0].arn}:*"
    }]
  })
}

resource "aws_lambda_function" "rin" {
  count            = var.enable_stage3 ? 1 : 0
  function_name    = local.rin_name
  role             = aws_iam_role.rin[0].arn
  runtime          = "python3.12"
  handler          = "phase3.rin_service.lambda_handler"
  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)
  timeout          = 45
  memory_size      = 512
  publish          = true
  depends_on       = [aws_iam_role_policy.rin_runtime, aws_iam_role_policy.rin_logs]
  environment {
    variables = {
      PHASE3_PUBLIC_RESULTS_BUCKET   = aws_s3_bucket.public_results[0].bucket
      PHASE3_PUBLIC_INDEX_TABLE      = aws_dynamodb_table.public_index[0].name
      PHASE3_RIN_FEATURE_TABLE       = aws_dynamodb_table.rin_feature[0].name
      PHASE3_RIN_QUOTA_FUNCTION_ARN  = aws_lambda_function.rin_quota[0].arn
      PHASE3_RIN_PROVIDER_SECRET_ARN = aws_secretsmanager_secret.rin_provider_key[0].arn
      PHASE3_RIN_MODEL               = var.rin_model
      PHASE3_RIN_MAX_INPUT_TOKENS    = tostring(var.rin_max_input_tokens)
      PHASE3_RIN_MAX_OUTPUT_TOKENS   = tostring(var.rin_max_output_tokens)
    }
  }
}

resource "aws_api_gateway_integration" "rin_post" {
  count                   = var.enable_stage3 ? 1 : 0
  rest_api_id             = aws_api_gateway_rest_api.public[0].id
  resource_id             = aws_api_gateway_resource.rin[0].id
  http_method             = aws_api_gateway_method.rin_post[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.rin[0].invoke_arn
}

resource "aws_lambda_permission" "api_rin_post" {
  count         = var.enable_stage3 ? 1 : 0
  statement_id  = "AllowApiGatewayRinPostOnly"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rin[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.public[0].execution_arn}/*/POST/api/rin"
}
