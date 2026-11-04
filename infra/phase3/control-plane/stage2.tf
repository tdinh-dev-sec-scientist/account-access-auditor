locals {
  public_bucket_name = "${var.bucket_prefix}-p3-public-${data.aws_caller_identity.current.account_id}"
  public_table_name  = "${var.bucket_prefix}-p3-public-index"
  publisher_name     = "${var.bucket_prefix}-p3-publisher"
  public_api_name    = "${var.bucket_prefix}-p3-public-api"
  public_routes      = toset(["latest", "runs", "findings", "drift"])
}

resource "aws_s3_bucket" "public_results" {
  #checkov:skip=CKV_AWS_145:Public sanitized results use SSE-S3 at rest; a KMS customer-managed key adds cost without improving the public boundary.
  count         = var.enable_stage2 ? 1 : 0
  bucket        = local.public_bucket_name
  force_destroy = false
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "public_results" {
  count                   = var.enable_stage2 ? 1 : 0
  bucket                  = aws_s3_bucket.public_results[0].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "public_results" {
  count  = var.enable_stage2 ? 1 : 0
  bucket = aws_s3_bucket.public_results[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "public_results" {
  count  = var.enable_stage2 ? 1 : 0
  bucket = aws_s3_bucket.public_results[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "public_results_transport" {
  count  = var.enable_stage2 ? 1 : 0
  bucket = aws_s3_bucket.public_results[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.public_results[0].arn, "${aws_s3_bucket.public_results[0].arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_dynamodb_table" "public_index" {
  count        = var.enable_stage2 ? 1 : 0
  name         = local.public_table_name
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
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
}

# Terraform creates the secret container only. The owner inserts the base64
# encoded 32-byte HMAC key through an approved secret-handling channel.
resource "aws_secretsmanager_secret" "pseudonym_key" {
  count                   = var.enable_stage2 ? 1 : 0
  name                    = "${var.bucket_prefix}/phase3/public-pseudonym-hmac"
  recovery_window_in_days = 30
}

resource "aws_iam_role" "publisher" {
  count = var.enable_stage2 ? 1 : 0
  name  = local.publisher_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "publisher_store" {
  count = var.enable_stage2 ? 1 : 0
  name  = "PrivateReadAndSanitizedPublicPublish"
  role  = aws_iam_role.publisher[0].id
  policy = templatefile("${path.module}/../policies/public-publisher-runtime.json", {
    demo_account_id      = var.demo_account_id
    private_bucket_arn   = aws_s3_bucket.private_snapshots.arn
    public_bucket_arn    = aws_s3_bucket.public_results[0].arn
    public_table_arn     = aws_dynamodb_table.public_index[0].arn
    pseudonym_secret_arn = aws_secretsmanager_secret.pseudonym_key[0].arn
  })
}

resource "aws_cloudwatch_log_group" "publisher" {
  count             = var.enable_stage2 ? 1 : 0
  name              = "/aws/lambda/${local.publisher_name}"
  retention_in_days = 30
}

resource "aws_iam_role_policy" "publisher_logs" {
  count = var.enable_stage2 ? 1 : 0
  name  = "WriteOnlyOwnLambdaLogs"
  role  = aws_iam_role.publisher[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.publisher[0].arn}:*"
    }]
  })
}

resource "aws_lambda_function" "publisher" {
  count            = var.enable_stage2 ? 1 : 0
  function_name    = local.publisher_name
  role             = aws_iam_role.publisher[0].arn
  runtime          = "python3.12"
  handler          = "phase3.publisher.lambda_handler"
  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)
  timeout          = 300
  memory_size      = 512
  publish          = true
  depends_on       = [aws_iam_role_policy.publisher_store, aws_iam_role_policy.publisher_logs]
  environment {
    variables = {
      PHASE3_TARGET_ACCOUNT_ID       = var.demo_account_id
      PHASE3_PRIVATE_SNAPSHOT_BUCKET = aws_s3_bucket.private_snapshots.bucket
      PHASE3_PUBLIC_RESULTS_BUCKET   = aws_s3_bucket.public_results[0].bucket
      PHASE3_PUBLIC_INDEX_TABLE      = aws_dynamodb_table.public_index[0].name
      PHASE3_PSEUDONYM_SECRET_ARN    = aws_secretsmanager_secret.pseudonym_key[0].arn
    }
  }
}

resource "aws_iam_role" "public_api" {
  count = var.enable_stage2 ? 1 : 0
  name  = "${var.bucket_prefix}-p3-public-api"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "public_api_read" {
  count = var.enable_stage2 ? 1 : 0
  name  = "ReadOnlySanitizedPublicResults"
  role  = aws_iam_role.public_api[0].id
  policy = templatefile("${path.module}/../policies/public-api-readonly.json", {
    public_bucket_arn = aws_s3_bucket.public_results[0].arn
    public_table_arn  = aws_dynamodb_table.public_index[0].arn
  })
}

resource "aws_cloudwatch_log_group" "public_api" {
  count             = var.enable_stage2 ? 1 : 0
  name              = "/aws/lambda/${var.bucket_prefix}-p3-public-api"
  retention_in_days = 30
}

resource "aws_iam_role_policy" "public_api_logs" {
  count = var.enable_stage2 ? 1 : 0
  name  = "WriteOnlyOwnLambdaLogs"
  role  = aws_iam_role.public_api[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.public_api[0].arn}:*"
    }]
  })
}

resource "aws_lambda_function" "public_api" {
  count            = var.enable_stage2 ? 1 : 0
  function_name    = "${var.bucket_prefix}-p3-public-api"
  role             = aws_iam_role.public_api[0].arn
  runtime          = "python3.12"
  handler          = "phase3.public_api.lambda_handler"
  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)
  timeout          = 30
  memory_size      = 512
  publish          = true
  depends_on = [
    aws_iam_role_policy.public_api_read,
    aws_iam_role_policy.public_api_logs,
    aws_iam_role_policy.public_api_feature_read
  ]
  environment {
    variables = {
      PHASE3_PUBLIC_RESULTS_BUCKET = aws_s3_bucket.public_results[0].bucket
      PHASE3_PUBLIC_INDEX_TABLE    = aws_dynamodb_table.public_index[0].name
      PHASE3_FEATURE_TABLE         = var.enable_stage3 ? aws_dynamodb_table.rin_feature[0].name : ""
    }
  }
}

resource "aws_api_gateway_rest_api" "public" {
  count = var.enable_stage2 ? 1 : 0
  name  = local.public_api_name
  endpoint_configuration {
    types = ["REGIONAL"]
  }
  disable_execute_api_endpoint = false
}

resource "aws_api_gateway_resource" "api" {
  count       = var.enable_stage2 ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.public[0].id
  parent_id   = aws_api_gateway_rest_api.public[0].root_resource_id
  path_part   = "api"
}

resource "aws_api_gateway_resource" "public_route" {
  for_each    = var.enable_stage2 ? local.public_routes : toset([])
  rest_api_id = aws_api_gateway_rest_api.public[0].id
  parent_id   = aws_api_gateway_resource.api[0].id
  path_part   = each.key
}

resource "aws_api_gateway_method" "public_get" {
  for_each      = var.enable_stage2 ? local.public_routes : toset([])
  rest_api_id   = aws_api_gateway_rest_api.public[0].id
  resource_id   = aws_api_gateway_resource.public_route[each.key].id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "public_head" {
  for_each      = var.enable_stage2 ? local.public_routes : toset([])
  rest_api_id   = aws_api_gateway_rest_api.public[0].id
  resource_id   = aws_api_gateway_resource.public_route[each.key].id
  http_method   = "HEAD"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "public_get" {
  for_each                = var.enable_stage2 ? local.public_routes : toset([])
  rest_api_id             = aws_api_gateway_rest_api.public[0].id
  resource_id             = aws_api_gateway_resource.public_route[each.key].id
  http_method             = aws_api_gateway_method.public_get[each.key].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.public_api[0].invoke_arn
}

resource "aws_api_gateway_integration" "public_head" {
  for_each                = var.enable_stage2 ? local.public_routes : toset([])
  rest_api_id             = aws_api_gateway_rest_api.public[0].id
  resource_id             = aws_api_gateway_resource.public_route[each.key].id
  http_method             = aws_api_gateway_method.public_head[each.key].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.public_api[0].invoke_arn
}

resource "aws_lambda_permission" "api_public_get" {
  for_each      = var.enable_stage2 ? local.public_routes : toset([])
  statement_id  = "AllowApiGatewayGet${title(each.key)}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_api[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.public[0].execution_arn}/*/GET/api/${each.key}"
}

resource "aws_lambda_permission" "api_public_head" {
  for_each      = var.enable_stage2 ? local.public_routes : toset([])
  statement_id  = "AllowApiGatewayHead${title(each.key)}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_api[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.public[0].execution_arn}/*/HEAD/api/${each.key}"
}

resource "aws_api_gateway_deployment" "public" {
  count       = var.enable_stage2 ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.public[0].id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_method.public_get,
      aws_api_gateway_method.public_head,
      aws_api_gateway_integration.public_get,
      aws_api_gateway_integration.public_head,
      aws_api_gateway_integration.rin_post,
      var.enable_stage3
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_api_gateway_integration.public_get,
    aws_api_gateway_integration.public_head,
    aws_api_gateway_integration.rin_post
  ]
}

resource "aws_api_gateway_stage" "public" {
  count                = var.enable_stage2 ? 1 : 0
  deployment_id        = aws_api_gateway_deployment.public[0].id
  rest_api_id          = aws_api_gateway_rest_api.public[0].id
  stage_name           = "v1"
  xray_tracing_enabled = false
}

resource "aws_wafv2_web_acl" "api_origin" {
  count       = var.enable_stage2 ? 1 : 0
  name        = "${var.bucket_prefix}-p3-api-origin"
  description = "Rate limit the direct regional API origin."
  scope       = "REGIONAL"
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
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "phase3-api-rate-limit"
      sampled_requests_enabled   = false
    }
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "phase3-api-origin"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl_association" "api_origin" {
  count        = var.enable_stage2 ? 1 : 0
  resource_arn = "arn:${data.aws_partition.current.partition}:apigateway:${var.aws_region}::/restapis/${aws_api_gateway_rest_api.public[0].id}/stages/${aws_api_gateway_stage.public[0].stage_name}"
  web_acl_arn  = aws_wafv2_web_acl.api_origin[0].arn
}

resource "aws_lambda_permission" "workflow_publisher" {
  count          = var.enable_stage2 && var.enable_scan_pipeline ? 1 : 0
  statement_id   = "AllowOnlyPhase3WorkflowPublisher"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.publisher[0].function_name
  principal      = "states.amazonaws.com"
  source_arn     = aws_sfn_state_machine.scan[0].arn
  source_account = data.aws_caller_identity.current.account_id
}
