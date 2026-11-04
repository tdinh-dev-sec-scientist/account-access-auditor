locals {
  aws_budget_name   = "${var.bucket_prefix}-phase3-monthly-aws"
  budget_topic_name = "${var.bucket_prefix}-phase3-budget-kill"
  kill_switch_name  = "${var.bucket_prefix}-phase3-kill-switch"
}

resource "aws_sns_topic" "budget_kill" {
  count = var.enable_stage4 ? 1 : 0
  name  = local.budget_topic_name
}

resource "aws_sns_topic_policy" "budget_kill" {
  count = var.enable_stage4 ? 1 : 0
  arn   = aws_sns_topic.budget_kill[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowOnlyThisAccountsBudgetsService"
      Effect    = "Allow"
      Principal = { Service = "budgets.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.budget_kill[0].arn
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          "aws:SourceArn"     = "arn:${data.aws_partition.current.partition}:budgets::${data.aws_caller_identity.current.account_id}:budget/${local.aws_budget_name}"
        }
      }
    }]
  })
}

resource "aws_iam_role" "kill_switch" {
  count = var.enable_stage4 ? 1 : 0
  name  = local.kill_switch_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "kill_switch_runtime" {
  count = var.enable_stage4 ? 1 : 0
  name  = "DisableOnlyPhase3RuntimeFlags"
  role  = aws_iam_role.kill_switch[0].id
  policy = templatefile("${path.module}/../policies/rin-kill-switch.json", {
    feature_table_arn = aws_dynamodb_table.rin_feature[0].arn
  })
}

resource "aws_cloudwatch_log_group" "kill_switch" {
  count             = var.enable_stage4 ? 1 : 0
  name              = "/aws/lambda/${local.kill_switch_name}"
  retention_in_days = 30
}

resource "aws_iam_role_policy" "kill_switch_logs" {
  count = var.enable_stage4 ? 1 : 0
  name  = "WriteOnlyOwnLambdaLogs"
  role  = aws_iam_role.kill_switch[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.kill_switch[0].arn}:*"
    }]
  })
}

resource "aws_lambda_function" "kill_switch" {
  count            = var.enable_stage4 ? 1 : 0
  function_name    = local.kill_switch_name
  role             = aws_iam_role.kill_switch[0].arn
  runtime          = "python3.12"
  handler          = "phase3.kill_switch.lambda_handler"
  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)
  timeout          = 15
  memory_size      = 256
  publish          = true
  depends_on       = [aws_iam_role_policy.kill_switch_runtime, aws_iam_role_policy.kill_switch_logs]
  environment {
    variables = {
      PHASE3_FEATURE_TABLE         = aws_dynamodb_table.rin_feature[0].name
      PHASE3_BUDGET_KILL_TOPIC_ARN = aws_sns_topic.budget_kill[0].arn
    }
  }
}

resource "aws_lambda_permission" "budget_kill" {
  count         = var.enable_stage4 ? 1 : 0
  statement_id  = "AllowIsolatedBudgetTopicOnly"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kill_switch[0].function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.budget_kill[0].arn
}

resource "aws_sns_topic_subscription" "budget_kill" {
  count      = var.enable_stage4 ? 1 : 0
  topic_arn  = aws_sns_topic.budget_kill[0].arn
  protocol   = "lambda"
  endpoint   = aws_lambda_function.kill_switch[0].arn
  depends_on = [aws_lambda_permission.budget_kill]
}

resource "aws_budgets_budget" "monthly_aws" {
  count        = var.enable_stage4 ? 1 : 0
  name         = local.aws_budget_name
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  cost_types {
    include_credit             = true
    include_discount           = true
    include_other_subscription = true
    include_recurring          = true
    include_refund             = true
    include_subscription       = true
    include_support            = true
    include_tax                = true
    include_upfront            = true
    use_amortized              = false
    use_blended                = false
  }
  depends_on = [aws_sns_topic_policy.budget_kill]
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_kill[0].arn]
  }
}
