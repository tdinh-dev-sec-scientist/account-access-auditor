locals {
  private_bucket_name      = "${var.bucket_prefix}-p3-private-${data.aws_caller_identity.current.account_id}"
  private_table_name       = "${var.bucket_prefix}-p3-private-runs"
  scan_worker_name         = "${var.bucket_prefix}-p3-scan-worker"
  snapshot_writer_name     = "${var.bucket_prefix}-p3-snapshot-writer"
  target_role_arn          = "arn:${data.aws_partition.current.partition}:iam::${var.demo_account_id}:role/AccountAccessAuditorReadOnly"
  scan_cluster_name        = "${var.bucket_prefix}-p3-scan"
  github_image_subject     = "repo:${var.github_repository}:environment:${var.github_image_environment}"
  github_oidc_provider_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"

  scan_workflow_states = {
    CreateScanRunId = {
      Type       = "Pass"
      Parameters = { "scan_run_id.$" = "States.UUID()" }
      ResultPath = "$.phase3"
      Next       = "ScanReadOnlyDemoAccount"
    }
    ScanReadOnlyDemoAccount = {
      Type     = "Task"
      Resource = "arn:${data.aws_partition.current.partition}:states:::ecs:runTask.sync"
      Parameters = {
        Cluster         = aws_ecs_cluster.scan.arn
        TaskDefinition  = try(aws_ecs_task_definition.scan[0].arn, "unconfigured")
        LaunchType      = "FARGATE"
        PlatformVersion = "LATEST"
        NetworkConfiguration = {
          AwsvpcConfiguration = {
            Subnets        = [aws_subnet.scan.id]
            SecurityGroups = [aws_security_group.scan.id]
            AssignPublicIp = "ENABLED"
          }
        }
        Overrides = {
          ContainerOverrides = [{
            Name = "phase3-scan"
            Environment = [{
              Name      = "PHASE3_SCAN_RUN_ID"
              "Value.$" = "$.phase3.scan_run_id"
            }]
          }]
        }
      }
      ResultPath = "$.scan_task"
      Next       = "GetScanReceipt"
      Catch = [{
        ErrorEquals = ["States.ALL"]
        ResultPath  = "$.scan_failure"
        Next        = "RecordScanFailure"
      }]
    }
    GetScanReceipt = {
      Type     = "Task"
      Resource = "arn:${data.aws_partition.current.partition}:states:::lambda:invoke"
      Parameters = {
        FunctionName = aws_lambda_function.snapshot_writer.arn
        Payload = {
          kind       = "get_receipt"
          "run_id.$" = "$.phase3.scan_run_id"
        }
      }
      ResultSelector = { "receipt.$" = "$.Payload" }
      ResultPath     = "$.scan_receipt"
      Next           = var.enable_stage2 ? "PublishSanitizedSnapshot" : "ScanSucceeded"
      Catch = [{
        ErrorEquals = ["States.ALL"]
        ResultPath  = "$.receipt_failure"
        Next        = "RecordScanFailure"
      }]
    }
    RecordScanFailure = {
      Type     = "Task"
      Resource = "arn:${data.aws_partition.current.partition}:states:::lambda:invoke"
      Parameters = {
        FunctionName = aws_lambda_function.snapshot_writer.arn
        Payload = {
          kind             = "scan_failure"
          "run_id.$"       = "$.phase3.scan_run_id"
          "completed_at.$" = "$$.State.EnteredTime"
        }
      }
      OutputPath = "$.Payload"
      Next       = var.enable_stage2 ? "PublishScanFailure" : "ScanFailed"
    }
    ScanSucceeded = { Type = "Succeed" }
    ScanFailed = {
      Type  = "Fail"
      Error = "Phase3ScanFailed"
      Cause = "The scan failed; the previous complete private snapshot remains authoritative."
    }
  }
  scan_workflow_states_with_publication = merge(local.scan_workflow_states, {
    PublishSanitizedSnapshot = {
      Type     = "Task"
      Resource = "arn:${data.aws_partition.current.partition}:states:::lambda:invoke"
      Parameters = {
        FunctionName = var.enable_stage2 ? aws_lambda_function.publisher[0].arn : aws_lambda_function.snapshot_writer.arn
        Payload      = { "receipt.$" = "$.scan_receipt.receipt" }
      }
      OutputPath = "$.Payload"
      End        = true
      Catch = [{
        ErrorEquals = ["States.ALL"]
        ResultPath  = "$.publication_failure"
        Next        = "RecordPublicationFailure"
      }]
    }
    PublishScanFailure = {
      Type     = "Task"
      Resource = "arn:${data.aws_partition.current.partition}:states:::lambda:invoke"
      Parameters = {
        FunctionName = var.enable_stage2 ? aws_lambda_function.publisher[0].arn : aws_lambda_function.snapshot_writer.arn
        Payload = {
          kind             = "scan_failure"
          "completed_at.$" = "$.completed_at"
        }
      }
      OutputPath = "$.Payload"
      Next       = "ScanFailed"
    }
    RecordPublicationFailure = {
      Type     = "Task"
      Resource = "arn:${data.aws_partition.current.partition}:states:::lambda:invoke"
      Parameters = {
        FunctionName = var.enable_stage2 ? aws_lambda_function.publisher[0].arn : aws_lambda_function.snapshot_writer.arn
        Payload = {
          kind             = "publication_failure"
          "completed_at.$" = "$$.State.EnteredTime"
        }
      }
      OutputPath = "$.Payload"
      Next       = "PublicationPaused"
    }
    PublicationPaused = {
      Type  = "Fail"
      Error = "Phase3PublicationPaused"
      Cause = "The previous complete public snapshot remains active."
    }
  })
}

resource "aws_s3_bucket" "private_snapshots" {
  bucket        = local.private_bucket_name
  force_destroy = false
  tags          = { project = "guardrails-phase3" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "private_snapshots" {
  bucket                  = aws_s3_bucket.private_snapshots.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "private_snapshots" {
  bucket = aws_s3_bucket.private_snapshots.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private_snapshots" {
  bucket = aws_s3_bucket.private_snapshots.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "private_snapshots_transport" {
  bucket = aws_s3_bucket.private_snapshots.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.private_snapshots.arn, "${aws_s3_bucket.private_snapshots.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "private_snapshots" {
  bucket = aws_s3_bucket.private_snapshots.id

  rule {
    id     = "ExpirePrivateSnapshotsAfterHistoryWindow"
    status = "Enabled"
    filter { prefix = "snapshots/" }
    expiration { days = 60 }
    noncurrent_version_expiration { noncurrent_days = 14 }
  }
}

resource "aws_dynamodb_table" "private_runs" {
  name         = local.private_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "account_id"
  range_key    = "sort_key"
  attribute {
    name = "account_id"
    type = "S"
  }
  attribute {
    name = "sort_key"
    type = "S"
  }
  attribute {
    name = "status_pk"
    type = "S"
  }
  attribute {
    name = "status_sk"
    type = "S"
  }
  attribute {
    name = "scan_run_id"
    type = "S"
  }
  global_secondary_index {
    name            = "status-index"
    hash_key        = "status_pk"
    range_key       = "status_sk"
    projection_type = "ALL"
  }
  global_secondary_index {
    name            = "scan-run-index"
    hash_key        = "scan_run_id"
    projection_type = "ALL"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
}

resource "aws_cloudwatch_log_group" "scan_task" {
  name              = "/aws/ecs/${local.scan_worker_name}"
  retention_in_days = 7
}

resource "aws_iam_role" "scan_task" {
  name = local.scan_worker_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "scan_task_assume_target" {
  name = "AssumeOnlyPhase3ReadOnlyTarget"
  role = aws_iam_role.scan_task.id
  policy = templatefile("${path.module}/../policies/scan-worker-runtime.json", {
    demo_account_id = var.demo_account_id
  })
}

resource "aws_iam_role_policy" "scan_task_invoke_private_writer" {
  name = "InvokeOnlyPhase3PrivateSnapshotWriter"
  role = aws_iam_role.scan_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.snapshot_writer.arn
    }]
  })
}

resource "aws_iam_role" "snapshot_writer" {
  name = "${var.bucket_prefix}-p3-snapshot-writer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "snapshot_writer_private_store" {
  name = "PrivateSnapshotsAndRunIndexOnly"
  role = aws_iam_role.snapshot_writer.id
  policy = templatefile("${path.module}/../policies/private-snapshot-writer.json", {
    demo_account_id    = var.demo_account_id
    private_bucket_arn = aws_s3_bucket.private_snapshots.arn
    private_table_arn  = aws_dynamodb_table.private_runs.arn
  })
}

resource "aws_cloudwatch_log_group" "snapshot_writer" {
  name              = "/aws/lambda/${var.bucket_prefix}-p3-snapshot-writer"
  retention_in_days = 7
}

resource "aws_iam_role_policy" "snapshot_writer_logs" {
  name = "WriteOnlyOwnLambdaLogs"
  role = aws_iam_role.snapshot_writer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.snapshot_writer.arn}:*"
    }]
  })
}

resource "aws_lambda_function" "snapshot_writer" {
  function_name    = "${var.bucket_prefix}-p3-snapshot-writer"
  role             = aws_iam_role.snapshot_writer.arn
  runtime          = "python3.12"
  handler          = "phase3.snapshot_writer.lambda_handler"
  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)
  timeout          = 300
  memory_size      = 512
  publish          = true
  depends_on       = [aws_cloudwatch_log_group.snapshot_writer, aws_iam_role_policy.snapshot_writer_private_store, aws_iam_role_policy.snapshot_writer_logs]
  environment {
    variables = {
      PHASE3_TARGET_ACCOUNT_ID       = var.demo_account_id
      PHASE3_SCAN_REGION             = var.aws_region
      PHASE3_PRIVATE_SNAPSHOT_BUCKET = aws_s3_bucket.private_snapshots.bucket
      PHASE3_PRIVATE_RUN_INDEX_TABLE = aws_dynamodb_table.private_runs.name
    }
  }
}

resource "aws_ecs_cluster" "scan" {
  name = local.scan_cluster_name
  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_iam_role" "scan_task_execution" {
  name = "${var.bucket_prefix}-p3-scan-task-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scan_task_execution" {
  name = "PullOnlyPhase3ScanImageAndWriteOwnLogs"
  role = aws_iam_role.scan_task_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = aws_ecr_repository.scan.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.scan_task.arn}:*"
      }
    ]
  })
}

resource "aws_vpc" "scan" {
  cidr_block           = "10.73.0.0/20"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.scan_cluster_name}-vpc" }
}

data "aws_availability_zones" "scan" {
  state = "available"
}

resource "aws_internet_gateway" "scan" {
  vpc_id = aws_vpc.scan.id
}

resource "aws_subnet" "scan" {
  vpc_id                  = aws_vpc.scan.id
  cidr_block              = "10.73.0.0/24"
  availability_zone       = data.aws_availability_zones.scan.names[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.scan_cluster_name}-public" }
}

resource "aws_route_table" "scan" {
  vpc_id = aws_vpc.scan.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.scan.id
  }
}

resource "aws_route_table_association" "scan" {
  subnet_id      = aws_subnet.scan.id
  route_table_id = aws_route_table.scan.id
}

resource "aws_security_group" "scan" {
  name        = "${local.scan_cluster_name}-egress-https"
  description = "No inbound access; HTTPS egress for AWS APIs, ECR, and CloudWatch Logs."
  vpc_id      = aws_vpc.scan.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecr_repository" "scan" {
  name = "${var.bucket_prefix}/phase3-scan"
  # Cosign stores keyless signatures under digest-derived tags and must be able
  # to replace them when the same digest is released again. Runtime task
  # definitions accept only signed image digests, never mutable tags.
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_iam_openid_connect_provider" "github" {
  arn = local.github_oidc_provider_arn
}

resource "aws_iam_role" "scan_image_publisher" {
  name = "${var.bucket_prefix}-p3-scan-image-publisher"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "token.actions.githubusercontent.com:aud"      = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub"      = local.github_image_subject
        "token.actions.githubusercontent.com:ref"      = "refs/heads/main"
        "token.actions.githubusercontent.com:workflow" = "Phase 3 scan image"
      } }
    }]
  })
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "scan_image_publisher" {
  name = "PublishOnlyThePhase3ScanImage"
  role = aws_iam_role.scan_image_publisher.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeImages",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart"
        ]
        Resource = aws_ecr_repository.scan.arn
      }
    ]
  })
}

resource "aws_ecs_task_definition" "scan" {
  count                    = var.enable_scan_pipeline ? 1 : 0
  family                   = "${var.bucket_prefix}-p3-scan"
  cpu                      = "512"
  memory                   = "1024"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.scan_task_execution.arn
  task_role_arn            = aws_iam_role.scan_task.arn
  container_definitions = jsonencode([{
    name      = "phase3-scan"
    image     = var.scan_container_image
    essential = true
    environment = [
      { name = "PHASE3_TARGET_ACCOUNT_ID", value = var.demo_account_id },
      { name = "PHASE3_TARGET_ROLE_ARN", value = local.target_role_arn },
      { name = "PHASE3_SCAN_REGION", value = var.aws_region },
      { name = "PHASE3_SNAPSHOT_WRITER_FUNCTION", value = aws_lambda_function.snapshot_writer.function_name },
      { name = "PHASE3_FAIL_ON", value = "MEDIUM" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.scan_task.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "scan"
      }
    }
  }])
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  depends_on = [aws_iam_role_policy.scan_task_execution]
}

resource "aws_iam_role" "workflow" {
  count = var.enable_scan_pipeline ? 1 : 0
  name  = "${var.bucket_prefix}-p3-scan-workflow"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "workflow_invoke" {
  count = var.enable_scan_pipeline ? 1 : 0
  name  = "RunOnlyPhase3FargateScanAndWriter"
  role  = aws_iam_role.workflow[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ecs:RunTask"
        Resource = aws_ecs_task_definition.scan[0].arn
      },
      {
        Effect   = "Allow"
        Action   = ["ecs:StopTask", "ecs:DescribeTasks"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["events:PutTargets", "events:PutRule", "events:DescribeRule"]
        Resource = "arn:${data.aws_partition.current.partition}:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/StepFunctionsGetEventsForECSTaskRule"
      },
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = [aws_iam_role.scan_task.arn, aws_iam_role.scan_task_execution.arn]
        Condition = { StringEquals = {
          "iam:PassedToService" = "ecs-tasks.amazonaws.com"
        } }
      },
      {
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = concat(
          [aws_lambda_function.snapshot_writer.arn],
          var.enable_stage2 ? [aws_lambda_function.publisher[0].arn] : []
        )
      }
    ]
  })
}

resource "aws_sfn_state_machine" "scan" {
  count    = var.enable_scan_pipeline ? 1 : 0
  name     = "${var.bucket_prefix}-p3-scheduled-scan"
  role_arn = aws_iam_role.workflow[0].arn
  type     = "STANDARD"

  logging_configuration {
    level = "OFF"
  }

  definition = jsonencode({
    Comment = var.enable_stage2 ? "Run a read-only Fargate demo scan, privately persist it, then publish only an allowlisted snapshot." : "Run a read-only Fargate demo scan and persist only through the private snapshot writer."
    StartAt = "CreateScanRunId"
    States  = local.scan_workflow_states_with_publication
  })

  depends_on = [aws_iam_role_policy.workflow_invoke]
}

resource "aws_iam_role" "scheduler" {
  count = var.enable_scan_pipeline ? 1 : 0
  name  = "${var.bucket_prefix}-p3-scan-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler_start_workflow" {
  count = var.enable_scan_pipeline ? 1 : 0
  name  = "StartOnlyPhase3ScanWorkflow"
  role  = aws_iam_role.scheduler[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.scan[0].arn
    }]
  })
}

resource "aws_scheduler_schedule" "scan" {
  count                        = var.enable_scan_pipeline ? 1 : 0
  name                         = "${var.bucket_prefix}-p3-six-hour-scan"
  schedule_expression          = "rate(6 hours)"
  schedule_expression_timezone = "UTC"
  state                        = var.scan_schedule_enabled ? "ENABLED" : "DISABLED"
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_sfn_state_machine.scan[0].arn
    role_arn = aws_iam_role.scheduler[0].arn
    input    = "{}"
    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 2
    }
  }
  depends_on = [aws_iam_role_policy.scheduler_start_workflow]
}
