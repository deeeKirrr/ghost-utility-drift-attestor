locals {
  bucket_name = var.create_bucket ? aws_s3_bucket.report_bucket[0].id : var.bucket_name
  bucket_arn  = var.create_bucket ? aws_s3_bucket.report_bucket[0].arn : "arn:aws:s3:::${var.bucket_name}"
  prefix      = trim(var.prefix, "/")
  subnets     = var.use_default_vpc ? data.aws_subnets.default.ids : var.subnet_ids
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "report_bucket" {
  count  = var.create_bucket ? 1 : 0
  bucket = var.bucket_name
}

resource "aws_s3_bucket_public_access_block" "report_bucket" {
  count                   = var.create_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.report_bucket[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_vpc" "default" {
  count   = var.use_default_vpc ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.use_default_vpc ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }
}

resource "aws_ecs_cluster" "this" {
  name = var.cluster_name
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.service_name}"
  retention_in_days = 30
}

resource "aws_iam_role" "task_execution" {
  name               = "${var.service_name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name               = "${var.service_name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${var.service_name}-policy"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_policy.json
}

data "aws_iam_policy_document" "task_policy" {
  statement {
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "iam:List*",
      "iam:Get*",
      "ec2:DescribeSecurityGroups",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetPublicAccessBlock",
      "s3:ListAllMyBuckets",
      "s3:ListBucket",
      "s3:GetObject",
      "s3:PutObject",
      "config:DescribeConfigurationRecorders",
      "config:DescribeConfigurationRecorderStatus",
      "sts:GetCallerIdentity"
    ]
    resources = ["*"]
  }

  statement {
    actions = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [
      local.bucket_arn,
      "${local.bucket_arn}/${local.prefix}/*"
    ]
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.service_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn        = aws_iam_role.task_execution.arn
  task_role_arn             = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "attestor"
      image     = var.image
      essential = true
      environment = [
        { name = "ATT_BUCKET", value = local.bucket_name },
        { name = "ATT_PREFIX", value = local.prefix },
        { name = "ATT_REGION", value = var.region }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_cloudwatch_event_rule" "monthly" {
  name                = "${var.service_name}-monthly"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "ecs" {
  rule      = aws_cloudwatch_event_rule.monthly.name
  target_id = "ecs"
  arn       = aws_ecs_cluster.this.arn
  role_arn  = aws_iam_role.events.arn

  ecs_target {
    task_definition_arn = aws_ecs_task_definition.this.arn
    task_count          = 1
    launch_type         = "FARGATE"
    network_configuration {
      subnets         = local.subnets
      security_groups = var.security_group_ids
      assign_public_ip = false
    }
  }
}

resource "aws_iam_role" "events" {
  name               = "${var.service_name}-events"
  assume_role_policy = data.aws_iam_policy_document.events_assume.json
}

data "aws_iam_policy_document" "events_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "events" {
  name   = "${var.service_name}-events-policy"
  role   = aws_iam_role.events.id
  policy = data.aws_iam_policy_document.events_policy.json
}

data "aws_iam_policy_document" "events_policy" {
  statement {
    actions   = ["ecs:RunTask"]
    resources = [aws_ecs_task_definition.this.arn]
  }
  statement {
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.task_execution.arn, aws_iam_role.task.arn]
  }
}
