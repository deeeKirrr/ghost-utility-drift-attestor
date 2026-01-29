# Terraform Module - Ghost Utility Drift Attestor

This module provisions ECS Fargate + EventBridge schedule + IAM + CloudWatch Logs for the Ghost Utility container.

## Inputs
- `region` (string): AWS region.
- `bucket_name` (string): S3 bucket for reports/state.
- `prefix` (string): Prefix for outputs.
- `create_bucket` (bool): Create the S3 bucket.
- `use_default_vpc` (bool): Use default VPC/subnets.
- `subnet_ids` (list): Subnets for ECS tasks if not using default VPC.
- `security_group_ids` (list): Security groups for ECS tasks.
- `schedule_expression` (string): EventBridge schedule (monthly by default).
- `image` (string): Container image URI.
- `cpu` / `memory`: Task sizing.

## Outputs
- `event_rule_name`
- `reports_prefix`
- `state_path`

## Notes
- S3 permissions are scoped to the specified bucket/prefix where possible.
- If you provide `use_default_vpc=true`, ensure there is at least one default subnet.
