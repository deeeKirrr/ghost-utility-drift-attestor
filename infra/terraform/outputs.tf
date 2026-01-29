output "event_rule_name" {
  value = aws_cloudwatch_event_rule.monthly.name
}

output "reports_prefix" {
  value = "s3://${local.bucket_name}/${local.prefix}/reports/"
}

output "state_path" {
  value = "s3://${local.bucket_name}/${local.prefix}/state/latest.json"
}
