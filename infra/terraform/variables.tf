variable "region" {
  type        = string
  description = "AWS region to deploy into."
}

variable "bucket_name" {
  type        = string
  description = "S3 bucket for reports and state."
}

variable "prefix" {
  type        = string
  description = "Prefix within the S3 bucket."
  default     = "ghost-utility"
}

variable "create_bucket" {
  type        = bool
  description = "Whether to create the S3 bucket."
  default     = false
}

variable "use_default_vpc" {
  type        = bool
  description = "Whether to use the default VPC/subnets."
  default     = false
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs for Fargate tasks (ignored if use_default_vpc=true)."
  default     = []
}

variable "security_group_ids" {
  type        = list(string)
  description = "Security group IDs for Fargate tasks."
  default     = []
}

variable "schedule_expression" {
  type        = string
  description = "EventBridge schedule expression."
  default     = "cron(0 3 1 * ? *)"
}

variable "image" {
  type        = string
  description = "Container image URI."
  default     = "public.ecr.aws/docker/library/python:3.12"
}

variable "cpu" {
  type        = number
  description = "Task CPU units."
  default     = 256
}

variable "memory" {
  type        = number
  description = "Task memory (MiB)."
  default     = 512
}

variable "cluster_name" {
  type        = string
  description = "ECS cluster name."
  default     = "ghost-utility"
}

variable "service_name" {
  type        = string
  description = "Service name prefix for resources."
  default     = "ghost-utility"
}
