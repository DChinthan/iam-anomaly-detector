variable "project_name" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "iam-anomaly-detector"
}

variable "environment" {
  description = "Deployment environment (dev/staging/prod)"
  type        = string
  default     = "dev"
}

variable "aws_regions" {
  description = "Regions to aggregate CloudTrail/IAM events from (feeds unique_regions feature)"
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

variable "cloudtrail_log_group_name" {
  description = "Existing CloudWatch Logs log group receiving CloudTrail events"
  type        = string
  default     = "/aws/cloudtrail/events"
}

variable "dynamodb_billing_mode" {
  description = "PAY_PER_REQUEST keeps cost near-zero for a demo/dev workload"
  type        = string
  default     = "PAY_PER_REQUEST"
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "scorer_image_uri" {
  description = "ECR URI for the scoring Lambda's container image (TensorFlow + sklearn are too large for a zip package)"
  type        = string
  default     = ""
}

variable "anthropic_api_key_secret_arn" {
  description = "Secrets Manager ARN holding the Claude API key (leave blank to run GenAI insights in rule-based mock mode)"
  type        = string
  default     = ""
}

variable "enable_cognito_auth" {
  description = "Provision a Cognito user pool for the Streamlit dashboard's production auth path"
  type        = bool
  default     = false
}

variable "schedule_expression" {
  description = "How often the scoring Lambda runs in production (batch-over-recent-window mode)"
  type        = string
  default     = "rate(15 minutes)"
}

variable "tags" {
  type    = map(string)
  default = {}
}
