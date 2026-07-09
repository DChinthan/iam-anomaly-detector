variable "project_name" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "iam-anomaly-detector"
}

variable "gcp_project" {
  description = "GCP project ID to deploy into"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev/staging/prod)"
  type        = string
  default     = "dev"
}

variable "gcp_regions" {
  description = "Regions the audited resources live in. Cloud Logging itself is global/project-scoped, so this does NOT select a per-region API endpoint the way infra/terraform's aws_regions does — it only tags/filters log queries and picks the Cloud Run/Firestore location. See gcp/README.md for the full AWS-vs-GCP regional-model writeup."
  type        = list(string)
  default     = ["us-central1", "us-east1"]
}

variable "audit_log_filter" {
  description = "Cloud Logging filter selecting the IAM/audit log entries this project consumes"
  type        = string
  default     = "logName:\"cloudaudit.googleapis.com\""
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "scorer_image_uri" {
  description = "Artifact Registry URI for the scoring Cloud Run service's container image"
  type        = string
  default     = ""
}

variable "anthropic_api_key_secret_id" {
  description = "Secret Manager secret ID holding the Claude API key (leave blank to run GenAI insights in rule-based mock mode)"
  type        = string
  default     = ""
}

variable "schedule_expression" {
  description = "Cloud Scheduler cron expression for the batch scoring run, mirroring infra/terraform's EventBridge schedule_expression"
  type        = string
  default     = "*/15 * * * *"
}

variable "labels" {
  type    = map(string)
  default = {}
}
