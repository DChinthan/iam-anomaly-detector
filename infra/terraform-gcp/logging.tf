# Routes the IAM/audit log entries this project consumes (gcp/cloud_logging_client.py)
# into a dedicated log bucket, keeping the anomaly detector's input
# independent of the project's default retention/routing. Mirrors
# infra/terraform/cloudwatch.tf's per-region log groups — but see
# variables.tf's gcp_regions description for why this is one global sink
# rather than one per region: Cloud Logging has no per-region API.
resource "google_logging_project_bucket_config" "audit_logs" {
  project        = var.gcp_project
  location       = var.gcp_regions[0]
  bucket_id      = "${local.name_prefix}-audit-logs"
  retention_days = var.log_retention_days

  depends_on = [google_project_service.required]
}

resource "google_logging_project_sink" "audit_logs" {
  name        = "${local.name_prefix}-audit-sink"
  project     = var.gcp_project
  destination = "logging.googleapis.com/projects/${var.gcp_project}/locations/${var.gcp_regions[0]}/buckets/${google_logging_project_bucket_config.audit_logs.bucket_id}"
  filter      = var.audit_log_filter

  unique_writer_identity = true
}
