# Least-privilege service account for the scoring Cloud Run service —
# equivalent scope to infra/terraform/iam.tf's Lambda execution role:
# Logging viewer, Firestore read/write, Pub/Sub subscriber, optional
# Secret Manager access for the Claude key.
resource "google_service_account" "scorer" {
  project      = var.gcp_project
  account_id   = "${local.name_prefix}-scorer"
  display_name = "IAM Anomaly Detector scoring service"
}

resource "google_project_iam_member" "scorer_logging_viewer" {
  project = var.gcp_project
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.scorer.email}"
}

resource "google_project_iam_member" "scorer_firestore_user" {
  project = var.gcp_project
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.scorer.email}"
}

resource "google_project_iam_member" "scorer_pubsub_subscriber" {
  project = var.gcp_project
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.scorer.email}"
}

resource "google_secret_manager_secret_iam_member" "scorer_secret_access" {
  count     = var.anthropic_api_key_secret_id == "" ? 0 : 1
  project   = var.gcp_project
  secret_id = var.anthropic_api_key_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.scorer.email}"
}
