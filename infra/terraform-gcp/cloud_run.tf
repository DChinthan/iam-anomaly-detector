# Scoring Cloud Run service, container-image deployed the same way as the
# AWS Lambda (infra/lambda/scorer/) — TensorFlow + scikit-learn are too
# large for Cloud Functions' deployment package limits, so this uses Cloud
# Run instead, preferred over Cloud Functions for the same reason
# infra/terraform/lambda.tf uses a container-image Lambda over a zip one.
resource "google_cloud_run_v2_service" "scorer" {
  name     = "${local.name_prefix}-scorer"
  project  = var.gcp_project
  location = var.gcp_regions[0]

  template {
    service_account = google_service_account.scorer.email
    timeout         = "120s"

    containers {
      image = var.scorer_image_uri != "" ? var.scorer_image_uri : "gcr.io/cloudrun/placeholder"

      env {
        name  = "FIRESTORE_COLLECTION"
        value = "iam-anomaly-results"
      }
      env {
        name  = "GCP_REGIONS"
        value = join(",", var.gcp_regions)
      }
      env {
        name  = "GCP_MOCK"
        value = "false"
      }
      env {
        name  = "ANTHROPIC_SECRET_ID"
        value = var.anthropic_api_key_secret_id
      }

      resources {
        limits = {
          memory = "1Gi"
          cpu    = "1"
        }
      }
    }
  }

  lifecycle {
    # Terraform shouldn't fight CI/CD over which image tag is deployed —
    # mirrors infra/terraform/lambda.tf's ignore_changes on image_uri.
    ignore_changes = [template[0].containers[0].image]
  }

  depends_on = [google_project_service.required]
}

# Cloud Run services aren't public by default, so Cloud Scheduler needs its
# own invoker identity to call the service on a schedule.
resource "google_service_account" "scheduler_invoker" {
  project      = var.gcp_project
  account_id   = "${local.name_prefix}-scheduler"
  display_name = "Invokes the scoring Cloud Run service on a schedule"

  depends_on = [google_project_service.required]
}

resource "google_cloud_run_v2_service_iam_member" "scheduler_invoker" {
  project  = var.gcp_project
  location = google_cloud_run_v2_service.scorer.location
  name     = google_cloud_run_v2_service.scorer.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler_invoker.email}"
}

# Runs the scoring pipeline on a schedule, independent of the always-on
# Pub/Sub streaming consumer — mirrors infra/terraform/lambda.tf's
# EventBridge-triggered Lambda.
resource "google_cloud_scheduler_job" "scorer_schedule" {
  name     = "${local.name_prefix}-scorer-schedule"
  project  = var.gcp_project
  region   = var.gcp_regions[0]
  schedule = var.schedule_expression

  http_target {
    uri         = google_cloud_run_v2_service.scorer.uri
    http_method = "POST"

    oidc_token {
      service_account_email = google_service_account.scheduler_invoker.email
    }
  }

  depends_on = [google_project_service.required]
}
