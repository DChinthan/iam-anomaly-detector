# Enables every GCP API this module's resources depend on. Unlike AWS,
# where CloudWatch/DynamoDB/Lambda need no equivalent step, GCP APIs are
# disabled by default on a fresh project — terraform apply fails on
# google_firestore_database, google_pubsub_topic, etc. until their APIs
# are turned on. Resources that need a given API declare an explicit
# depends_on below, since Terraform can't infer that dependency the way
# it infers dependencies between two resources referencing each other.
locals {
  required_apis = [
    "logging.googleapis.com",
    "firestore.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "cloudscheduler.googleapis.com",
    "iam.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ]
}

resource "google_project_service" "required" {
  for_each = toset(local.required_apis)
  project  = var.gcp_project
  service  = each.value

  disable_dependent_services = false
  disable_on_destroy         = false
}
