# Matches streaming/pubsub_backend.py's PUBSUB_TOPIC / PUBSUB_SUBSCRIPTION
# defaults exactly, so the deployed infra needs no env var overrides.
resource "google_pubsub_topic" "iam_events" {
  project = var.gcp_project
  name    = "iam-cloudtrail-events"
  labels  = local.common_labels
}

resource "google_pubsub_subscription" "iam_events_scorer" {
  project = var.gcp_project
  name    = "iam-anomaly-scorer-sub"
  topic   = google_pubsub_topic.iam_events.name

  ack_deadline_seconds       = 30
  message_retention_duration = "86400s"

  expiration_policy {
    ttl = "" # never expires
  }

  labels = local.common_labels
}

output "pubsub_topic" {
  value = google_pubsub_topic.iam_events.name
}

output "pubsub_subscription" {
  value = google_pubsub_subscription.iam_events_scorer.name
}
