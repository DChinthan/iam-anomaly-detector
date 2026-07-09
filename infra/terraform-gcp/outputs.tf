output "scorer_service_url" {
  value = google_cloud_run_v2_service.scorer.uri
}

output "scorer_service_account_email" {
  value = google_service_account.scorer.email
}
