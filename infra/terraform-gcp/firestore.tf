# Mirrors gcp/firestore_store.py: document ID user_id, queryable
# analysis_timestamp field. Firestore in Native mode is project-wide —
# there's no separate "table" resource to create beyond the database
# itself; the collection (default: iam-anomaly-results, see
# FIRESTORE_COLLECTION) is created implicitly on first write.
resource "google_firestore_database" "anomaly_results" {
  project     = var.gcp_project
  name        = "(default)"
  location_id = var.gcp_regions[0]
  type        = "FIRESTORE_NATIVE"
}

output "firestore_database_name" {
  value = google_firestore_database.anomaly_results.name
}
