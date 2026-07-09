# Terraform module — IAM Anomaly Detector (GCP)

Parallel module to `../terraform/` (AWS) — same resources, GCP equivalents,
`google` provider instead of `aws`. Deploying this does **not** modify or
depend on `../terraform/`; the two clouds are independent stacks that both
feed the same provider-agnostic ML pipeline (`models/`, `features/`).

Provisions: every required GCP API (`apis.tf` — these are disabled by
default on a fresh project, unlike AWS's CloudWatch/DynamoDB/Lambda), a
Firestore database, a Cloud Logging sink/bucket for the audit logs
`gcp/cloud_logging_client.py` consumes, a Pub/Sub topic + subscription
matching `streaming/pubsub_backend.py`, a container-image Cloud Run service
running the batch scoring path on a Cloud Scheduler trigger, and a
least-privilege service account.

The only step this module doesn't own is publishing the scoring service's
container image — Terraform can't build or push your application code, the
same way it can't on the AWS side (`infra/terraform/README.md`). Everything
else, including API enablement, is one `terraform apply`.

This is IaC scaffolding, not a `terraform apply`-and-forget black box —
review `variables.tf` and adjust for your project before applying.

## Deploy

```bash
# 1. Build and push the scoring service's container image (same handler
#    pattern as infra/lambda/scorer/, adapted for Cloud Run — see gcp/README.md)
cd ../../                      # project root
gcloud artifacts repositories create iam-anomaly-scorer --repository-format=docker --location=us-central1
docker build -f infra/lambda/scorer/Dockerfile -t us-central1-docker.pkg.dev/<project_id>/iam-anomaly-scorer/scorer:latest .
docker push us-central1-docker.pkg.dev/<project_id>/iam-anomaly-scorer/scorer:latest

# 2. Plan and apply
cd infra/terraform-gcp
terraform init
terraform plan  -var="gcp_project=<project_id>" -var="scorer_image_uri=us-central1-docker.pkg.dev/<project_id>/iam-anomaly-scorer/scorer:latest"
terraform apply -var="gcp_project=<project_id>" -var="scorer_image_uri=us-central1-docker.pkg.dev/<project_id>/iam-anomaly-scorer/scorer:latest"
```

## What it creates

| Resource | AWS equivalent | Purpose |
|---|---|---|
| `google_firestore_database.anomaly_results` | `aws_dynamodb_table.anomaly_results` | Backs `gcp/firestore_store.py` |
| `google_logging_project_sink.audit_logs` | `aws_cloudwatch_log_group.cloudtrail` | Routes audit log entries for `gcp/cloud_logging_client.py` |
| `google_pubsub_topic.iam_events` + `google_pubsub_subscription.iam_events_scorer` | (no AWS equivalent provisioned — Kafka/MSK is BYO cluster) | Backs `streaming/pubsub_backend.py` |
| `google_cloud_run_v2_service.scorer` + `google_cloud_scheduler_job.scorer_schedule` | `aws_lambda_function.scorer` + `aws_cloudwatch_event_rule.scorer_schedule` | Scheduled batch scoring |
| `google_service_account.scorer` | `aws_iam_role.scorer_lambda` | Least-privilege identity: Logging viewer, Firestore user, Pub/Sub subscriber, optional Secret Manager accessor |
| `google_project_service.required` (for_each, 8 APIs) | (no equivalent — AWS needs no enablement step) | Enables Logging, Firestore, Pub/Sub, Cloud Run, Cloud Scheduler, IAM, Secret Manager, and Resource Manager APIs before any dependent resource is created |

## Regional model — read before touching `gcp_regions`

Unlike AWS, Cloud Logging has no per-region API endpoint — it's a single
global, project-scoped service. `gcp_regions` here does **not** pick which
API is called; it only tags the Firestore/Cloud Run location and filters
audit log queries by `resource.labels.location`. See `gcp/README.md` for
the full comparison against `aws_regions` in `../terraform/variables.tf`.

## Validate

```bash
terraform init -backend=false
terraform validate
```

## Known gaps

- The Pub/Sub streaming consumer (`streaming/stream_processor.py` via `STREAM_MODE=pubsub`) is meant to run as a long-lived process (GKE/Cloud Run with no request timeout, or a Compute Engine VM), not the scheduled Cloud Run service above — that one only runs the batch scoring path, same split as the AWS Lambda/streaming-consumer split.
- No VPC Service Controls / private networking included — add if Firestore/Pub/Sub need to be reached from a VPC-only workload.
