# GCP backend

Parallel to `aws/` — same public interfaces, same event schema, GCP
services underneath. Deploying/using this does not require the AWS side at
all; `CLOUD_PROVIDER=gcp` routes `main.py`'s ingest/score/stream commands
here instead. See `../infra/terraform-gcp/` for the matching IaC module
(parallel to `../infra/terraform/`, which stays AWS-only).

| File | AWS equivalent | Role |
|---|---|---|
| `cloud_logging_client.py` | `aws/cloudwatch_client.py` | Pulls IAM/audit events, normalizes into the 9-column schema `features/extractor.py` expects |
| `firestore_store.py` | `aws/dynamodb_store.py` | Persists scored results — same `put_result`/`get_result`/`get_flagged`/`bulk_put` interface |
| `../streaming/pubsub_backend.py` | (Kafka, BYO cluster) | Third `STREAM_MODE` backend for `../streaming/event_stream.py` |

## Run everything in mock mode — zero GCP account, zero billing

Mock mode is the default (`GCP_MOCK=true`), exactly like `AWS_MOCK=true`:

```bash
CLOUD_PROVIDER=gcp python main.py ingest   # synthetic Cloud Audit Log-shaped events -> SQLite
CLOUD_PROVIDER=gcp python main.py score    # scores + persists to data/firestore_mock.json
CLOUD_PROVIDER=gcp python main.py stream   # STREAM_MODE still defaults to "mock" independently — combine below if you want Pub/Sub too
```

`CLOUD_PROVIDER` (ingestion + storage) and `STREAM_MODE` (event bus) are
independent toggles — you can run `CLOUD_PROVIDER=gcp` with
`STREAM_MODE=mock` (no Pub/Sub needed), or AWS ingestion with
`STREAM_MODE=pubsub`, etc. Nothing here requires real GCP credentials
unless you also set `GCP_MOCK=false` or `STREAM_MODE=pubsub` without
`PUBSUB_EMULATOR_HOST`.

### Pub/Sub without a GCP project — the local emulator

```bash
gcloud beta emulators pubsub start --project=iam-anomaly-detector
$(gcloud beta emulators pubsub env-init)   # exports PUBSUB_EMULATOR_HOST

STREAM_MODE=pubsub python main.py stream-simulate 100   # separate terminal
STREAM_MODE=pubsub python main.py stream
```
`google-cloud-pubsub` automatically talks to the emulator instead of the
real service when `PUBSUB_EMULATOR_HOST` is set — `streaming/pubsub_backend.py`
has no separate emulator/real code path because of this.

## Real mode setup

1. `gcloud auth application-default login` (or a service account key — see
   `../infra/terraform-gcp/iam.tf` for the minimum role set to grant it):
   - `roles/logging.viewer` — read Cloud Audit Log entries
   - `roles/datastore.user` — read/write Firestore
   - `roles/pubsub.subscriber` — consume the streaming topic
   - `roles/secretmanager.secretAccessor` — only if `ANTHROPIC_API_KEY` is stored in Secret Manager
2. Set `GCP_PROJECT`, `GCP_MOCK=false`, and (optionally) `GCP_REGIONS`.
3. Deploy the supporting infra with `../infra/terraform-gcp/` (Firestore database, Cloud Logging sink, Pub/Sub topic/subscription, scoring Cloud Run service — **the Cloud Run service has no working entrypoint yet**, see `../infra/terraform-gcp/README.md`'s Deploy section before relying on it).

## The Cloud Logging "region" caveat — read this before assuming AWS parity

`aws/cloudwatch_client.py`'s `AWS_REGIONS` loop calls a **different regional
API endpoint** per region (`boto3.client("logs", region_name=...)`) — that's
a real per-region connection.

Cloud Logging has no such thing: `google.cloud.logging.Client` is a single
global, project-scoped client. There's no `region_name` parameter. So
`GCP_REGIONS` in `cloud_logging_client.py` does **not** pick a connection
target — every "region" in the list is queried through the same client,
with the region only used to (a) filter the query by
`resource.labels.location` and (b) tag the normalized events' `region`
field, so the `unique_regions` feature still behaves sensibly on GCP-sourced
data. This is the accurate mapping, not a shortcut — Cloud Logging audit
trails are inherently project-wide (or org/folder-wide with an aggregated
sink), not region-partitioned, even though the *resources* being audited
(Compute instances, GKE clusters) are regional.

## Another honest caveat — `suspicious_api_ratio` on GCP data

`features/extractor.py`'s `SUSPICIOUS_APIS` set is a fixed list of AWS
action names (`CreateAccessKey`, `AttachUserPolicy`, etc.). GCP method
names look different (`google.iam.admin.v1.CreateServiceAccountKey`,
`SetIamPolicy`). Since the task scope keeps `features/extractor.py`
provider-agnostic and untouched, `suspicious_api_ratio` will read as ~0 for
GCP-sourced traffic even when genuinely suspicious IAM methods are present.
The other 11 features (off-hours ratio, burst score, MFA rate, geo
deviation, etc.) are computed from schema fields, not API name string
matching, so they work identically regardless of source. Extending
`SUSPICIOUS_APIS` to include GCP method names is a natural next step, but
is a change to shared ML code and was intentionally left out of this
provider-parity pass.

## Tests

`../tests/test_firestore_store.py` and `../tests/test_pubsub_backend.py`
run entirely in mock mode — no GCP credentials, project, or emulator
required.
