# IAM Anomaly Detector

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15-orange)](https://tensorflow.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E)](https://scikit-learn.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32-FF4B4B)](https://streamlit.io)
[![AWS](https://img.shields.io/badge/AWS-CloudWatch%20%7C%20DynamoDB%20%7C%20Lambda-232F3E)](https://aws.amazon.com)
[![GCP](https://img.shields.io/badge/GCP-Cloud%20Logging%20%7C%20Firestore%20%7C%20Cloud%20Run-4285F4)](https://cloud.google.com)
[![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC)](infra/)
[![Tests](https://img.shields.io/badge/tests-40%20passing-brightgreen)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> Documentation snapshot: verified against application code as of commit `b35ba80`. If you're reading this on a later commit, check `git log` — the code may have moved on since these numbers were run.

I built this to flag anomalous IAM/CloudTrail user behavior — stolen credentials, over-privileged accounts, off-hours access — using an unsupervised ML ensemble instead of signature rules, since credential-based attacks use valid auth and don't trip anything signature-based. Claude writes a plain-language incident summary for whatever gets flagged. It runs against AWS or GCP, or fully offline with synthetic data — no cloud account needed to try it.

All three models train only on normal behavior. No labeled attack data required, because in practice you rarely have any.

---

## What's actually shared vs. cloud-specific

This is the part I want to be precise about, because "cloud-portable" gets thrown around loosely. Here's what's actually true, verified by checking imports, not by reading my own docstrings:

**Genuinely shared — zero `aws.*` or `gcp.*` imports, same code regardless of provider:**
`features/extractor.py`, `models/detector.py`, `models/autoencoder.py`, `models/drift.py`, `genai/insights.py`, `genai/cache.py`, `data/db.py`, `streaming/event_stream.py` (branches internally on a `STREAM_MODE` string, not on provider), `streaming/stream_processor.py` (takes its persistence backend as a constructor argument, so it doesn't care which store is injected).

**Cloud-specific adapters — separate files per provider, unified only by matching method signatures (duck typing), not shared code:**
`aws/cloudwatch_client.py` vs. `gcp/cloud_logging_client.py` (ingestion), `aws/dynamodb_store.py` vs. `gcp/firestore_store.py` (persistence), `streaming/pubsub_backend.py` (GCP-only — Kafka isn't cloud-specific so it's handled inline in `event_stream.py`), and the two Terraform modules (`infra/terraform/` vs. `infra/terraform-gcp/`), which are entirely separate and don't share HCL.

**Dashboard cloud-portability — fixed and verified against a real GCP deployment.**
`dashboard/app.py` used to import `DynamoDBStore` directly at module level with no `CLOUD_PROVIDER` awareness at all, and always regenerated a fresh synthetic dataset — it never read real ingested events from either cloud, no matter what that env var was set to. It now routes through the same store-selection logic as `main.py` (`_get_store()`), and has a sidebar toggle, "Use live ingested data," that loads whatever's actually in `data/iam_logs.db` instead of overwriting it with synthetic data every run. See "Live deployment" below for how this was verified against a real GCP project, including a case that still needs care: fitting a fresh ensemble on a single live user isn't meaningful, so live mode loads the already-trained model rather than refitting.

```mermaid
flowchart TD
    subgraph ing["Ingestion — cloud-specific"]
        awsin["aws/cloudwatch_client.py<br/>CloudWatch Logs Insights"]
        gcpin["gcp/cloud_logging_client.py<br/>Cloud Logging"]
        strm["streaming/event_stream.py<br/>Kafka / Pub-Sub / mock — one shared file"]
    end

    subgraph core["Shared core — no cloud imports"]
        db["data/db.py<br/>SQLite / Postgres via SQLAlchemy"]
        feat["features/extractor.py<br/>12 behavioral features"]
        ens["models/detector.py + autoencoder.py<br/>ensemble scoring"]
        drift["models/drift.py<br/>PSI / KS drift check"]
        genai["genai/insights.py + cache.py<br/>Claude incident reports"]
    end

    subgraph store["Persistence — cloud-specific"]
        ddb["aws/dynamodb_store.py"]
        fs["gcp/firestore_store.py"]
    end

    subgraph ui["Dashboard — CLOUD_PROVIDER-aware, live-data toggle"]
        dash["dashboard/app.py<br/>_get_store() routing + 'Use live ingested data' toggle"]
    end

    awsin --> db
    gcpin --> db
    strm --> db
    db --> feat --> ens --> drift --> genai
    genai --> ddb
    genai --> fs
    ddb -.-> dash
    fs -.-> dash
```

`main.py` (the CLI) reads `CLOUD_PROVIDER=aws|gcp` once at startup and picks the matching ingestion client and store — that routing is real and it's what the diagram's cloud-specific boxes feed into. The dashboard now shares the same store-selection logic (see "Live deployment" below).

---

## What it does

- 12 behavioral features per user (off-hours ratio, MFA rate, burst score, suspicious-API ratio, geo deviation, session duration, etc.) — see `features/extractor.py`.
- Three unsupervised models scored as a weighted ensemble: Isolation Forest (40%), One-Class SVM (30%), a small TensorFlow autoencoder (30%). Trained only on normal data.
- A second confidence signal: the autoencoder's own 95th-percentile reconstruction-error threshold is checked independently of the 0.65 ensemble cutoff. If both agree, the user is marked `CONFIRMED`; if only the ensemble crosses threshold, it's `SUSPECTED`. This tells you which flags are worth looking at first without re-deriving it from the raw scores yourself.
- PSI + Kolmogorov-Smirnov drift check against a saved training-time baseline, so a model that's quietly gone stale shows up as a number instead of nothing.
- Claude writes a short incident summary (attack pattern, key signals, one-line recommendation) for each flagged user, with a rule-based fallback if no API key is set — the pipeline runs the same either way. Responses are cached by `(user_id, score bucket)` so re-running the dashboard doesn't re-call the API for a user whose score hasn't moved.
- Streaming path (Kafka / GCP Pub/Sub / in-memory) that rescoring incrementally as events arrive, alongside the batch path. See the Limitations section below for the real tradeoff this introduces.
- Dashboard login gated by three roles (admin/analyst/viewer); the dashboard is now `CLOUD_PROVIDER`-aware with a live-data toggle — see "Live deployment" below.
- Two Terraform modules, one per cloud. Both pass `terraform validate`; the GCP module has additionally been `terraform apply`'d to a real project (see "Live deployment" below). The AWS module has not yet been applied (also covered in Limitations).

---

## Behavioral Features

| Feature | Description | Signal it's meant to catch |
|---|---|---|
| `total_api_calls` | Calls per day over the window | Automated credential abuse |
| `avg_session_duration` / `max_session_duration` | Time between first and last call per session | Persistent unauthorized sessions |
| `geo_deviation_score` | Unique /24 subnets used | Lateral movement / IP hopping |
| `suspicious_api_ratio` | % calls to a fixed list of privilege-escalation APIs | CreateAccessKey, GetSecretValue, DeleteTrail (AWS action names — see Limitations for the GCP caveat) |
| `off_hours_ratio` | % activity between 10pm–6am | Compromised creds used outside business hours |
| `mfa_usage_rate` | MFA present on API calls | Stolen long-lived access keys |
| `burst_score` | Max calls in any 30-min window | Automated credential harvesting |
| `error_rate` | % calls returning AccessDenied | Probing for permissions |
| `unique_ips` / `unique_regions` | Distinct source IPs / regions | Credential sharing, unusual footprint |
| `weekend_ratio` | % activity on Sat/Sun | Atypical access schedule |

---

## Quickstart

```bash
pip install -r requirements.txt
python main.py pipeline          # generate synthetic data -> train -> score -> insights
streamlit run dashboard/app.py   # dashboard, always synthetic AWS-mode data (see caveat above)
```

Copy `.env.example` to `.env` for every configuration option. Everything above runs with no cloud credentials.

### Real-world data: LANL dataset — schema-compatible, not benchmarked

The [LANL Comprehensive Multi-Source Cybersecurity Events dataset](https://csr.lanl.gov/data/cyber1/) has real de-identified auth logs from Los Alamos National Lab. `data/lanl_adapter.py` maps its format to this project's event schema and runs it through the same pipeline.

Be clear about what this does and doesn't prove: the adapter ingests LANL's raw `auth.txt.gz` events, but it does **not** ingest LANL's companion `redteam.txt.gz` file — the ground-truth list of actually-compromised logins that dataset ships specifically for validating detectors. Every row currently gets `is_anomaly=0` by default. So running this dataset through the pipeline demonstrates the schema mapping works on real, messy, real-world-shaped data — it does not give you a precision/recall number against real attacks. If you want that, wiring up the redteam labels is the next step, and I haven't done it yet.

```bash
python main.py lanl data/auth.txt.gz 500000
python main.py train
python main.py score
```

### Multi-cloud (CLI only — see the dashboard caveat above)

```bash
export CLOUD_PROVIDER=aws   # or: gcp
export AWS_MOCK=false
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# or for GCP: GCP_MOCK=false, GCP_PROJECT=..., see gcp/README.md

python main.py ingest
python main.py train
python main.py score
```

Streaming and drift check:

```bash
python main.py stream-demo 200      # mock mode, no infra
python main.py drift                # PSI/KS report vs. training baseline
```

Postgres instead of local SQLite (RDS, Aurora, or Cloud SQL — same code path):

```bash
DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/iam_anomaly python main.py pipeline
```

---

## Project Structure

```
iam-anomaly-detector/
├── data/                 # log_generator.py, lanl_adapter.py, db.py (SQLite/Postgres)
├── features/extractor.py # 12 behavioral features — shared, no cloud imports
├── models/               # detector.py, autoencoder.py, drift.py — shared, no cloud imports
├── genai/                # insights.py, cache.py — shared, no cloud imports
├── aws/                  # cloudwatch_client.py, dynamodb_store.py — AWS-specific
├── gcp/                  # cloud_logging_client.py, firestore_store.py — GCP-specific
├── streaming/            # event_stream.py (shared), pubsub_backend.py (GCP), stream_processor.py (shared)
├── dashboard/            # app.py (AWS-only, see caveat), auth.py (role-based login)
├── infra/                # terraform/ (AWS), terraform-gcp/ (GCP), lambda/scorer/ (Lambda handler)
├── tests/                # 40 tests
├── main.py               # CLI, CLOUD_PROVIDER-aware routing
└── requirements.txt
```

---

## ML Model Details

**Isolation Forest** — 300 estimators, contamination 0.05. Tree-based, isolates anomalies by random partitioning.

**One-Class SVM** — RBF kernel, `nu` reuses the same 0.05 contamination value. Hypersphere around normal behavior in kernel space.

**TensorFlow Autoencoder** — Dense 12→8→4→8→12, trained to minimize reconstruction MSE. `anomaly_score = MSE(input, reconstruction)`, normalized to [0, 1]. Its 95th-percentile training-error threshold backs the confidence tier.

**Ensemble** — `0.40*IF + 0.30*SVM + 0.30*AE`, flagged above 0.65. Confirmed when the AE's own threshold agrees, suspected when only the ensemble crosses.

None of these numbers — the 40/30/30 weights, the 0.65 threshold, `n_estimators=300`, `contamination=0.05`, `latent_dim=4`, `epochs=80` — have been tuned against labeled data. They're reasonable starting defaults, not the output of a grid search or cross-validation. See Limitations.

**Model drift** — PSI + Kolmogorov-Smirnov per feature against a training-time baseline snapshotted on every `fit()`. `python main.py drift`. Warn above PSI 0.10, alert above 0.25.

---

## Results — proof of concept, not a validated benchmark

```
Users: 55 (50 normal + 5 synthetically injected anomalous)
Log events: ~75,000-90,000 over 30 days (varies per run — not seeded)
TPR: 100%   FPR: 0%   (most recent run; verified fresh, not a historical figure)
```

Read that correctly: this is one run against synthetic data with injected, labeled anomaly patterns (off-hours access from suspicious IPs, privilege-escalation API bursts, missing MFA, credential-harvesting bursts). Injected anomalies are cleaner and more separable than real attacker behavior that's actively trying to blend in. This number tells you the ensemble can separate an obvious synthetic signal from normal behavior — it is not a claim about real-world detection accuracy, because there's no real-world ground truth run yet (see the LANL section above).

Reproduce it:

```bash
rm -f data/iam_logs.db && python main.py pipeline
```

Expect the exact event count and TPR/FPR to vary slightly between runs since the log generator doesn't use a fixed random seed for daily call volume.

Automated tests: `terraform validate` passes on both IaC modules (Success, checked directly, not from memory).

---

## Live deployment — applied to real AWS and GCP accounts, not just `terraform validate`

Both cloud modules have now been genuinely `terraform apply`'d against real accounts, exercised end-to-end, and torn down. Between the two, this surfaced **9 real, previously-undiscovered bugs** — none of which `terraform validate` or a code read could have caught, because they only show up when real cloud APIs, real IAM permissions, and real container runtimes are actually involved. That's the concrete case for why "applied," not just "validated," matters. GCP first, then AWS.

### GCP

Everything above describes the code. This section is what happened when `infra/terraform-gcp/` was actually `terraform apply`'d against a real (free-trial) GCP project, rather than just validated.

**What got created.** 21 resources: Firestore (Native mode), a Pub/Sub topic + subscription, a Cloud Logging sink into a dedicated bucket, a Cloud Run service, a Cloud Scheduler job invoking it every 15 minutes, 2 least-privilege service accounts, and their IAM bindings. All within GCP's free tier/trial credit at this scale.

**A real bug this surfaced.** `terraform plan` failed on the first attempt: GCP caps `google_service_account.account_id` at 30 characters, and `${project_name}-${environment}-scheduler` is 34. This had never been caught before because the module had only ever been `terraform validate`'d, never applied. Fixed in `infra/terraform-gcp/main.tf` (added a truncated `sa_prefix` local), `iam.tf`, and `cloud_run.tf`.

**Real ingest → real score → real Firestore write, verified end to end:**
```bash
export CLOUD_PROVIDER=gcp GCP_MOCK=false GCP_PROJECT=<project-id>
python main.py ingest   # pulled 2 real Cloud Audit Log events from live Cloud Logging
python main.py score    # scored against the already-trained ensemble, wrote the result to live Firestore
```
Result: the real account behind those 2 API calls got flagged (`ensemble_score=0.70`, `off_hours_ratio=1.0`, `burst_score=2.0`), and the scored result was confirmed sitting in the live Firestore `iam-anomaly-results` collection via the GCP Console — not the mock JSON file.

**Read that flag correctly.** This isn't "the model caught a real attacker." It's one real user's small, midnight session compared against an ensemble whose "normal" baseline came from a synthetic 30-day, many-call-per-day population — so it reads as statistically out-of-distribution and gets flagged. That's the unsupervised model doing exactly what it's supposed to when applied to real activity that looks nothing like its training data. What this proves is that the pipeline genuinely works end-to-end against a live cloud account and a live database; it is not a validated detection result — that claim still rests solely on the synthetic benchmark above, same caveat as always.

**The dashboard fix this drove.** `dashboard/app.py` previously hardcoded `DynamoDBStore` and always regenerated synthetic data regardless of `CLOUD_PROVIDER` (see the "Dashboard cloud-portability" note above). It now shares `main.py`'s store-selection logic and has a sidebar toggle, "Use live ingested data," to load whatever's actually in `data/iam_logs.db`. One more fix came out of testing this against the 1-user real dataset: fitting a fresh ensemble on a single sample crashes (`ValueError` from Keras's validation split), so live mode loads the already-trained model via `AnomalyDetector.load()` instead of refitting — mirroring what `main.py score` already did. Synthetic demo mode is unaffected and still fits fresh every run.

**What's still not deployed for real.** The Cloud Run service is running Google's placeholder container image (`gcr.io/cloudrun/placeholder`), not the actual scorer — `infra/lambda/scorer/handler.py` is Lambda-shaped and still needs an HTTP-server adapter before it can run on Cloud Run (pre-existing gap, see Limitations). The Cloud Scheduler job does successfully invoke it every 15 minutes (`Status: Success` in the console) — that's it responding 200 to being pinged, not real scoring logic executing.

**Console evidence.** Screenshots taken directly from the GCP Console for the project this was applied to, same day as the `terraform apply` above:

| | |
|---|---|
| ![Firestore document showing the real scored result](docs/screenshots/07-gcp-firestore-live-document.png) | **Firestore** — the real `chinthandp@gmail.com` document in `iam-anomaly-results`, written by `python main.py score`, not the mock JSON file. `ensemble_score: "0.7"`, `flagged: true`. |
| ![Cloud Logging showing real audit log entries](docs/screenshots/08-gcp-cloud-logging-real-audit-events.png) | **Cloud Logging** — real `cloudaudit.googleapis.com` entries from the live project (Cloud Run deploys, IAM policy changes, Scheduler jobs), the actual source `main.py ingest` reads from. |
| ![Cloud Run service detail page](docs/screenshots/09-gcp-cloud-run-service.png) | **Cloud Run** — `iam-anomaly-detector-dev-scorer`, deployed and serving (running the placeholder image, per the caveat above). |
| ![Pub/Sub subscription detail page](docs/screenshots/10-gcp-pubsub-subscription.png) | **Pub/Sub** — `iam-anomaly-scorer-sub`, subscribed to `iam-cloudtrail-events`. |
| ![Cloud Scheduler job with a successful last run](docs/screenshots/11-gcp-cloud-scheduler-job.png) | **Cloud Scheduler** — the 15-minute job, `Status: Success` on its last invocation. |

**Dashboard, for reference.** The screenshots below are the fixed dashboard (`dashboard/app.py`) running — but they're showing **synthetic demo mode**, not the live-data toggle (the numbers, 84,257 events / 55 users / 100% TPR, match the synthetic benchmark above, not the 2-event real dataset). Captured this way deliberately rather than mislabeling a demo-mode screenshot as live: the live-data path is verified instead through the CLI trace and Firestore screenshot above, which unambiguously show the real 1-user result.

| | |
|---|---|
| ![Dashboard sign-in screen](docs/screenshots/01-dashboard-login.png) | Role-gated sign-in (`dashboard/auth.py`). |
| ![Dashboard overview metrics and GenAI alerts](docs/screenshots/02-dashboard-overview-metrics.png) | Overview metrics + Claude-generated GenAI security alerts for flagged users. |
| ![Anomaly score distribution and flagged users table](docs/screenshots/03-dashboard-score-distribution.png) | Ensemble score distribution vs. the 0.65 threshold, and the flagged-users table. |
| ![Model comparison scatterplots](docs/screenshots/04-dashboard-model-comparison.png) | Isolation Forest vs. One-Class SVM, and ensemble score vs. autoencoder reconstruction error. |
| ![Feature heatmap for top-scoring users](docs/screenshots/05-dashboard-feature-heatmap.png) | Per-feature heatmap for the top 20 users by anomaly score. |
| ![API call volume over time](docs/screenshots/06-dashboard-api-call-volume.png) | Daily API call volume, normal vs. anomalous users. |

### AWS

`infra/terraform/` was applied against a real AWS account (IAM user `Terraform`), including building and pushing a real Lambda container image to ECR — unlike GCP's Cloud Run, which only ever ran a placeholder image, this Lambda runs the project's actual scorer code.

**What got created:** DynamoDB table + GSI, a CloudWatch log group per region, the Lambda function (container image) + its execution role/policy, an EventBridge 15-minute schedule, and a Lambda-error CloudWatch alarm.

**8 real bugs found and fixed, only surfaced by actually building, deploying, and invoking this for real:**

1. **Unpinned ML dependencies broke the container build.** `requirements.txt`'s open-ended lower bounds (`scikit-learn>=1.4.0`, no upper cap) resolved to versions with no prebuilt wheel for the Lambda base image, forcing a from-source `numpy` build that failed — the image has no C compiler. Fixed by forcing `pip install --only-binary=:all:` in `infra/lambda/scorer/Dockerfile`.
2. **Docker's provenance attestation broke Lambda deployment.** Modern Buildx attaches a provenance/SBOM manifest by default, turning the pushed image into an OCI manifest list — which Lambda's container support explicitly rejects (`"image manifest ... media type ... not supported"`). Fixed with `docker build --provenance=false`.
3. **CloudWatch log group naming mismatch.** `aws/cloudwatch_client.py` queried the unsuffixed `/aws/cloudtrail/events`, but Terraform's `cloudwatch.tf` creates one log group per region with a `-{region}` suffix — that unsuffixed name never existed. Fixed to match Terraform's naming.
4. **DynamoDB GSI type mismatch — the exact bug this README already predicted, now confirmed live.** `infra/terraform/dynamodb.tf` types the `flagged` GSI key as String (DynamoDB doesn't allow `BOOL` as a key-schema type at all), but `aws/dynamodb_store.py` wrote it as a native Python `bool`, so every real write failed validation. Fixed by stringifying `flagged` on the write and read-filter paths in `aws/dynamodb_store.py`.
5. **Explicit boto3 credentials broke Lambda's STS auth.** Both AWS client constructors passed `aws_access_key_id`/`aws_secret_access_key` from env vars but never `aws_session_token` — harmless with long-lived IAM user keys, but Lambda's execution role only ever hands out temporary STS credentials, which are rejected without their session token. Fixed by dropping the explicit credential kwargs entirely and letting boto3's default credential chain resolve them (correct in both environments).
6. **Single un-aliased AWS provider silently broke "multi-region."** `infra/terraform/main.tf` has one `aws` provider pinned to `var.aws_regions[0]` with no per-region provider aliasing — so the log group *named* `...-us-west-2` was actually physically created in `us-east-1`. Real proof: the Lambda's IAM policy, once generated, only ever granted permissions on `us-east-1`-region ARNs regardless of the resource's name. Workaround applied: scoped `aws_regions` to `["us-east-1"]` only rather than building out full provider aliasing for a dev-scale test — documented as a real gap, not silently patched over.
7. **`extract_features()` crashed on zero ingested events.** With no CloudTrail trail wired up (see below), a real ingest legitimately returns 0 rows — and `groupby("user_id")` on an empty frame produced a DataFrame with *no columns at all*, breaking every downstream consumer with a `KeyError`. Fixed in `features/extractor.py` to return the correct empty schema.
8. **`AnomalyDetector.score()` crashed on zero rows regardless of the previous fix.** Even with the right columns, scikit-learn's `StandardScaler.transform()` hard-rejects a 0-sample array. Fixed with an early-return guard in `models/detector.py` that reports "nothing to score" instead of calling into sklearn at all — this is a genuine production robustness fix, not just a demo convenience, since an idle 24-hour window with zero new activity is a completely realistic scenario.

**A real, separate gap, not fixed (documented instead):** this Terraform module creates CloudWatch log groups but never provisions an actual `aws_cloudtrail` trail to deliver events into them — unlike GCP, where every project has an always-on Cloud Audit Log with zero extra setup. So a real `ingest` against this AWS deployment correctly connects and correctly returns 0 events; there's nothing to receive real IAM activity yet.

**Real writes, real invocation, verified:**
```bash
export CLOUD_PROVIDER=aws AWS_MOCK=false AWS_REGIONS=us-east-1 DYNAMODB_TABLE=iam-anomaly-detector-dev-results
python3 main.py score   # 55 users scored, 5 flagged, persisted to real DynamoDB
aws lambda invoke --function-name iam-anomaly-detector-dev-scorer --region us-east-1 /tmp/out.json
# {"usersScored": 0, "usersFlagged": 0, "flaggedUserIds": []} — correct, given no CloudTrail data
```

**Console evidence:**

| | |
|---|---|
| ![DynamoDB scan configuration](docs/screenshots/13-aws-dynamodb-scan-setup.png) | **DynamoDB** — real table `iam-anomaly-detector-dev-results`. |
| ![DynamoDB flagged-index scan results](docs/screenshots/14-aws-dynamodb-flagged-index.png) | The `flagged-index` GSI returning real results — proof the String-type fix actually works against the live table. |
| ![Lambda function overview](docs/screenshots/15-aws-lambda-function-overview.png) | **Lambda** — `iam-anomaly-detector-dev-scorer`, deployed from the real ECR image, wired to its EventBridge trigger. |
| ![Lambda service dashboard](docs/screenshots/16-aws-lambda-dashboard.png) | Real invocation/error/concurrency graphs from the debugging + successful-invoke cycle. |
| ![Lambda monitor tab graphs](docs/screenshots/17-aws-lambda-monitor-graphs.png) | Error count vs. success rate, duration, and throttle metrics for real invocations. |
| ![CloudWatch cross-service Lambda view](docs/screenshots/18-aws-cloudwatch-lambda.png) | Same function's metrics from CloudWatch's own Lambda view — 23 real invocations logged during this session. |
| ![ECR repository image history](docs/screenshots/19-aws-ecr-images.png) | **ECR** — the real pushed image history, one entry per rebuild cycle during the bug-fixing loop above. |
| ![CLI output showing 55 scored users, 5 flagged](docs/screenshots/12-aws-cli-flagged-users.png) | The `python3 main.py score` run that produced the DynamoDB write above. |

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML models | scikit-learn (IsolationForest, OneClassSVM), TensorFlow/Keras |
| GenAI | Anthropic Claude API |
| Feature engineering | pandas, numpy, scipy |
| Relational storage | SQLite (dev), Postgres — RDS/Aurora or Cloud SQL (prod), via SQLAlchemy |
| NoSQL storage | AWS DynamoDB, GCP Firestore |
| Log ingestion | AWS CloudWatch Logs Insights, GCP Cloud Logging |
| Event streaming | Kafka (confluent-kafka), GCP Pub/Sub |
| Infrastructure as Code | Terraform (AWS + Google providers), Docker |
| Dashboard | Streamlit, Plotly |
| Testing | pytest |

---

## Testing

```bash
python -m pytest tests/ -q
```

40 tests, 6 files, verified passing at the commit noted at the top of this file:

| File | Tests | Covers |
|---|---|---|
| `test_feature_extractor.py` | 15 | Per-feature correctness |
| `test_detector.py` | 6 | Ensemble fit/score/save/load, confidence tiering |
| `test_log_generator.py` | 6 | Schema, anomaly injection, timestamp validity |
| `test_dynamodb_store.py` | 5 | AWS mock-mode CRUD |
| `test_firestore_store.py` | 5 | GCP mock-mode CRUD |
| `test_pubsub_backend.py` | 3 | Streaming round-trip (mocked), lazy-import safety |

Every backend has a mock mode, so none of this needs cloud credentials.

---

## Limitations / Known Gaps / What I'd Improve Next

These are real, specific things I found by checking the code, not a generic disclaimer paragraph:

1. ~~**Dashboard isn't cloud-portable.**~~ **Fixed.** `dashboard/app.py` now routes through the same `_get_store()` pattern as `main.py`, and a sidebar toggle ("Use live ingested data") loads real ingested events instead of always regenerating synthetic data. Verified against a real GCP deployment — see "Live deployment" above. Remaining caveat: live mode reuses the already-trained model rather than refitting, since refitting on a very small live sample can crash (see that section for why).
2. **Dashboard auth isn't backed by a real identity provider.** `dashboard/auth.py` is a `DASHBOARD_USERS` env var, SHA-256 hashed, checked in-process. Fine for local dev, not something you'd point real users at. Cognito is scaffolded in `infra/terraform/cognito.tf` but nothing wires the dashboard to it.
3. **GCP Cloud Run scoring service has no real entrypoint.** `infra/terraform-gcp/cloud_run.tf` references a container image, but the only application code that exists (`infra/lambda/scorer/handler.py`) is a Lambda-style `handler(event, context)` function that assumes `/var/task` — it would not run correctly as a Cloud Run service, which needs an HTTP server listening on `$PORT`. That adapter doesn't exist yet.
4. ~~**DynamoDB GSI type mismatch.**~~ **Fixed and confirmed live.** `infra/terraform/dynamodb.tf` types the `flagged` GSI key as a String, but `aws/dynamodb_store.py` was writing it as a native Python bool via boto3 — this was predicted here before ever being tested, and the first real write against the live table hit exactly this error. Fixed by stringifying `flagged` on write/read. See "Live deployment" above.
5. ~~**`terraform validate` is not `terraform apply`.**~~ **Resolved for both clouds.** Both modules have now been applied against real accounts and exercised end-to-end (see "Live deployment" above) — GCP surfaced a service-account character-limit bug, AWS surfaced 8 separate bugs including this file's #4. Both environments were subsequently torn down.
6. **No real-world validated detection rate.** The only benchmark is the synthetic proof-of-concept above. The LANL adapter proves schema compatibility, not detection accuracy, since the ground-truth redteam labels aren't wired in (see above).
7. **Hyperparameters are defaults, not tuned.** Ensemble weights, the 0.65 threshold, Isolation Forest's `n_estimators`/`contamination`, the autoencoder's `latent_dim`/`epochs` — none of these came from cross-validation or a grid search against labeled data.
8. **GenAI caching reduces redundant calls, it doesn't cap spend.** `genai/cache.py` skips a repeat Claude call for a user whose score hasn't moved, but there's no hard rate limit or budget ceiling — a caller that hammers `analyze_batch` on genuinely new data would still hit the API at whatever pace it's called.
9. **`suspicious_api_ratio` is AWS-shaped.** The suspicious-API list is a fixed set of AWS action names (`CreateAccessKey`, `AttachUserPolicy`, etc.). On GCP-sourced data this feature reads near zero even for genuinely suspicious activity, since GCP method names look completely different. The other 11 features are schema-based and work the same regardless of source.
10. **Streaming trades accuracy for latency.** Incremental rescoring uses small rolling windows (20 events) that produce noisier features — especially burst score — than the 30-day batch baseline, so the streaming path over-flags relative to batch. This is a real tradeoff, not a bug to be fixed for free.
11. **No CI pipeline in this repo.** Tests and `terraform validate` are run manually. There's no `.github/workflows` gating a PR on either.
12. **AWS Terraform module creates log groups but never provisions a CloudTrail trail.** `infra/terraform/cloudwatch.tf` creates the CloudWatch log groups `main.py ingest` reads from, but nothing in this module creates an `aws_cloudtrail` resource to actually deliver IAM/API activity into them — unlike GCP, which has an always-on Cloud Audit Log with zero extra setup. Found by applying this for real: `ingest` correctly connects to a real, empty log group and correctly returns 0 events, rather than the crash a naming bug would cause.
13. **AWS Terraform module isn't genuinely multi-region.** `infra/terraform/main.tf` declares a single `aws` provider pinned to `var.aws_regions[0]`, with no per-region provider aliasing. Resources named with a `-us-west-2` suffix (log groups, IAM policy ARNs) are still physically created in `us-east-1` — the name string doesn't control the region, the provider connection does. Confirmed live: `us-west-2` queries returned `ResourceNotFoundException` locally and `AccessDeniedException` from the Lambda's more restrictive IAM policy, both consistent with the resource never actually existing outside `us-east-1`. Real fix would mean adding aliased provider blocks per region; worked around for testing by scoping `aws_regions` to `["us-east-1"]` only.

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Chinthan Dinesh](https://github.com/DChinthan) · [github.com/DChinthan/iam-anomaly-detector](https://github.com/DChinthan/iam-anomaly-detector)
