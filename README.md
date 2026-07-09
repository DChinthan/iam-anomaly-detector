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

**Where this breaks down — the dashboard is not cloud-portable today:**
`dashboard/app.py` imports `DynamoDBStore` directly at module level and has no `CLOUD_PROVIDER` awareness at all. Whatever you set that env var to, the dashboard always talks to DynamoDB and always regenerates its own synthetic dataset — it never reads real ingested events from either cloud. The CLI (`main.py`) genuinely routes between AWS and GCP; the dashboard doesn't yet. I'm noting this here instead of letting the architecture diagram imply otherwise.

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

    subgraph ui["Dashboard — AWS-only, not yet cloud-portable"]
        dash["dashboard/app.py<br/>hardcoded DynamoDBStore, ignores CLOUD_PROVIDER"]
    end

    awsin --> db
    gcpin --> db
    strm --> db
    db --> feat --> ens --> drift --> genai
    genai --> ddb
    genai --> fs
    ddb -.-> dash
```

`main.py` (the CLI) reads `CLOUD_PROVIDER=aws|gcp` once at startup and picks the matching ingestion client and store — that routing is real and it's what the diagram's cloud-specific boxes feed into. The dashboard sits outside that routing.

---

## What it does

- 12 behavioral features per user (off-hours ratio, MFA rate, burst score, suspicious-API ratio, geo deviation, session duration, etc.) — see `features/extractor.py`.
- Three unsupervised models scored as a weighted ensemble: Isolation Forest (40%), One-Class SVM (30%), a small TensorFlow autoencoder (30%). Trained only on normal data.
- A second confidence signal: the autoencoder's own 95th-percentile reconstruction-error threshold is checked independently of the 0.65 ensemble cutoff. If both agree, the user is marked `CONFIRMED`; if only the ensemble crosses threshold, it's `SUSPECTED`. This tells you which flags are worth looking at first without re-deriving it from the raw scores yourself.
- PSI + Kolmogorov-Smirnov drift check against a saved training-time baseline, so a model that's quietly gone stale shows up as a number instead of nothing.
- Claude writes a short incident summary (attack pattern, key signals, one-line recommendation) for each flagged user, with a rule-based fallback if no API key is set — the pipeline runs the same either way. Responses are cached by `(user_id, score bucket)` so re-running the dashboard doesn't re-call the API for a user whose score hasn't moved.
- Streaming path (Kafka / GCP Pub/Sub / in-memory) that rescoring incrementally as events arrive, alongside the batch path. See the Limitations section below for the real tradeoff this introduces.
- Dashboard login gated by three roles (admin/analyst/viewer) — see the cloud-portability caveat above for what this dashboard does and doesn't do.
- Two Terraform modules, one per cloud, both pass `terraform validate` — neither has been applied to a real account (also covered in Limitations).

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

1. **Dashboard isn't cloud-portable.** `dashboard/app.py` hardcodes `DynamoDBStore` and ignores `CLOUD_PROVIDER` entirely — it always writes to DynamoDB and always uses freshly generated synthetic data, never real ingested events from either cloud. Fixing this means threading the same store-injection pattern `StreamProcessor` already uses into the dashboard.
2. **Dashboard auth isn't backed by a real identity provider.** `dashboard/auth.py` is a `DASHBOARD_USERS` env var, SHA-256 hashed, checked in-process. Fine for local dev, not something you'd point real users at. Cognito is scaffolded in `infra/terraform/cognito.tf` but nothing wires the dashboard to it.
3. **GCP Cloud Run scoring service has no real entrypoint.** `infra/terraform-gcp/cloud_run.tf` references a container image, but the only application code that exists (`infra/lambda/scorer/handler.py`) is a Lambda-style `handler(event, context)` function that assumes `/var/task` — it would not run correctly as a Cloud Run service, which needs an HTTP server listening on `$PORT`. That adapter doesn't exist yet.
4. **DynamoDB GSI type mismatch.** `infra/terraform/dynamodb.tf` types the `flagged` GSI key as a String, but `aws/dynamodb_store.py` writes it as a native Python bool via boto3. The index wouldn't actually match real writes without changing one side or the other.
5. **`terraform validate` is not `terraform apply`.** Both modules pass validation; neither has ever been applied against a real AWS or GCP account. Real applies can surface things validation can't — quota limits, region availability, IAM propagation delays, typos in resource references that only fail at plan/apply time.
6. **No real-world validated detection rate.** The only benchmark is the synthetic proof-of-concept above. The LANL adapter proves schema compatibility, not detection accuracy, since the ground-truth redteam labels aren't wired in (see above).
7. **Hyperparameters are defaults, not tuned.** Ensemble weights, the 0.65 threshold, Isolation Forest's `n_estimators`/`contamination`, the autoencoder's `latent_dim`/`epochs` — none of these came from cross-validation or a grid search against labeled data.
8. **GenAI caching reduces redundant calls, it doesn't cap spend.** `genai/cache.py` skips a repeat Claude call for a user whose score hasn't moved, but there's no hard rate limit or budget ceiling — a caller that hammers `analyze_batch` on genuinely new data would still hit the API at whatever pace it's called.
9. **`suspicious_api_ratio` is AWS-shaped.** The suspicious-API list is a fixed set of AWS action names (`CreateAccessKey`, `AttachUserPolicy`, etc.). On GCP-sourced data this feature reads near zero even for genuinely suspicious activity, since GCP method names look completely different. The other 11 features are schema-based and work the same regardless of source.
10. **Streaming trades accuracy for latency.** Incremental rescoring uses small rolling windows (20 events) that produce noisier features — especially burst score — than the 30-day batch baseline, so the streaming path over-flags relative to batch. This is a real tradeoff, not a bug to be fixed for free.
11. **No CI pipeline in this repo.** Tests and `terraform validate` are run manually. There's no `.github/workflows` gating a PR on either.

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Chinthan Dinesh](https://github.com/DChinthan) · [github.com/DChinthan/iam-anomaly-detector](https://github.com/DChinthan/iam-anomaly-detector)
