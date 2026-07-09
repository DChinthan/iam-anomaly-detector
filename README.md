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

A cloud-native platform that detects anomalous IAM/CloudTrail user behavior using an unsupervised ML ensemble, with a GenAI intelligence layer (Claude) that turns flagged users into analyst-grade incident reports. Ingestion, storage, and streaming are fully implemented on **both AWS and GCP** behind one provider-agnostic interface — the same ML and business logic runs on either cloud, selected at runtime.

All models are trained exclusively on normal behavior — no labeled attack data required.

Contributions, issues, and forks are welcome. See [Project Structure](#project-structure) below for where things live.

---

## Architecture

```
┌─ Ingestion — batch or streaming, either cloud ─────────────────────────────┐
│  AWS: CloudWatch Logs Insights (multi-region) · DynamoDB                   │
│  GCP: Cloud Logging (Audit Logs)             · Firestore                   │
│  Streaming: Kafka | GCP Pub/Sub | in-memory (dev)                          │
│  Also: synthetic log generator · real-world LANL dataset adapter           │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 │ normalized IAM events
                                 ▼
┌─ Storage (data/db.py) ──────────────────────────────────────────────────────┐
│  SQLAlchemy engine — SQLite (dev) or Postgres/RDS/Cloud SQL (prod)          │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌─ Feature Engineering (features/extractor.py) ───────────────────────────────┐
│  12 behavioral features per user: call volume, session duration,           │
│  geographic deviation, API call patterns, MFA rate, burst score, ...       │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌─ Ensemble Anomaly Detection (models/detector.py) ───────────────────────────┐
│  Isolation Forest (40%) + One-Class SVM (30%) + TensorFlow Autoencoder     │
│  (30%) → weighted ensemble score + AE-threshold confidence tier            │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌─ Model Drift Monitoring (models/drift.py) ──────────────────────────────────┐
│  PSI + Kolmogorov-Smirnov test vs. training-time baseline                  │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌─ GenAI Security Intelligence (genai/insights.py) ───────────────────────────┐
│  Claude analyzes each flagged user → attack pattern + signals +            │
│  remediation, cached to control cost/latency on repeated runs              │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌─ Streamlit Dashboard (dashboard/app.py) ─────────────────────────────────────┐
│  Role-gated (admin/analyst/viewer) — GenAI alert cards, score              │
│  distribution, model-comparison scatter, feature heatmap, timeline         │
└─────────────────────────────────────────────────────────────────────────────┘

Deployed via two independent, parallel Terraform (HCL) modules:
infra/terraform/ (AWS) and infra/terraform-gcp/ (GCP) — both terraform validate-clean.
```

---

## Platform Capabilities

- **Cloud-portable by design** — `CLOUD_PROVIDER=aws|gcp` routes ingestion, storage, and streaming for the entire CLI; the ML and business logic never branches on provider.
- **Unsupervised ML ensemble** — Isolation Forest + One-Class SVM + TF Autoencoder trained on normal IAM profiles; no attack labels needed.
- **Confidence-tiered alerting** — the autoencoder's own 95th-percentile reconstruction-error threshold is checked independently of the ensemble cutoff, so a flagged user is marked `CONFIRMED` when both signals agree and `SUSPECTED` when only one does — cuts alert-fatigue noise for the analyst reading the output.
- **Real-time event streaming** — Kafka and GCP Pub/Sub as interchangeable backends behind one producer/consumer interface, with incremental per-user rescoring as events arrive, alongside the batch path.
- **Model drift monitoring** — PSI + KS statistical tests against a saved training-time baseline, so silent accuracy decay gets caught instead of ignored.
- **GenAI incident reports** — Claude generates natural-language security alerts with attack pattern classification and remediation steps; a rule-based fallback keeps the system fully functional with zero external API dependency.
- **Role-based access control** — admin/analyst/viewer roles gate retrain controls, GenAI panels, and user-identifying data on the dashboard itself.
- **Infrastructure as Code** — two independent Terraform modules (AWS and GCP) provisioning storage, log aggregation, scheduled scoring compute, and least-privilege IAM/service accounts.
- **Database-agnostic persistence** — SQLite for local development, Postgres (RDS/Aurora or Cloud SQL) for production, via one SQLAlchemy abstraction with no code changes between environments.
- **Zero-cost local development** — every cloud backend (AWS, GCP, Kafka, Pub/Sub) has a working mock mode, so the full test suite and every CLI command run without cloud credentials.

---

## Behavioral Features

| Feature | Description | Attack Signal |
|---|---|---|
| `total_api_calls` | Calls per day over the window | Automated credential abuse |
| `avg_session_duration` / `max_session_duration` | Time between first and last call per session | Persistent unauthorized sessions |
| `geo_deviation_score` | Unique /24 subnets used | Lateral movement / IP hopping |
| `suspicious_api_ratio` | % calls to privilege-escalation APIs | CreateAccessKey, GetSecretValue, DeleteTrail |
| `off_hours_ratio` | % activity between 10pm–6am | Compromised creds used outside business hours |
| `mfa_usage_rate` | MFA present on API calls | Stolen long-lived access keys |
| `burst_score` | Max calls in any 30-min window | Automated credential harvesting |
| `error_rate` | % calls returning AccessDenied | Probing for permissions |
| `unique_ips` / `unique_regions` | Distinct source IPs / regions | Credential sharing, unusual footprint |
| `weekend_ratio` | % activity on Sat/Sun | Atypical access schedule |

---

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the full pipeline (generate → train → score → insights)
python main.py pipeline

# 3. Launch the real-time Streamlit dashboard
streamlit run dashboard/app.py
```

Copy `.env.example` to `.env` for the full list of configuration options — every default runs fully locally with zero cloud credentials.

### Option B: Real-world dataset (LANL Unified Host and Network Dataset)

The [LANL Comprehensive Multi-Source Cybersecurity Events](https://csr.lanl.gov/data/cyber1/) dataset contains 58 days of de-identified authentication logs from Los Alamos National Laboratory — millions of real enterprise auth events used in dozens of published security papers.

```bash
# 1. Visit csr.lanl.gov/data/cyber1/ and accept the free data use agreement
# 2. Download auth.txt.gz (~1.5 GB) and place it in data/

# 3. Ingest the first 500k events (≈ 40 MB uncompressed, plenty for the models)
python main.py lanl data/auth.txt.gz 500000

# 4. Train and score on real data
python main.py train
python main.py score
streamlit run dashboard/app.py
```

The LANL adapter (`data/lanl_adapter.py`) maps authentication events to the IAM log schema: maps `auth_type` + `logon_type` to API call equivalents, derives session durations from LogOn/LogOff pairs, and assigns stable synthetic IPs from computer names.

---

### Multi-cloud configuration

```bash
# GenAI alerts via Claude
export ANTHROPIC_API_KEY=your_key

# Route ingestion/storage/streaming to AWS (default) or GCP
export CLOUD_PROVIDER=aws   # or: gcp

# AWS — CloudWatch + DynamoDB
export AWS_MOCK=false
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGIONS=us-east-1,us-west-2
export DYNAMODB_TABLE=iam-anomaly-results

# GCP — Cloud Logging + Firestore (see gcp/README.md for full setup)
export GCP_MOCK=false
export GCP_PROJECT=your-project-id
export GCP_REGIONS=us-central1,us-east1

python main.py ingest    # pulls from the configured provider
python main.py train
python main.py score
```

Real-time streaming:

```bash
python main.py stream-demo 200                    # mock mode, zero infra
STREAM_MODE=kafka  KAFKA_BROKERS=broker:9092  python main.py stream
STREAM_MODE=pubsub PUBSUB_EMULATOR_HOST=localhost:8085 python main.py stream
```

Model drift check and Postgres/RDS/Cloud SQL persistence:

```bash
python main.py drift

DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/iam_anomaly python main.py pipeline
```

See `.env.example` for every configuration option, and `gcp/README.md` for GCP-specific setup (service account roles, Pub/Sub emulator).

---

## Project Structure

```
iam-anomaly-detector/
├── data/
│   ├── log_generator.py        # Synthetic IAM log generation
│   ├── lanl_adapter.py         # Real-world LANL dataset adapter
│   └── db.py                   # SQLite (dev) / Postgres — RDS or Cloud SQL (prod) engine abstraction
├── features/
│   └── extractor.py            # FeatureExtractor class — 12 behavioral features
├── models/
│   ├── autoencoder.py          # TensorFlow/Keras Dense Autoencoder (IAMAutoencoder class)
│   ├── detector.py             # AnomalyDetector ensemble class (IF + SVM + AE), confidence tiering
│   └── drift.py                # PSI/KS-based model drift detection vs. training baseline
├── genai/
│   ├── insights.py             # Claude-powered GenAI security alert generation
│   └── cache.py                # TTL cache for GenAI alerts (cost/latency control)
├── aws/
│   ├── cloudwatch_client.py    # Multi-region CloudWatch Logs ingestion (boto3)
│   └── dynamodb_store.py       # DynamoDB NoSQL persistence (DynamoDBStore class)
├── gcp/
│   ├── cloud_logging_client.py # Cloud Logging / Audit Log ingestion (google-cloud-logging)
│   ├── firestore_store.py      # Firestore NoSQL persistence (FirestoreStore class)
│   └── README.md               # GCP setup, IAM roles, regional-model notes
├── streaming/
│   ├── event_stream.py         # Kafka | GCP Pub/Sub | in-memory producer & consumer
│   ├── pubsub_backend.py       # GCP Pub/Sub backend (emulator-compatible)
│   ├── stream_processor.py     # Incremental per-user rescoring off the live stream
│   └── simulate_producer.py    # Publishes synthetic live events
├── dashboard/
│   ├── app.py                  # Streamlit real-time dashboard (Plotly charts)
│   └── auth.py                 # Role-based access control (admin/analyst/viewer)
├── infra/
│   ├── terraform/               # AWS: DynamoDB, CloudWatch, scoring Lambda, IAM, Cognito
│   ├── terraform-gcp/           # GCP: Firestore, Cloud Logging, Pub/Sub, Cloud Run, IAM
│   └── lambda/scorer/           # Container-image Lambda handler for scheduled scoring
├── tests/                      # 40 automated tests, zero cloud credentials required
├── main.py                     # CLI: pipeline / stream / drift / ingest / ... (CLOUD_PROVIDER-aware)
├── .env.example                 # Every configuration option, documented
└── requirements.txt
```

---

## ML Model Details

### Isolation Forest
- 300 estimators, contamination = 0.05
- Isolates anomalies by randomly partitioning feature space
- Anomalies require fewer splits → shorter path lengths

### One-Class SVM
- RBF kernel, nu = 0.05
- Learns a hypersphere around normal behavior in kernel space
- Points outside the boundary are classified as anomalies

### TensorFlow Autoencoder
- Architecture: Dense 12 → 8 → 4 → 8 → 12
- Trained to minimize reconstruction MSE on normal user profiles
- At inference: `anomaly_score = MSE(input, reconstruction)`, normalized to [0, 1]
- Its 95th-percentile training-reconstruction-error threshold backs the confidence tier below

### Ensemble
- Weighted combination: 40% IF + 30% SVM + 30% AE
- Users with ensemble score > 0.65 are flagged for investigation
- **Confidence tiering**: the AE's own threshold is checked independently (`ae_threshold_exceeded`). A flagged user is `CONFIRMED` when both signals agree, `SUSPECTED` when only the ensemble score crosses 0.65 — separates high-confidence hits from borderline ones for the analyst.

### Model Drift Monitoring
- Population Stability Index (PSI) + Kolmogorov-Smirnov test per feature against a training-time baseline, snapshotted automatically on every `fit()`
- Run via `python main.py drift`; thresholds at PSI > 0.10 (warn) and > 0.25 (alert)

---

## Benchmark Results

| Metric | Value |
|---|---|
| True Positive Rate | >95% |
| False Positive Rate | <10% |
| Users analyzed | 55 (50 normal + 5 adversarial) |
| Log events | ~120,000 over 30 days |
| Automated tests | 40 passing (pytest, zero cloud credentials required) |
| IaC validation | `terraform validate`: Success on both AWS and GCP modules |

Injected anomaly patterns: off-hours access from suspicious IPs, privilege escalation API bursts, missing MFA with high session duration, credential harvesting (CreateAccessKey + GetSecretValue bursts).

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML models | scikit-learn (IsolationForest, OneClassSVM), TensorFlow/Keras |
| GenAI | Anthropic Claude API |
| Feature engineering | pandas, numpy, scipy |
| Relational storage | SQLite (dev), Postgres — AWS RDS/Aurora or GCP Cloud SQL (prod), via SQLAlchemy |
| NoSQL storage | AWS DynamoDB (boto3), GCP Firestore (google-cloud-firestore) |
| Log ingestion | AWS CloudWatch Logs Insights, GCP Cloud Logging |
| Event streaming | Kafka (confluent-kafka), GCP Pub/Sub (google-cloud-pubsub) |
| Infrastructure as Code | Terraform (AWS + Google providers), Docker |
| Dashboard | Streamlit, Plotly |
| Testing | pytest (40 tests) |
| Version control | Git |

---

## Testing

```bash
python -m pytest tests/ -q
```

40 tests across 6 files cover feature extraction, the ML ensemble, both cloud storage backends (AWS + GCP), the streaming layer, and the synthetic log generator — every backend has a mock mode, so no cloud credentials or emulators are required to run the full suite.

---

## License

MIT — see [LICENSE](LICENSE).

Built by [Chinthan Dinesh](https://github.com/DChinthan) · [github.com/DChinthan/iam-anomaly-detector](https://github.com/DChinthan/iam-anomaly-detector)
