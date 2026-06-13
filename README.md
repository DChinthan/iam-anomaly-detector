# AI-Driven Behavioral Anomaly Detection in IAM: GenAI Security Tool

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15-orange)](https://tensorflow.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E)](https://scikit-learn.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32-FF4B4B)](https://streamlit.io)
[![AWS](https://img.shields.io/badge/AWS-CloudWatch%20%7C%20DynamoDB-232F3E)](https://aws.amazon.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

An AI-powered security tool that autonomously detects anomalous AWS IAM user behavior using an ensemble of **Isolation Forest**, **One-Class SVM**, and a **TensorFlow Autoencoder** — with a **GenAI intelligence layer** (Claude) that generates analyst-grade incident reports for every flagged user.

All models are trained exclusively on normal behavior — no labeled attack data required.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  AWS Data Sources                                           │
│  ┌─────────────────┐       ┌──────────────────────────┐    │
│  │  CloudWatch Logs│       │  DynamoDB (NoSQL store)  │    │
│  │  (CloudTrail)   │       │  Anomaly results / alerts│    │
│  └────────┬────────┘       └──────────────────────────┘    │
└───────────┼─────────────────────────────────────────────────┘
            │ raw IAM events → SQLite
            ▼
┌───────────────────────────────────────────────────────┐
│  Feature Engineering  (features/extractor.py)         │
│  FeatureExtractor class — 12 behavioral features      │
│  per user: login frequency, session duration,         │
│  geographic deviation, API call patterns, MFA rate    │
└───────────────────┬───────────────────────────────────┘
                    │  feature matrix (n_users × 12)
                    ▼
┌───────────────────────────────────────────────────────┐
│  Ensemble Anomaly Detection  (models/detector.py)     │
│                                                       │
│  ┌─────────────────┐ ┌──────────────┐ ┌───────────┐  │
│  │ Isolation Forest│ │ One-Class SVM│ │TensorFlow │  │
│  │   (40% weight)  │ │  (30% weight)│ │Autoencoder│  │
│  │  tree-based     │ │  kernel-based│ │ (30% wgt) │  │
│  │  n_estimators   │ │  RBF kernel  │ │ Dense AE  │  │
│  │  = 300          │ │  nu = 0.05   │ │ 12→8→4→8→12│ │
│  └─────────────────┘ └──────────────┘ └───────────┘  │
│         └──────────────────┬──────────────┘           │
│                   Weighted ensemble score              │
└───────────────────┬───────────────────────────────────┘
                    │  anomaly scores per user
                    ▼
┌───────────────────────────────────────────────────────┐
│  GenAI Security Intelligence  (genai/insights.py)     │
│  Claude analyzes each flagged user's profile →        │
│  attack pattern + key signals + remediation steps     │
└───────────────────┬───────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────┐
│  Streamlit Real-Time Dashboard  (dashboard/app.py)    │
│  • GenAI alert cards  • Score distribution            │
│  • Feature heatmap    • Model comparison scatter      │
│  • API call timeline  • Flagged user table            │
└───────────────────────────────────────────────────────┘
```

---

## Key Features

- **Unsupervised ML ensemble** — Isolation Forest + One-Class SVM + TF Autoencoder trained on normal IAM profiles; no attack labels needed
- **TensorFlow Autoencoder** — Dense neural network learns to reconstruct normal sessions; high reconstruction error = anomaly
- **GenAI incident reports** — Claude generates natural-language security alerts with attack pattern classification and remediation steps
- **Automated feature extraction** from SQL (SQLite) and NoSQL (DynamoDB) sources
- **AWS CloudWatch ingestion** — Logs Insights queries over CloudTrail events; mock mode for local development
- **DynamoDB persistence** — Scored results and alerts stored in NoSQL for cross-session querying
- **OOP design** — `FeatureExtractor`, `AnomalyDetector`, `IAMAutoencoder`, `DynamoDBStore`, `SecurityAlert` classes

---

## Behavioral Features

| Feature | Description | Attack Signal |
|---|---|---|
| `login_frequency` / `total_api_calls` | Calls per day over the window | Automated credential abuse |
| `session_duration` (avg + max) | Time between first and last call per session | Persistent unauthorized sessions |
| `geographic_deviation` | Unique /24 subnets used | Lateral movement / IP hopping |
| `api_call_patterns` | % calls to privilege-escalation APIs | CreateAccessKey, GetSecretValue, DeleteTrail |
| `off_hours_ratio` | % activity between 10pm–6am | Compromised creds used outside business hours |
| `mfa_usage_rate` | MFA present on API calls | Stolen long-lived access keys |
| `burst_score` | Max calls in any 30-min window | Automated credential harvesting |
| `error_rate` | % calls returning AccessDenied | Probing for permissions |

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

The LANL adapter (`data/lanl_adapter.py`) maps authentication events to the IAM log schema:
maps `auth_type` + `logon_type` → AWS API call equivalents, derives session durations from LogOn/LogOff pairs, and assigns stable synthetic IPs from computer names.

---

### Optional: Enable live GenAI alerts

```bash
export ANTHROPIC_API_KEY=your_key
streamlit run dashboard/app.py
```

### Optional: Connect to real AWS

```bash
export AWS_MOCK=false
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=us-east-1
export DYNAMODB_TABLE=iam-anomaly-results

python main.py ingest    # pull last 24h from CloudWatch Logs
python main.py train
python main.py score
```

---

## Project Structure

```
iam-anomaly-detector/
├── data/
│   └── log_generator.py        # Synthetic IAM log generation (SQL → SQLite)
├── features/
│   └── extractor.py            # FeatureExtractor class — 12 behavioral features
├── models/
│   ├── autoencoder.py          # TensorFlow/Keras Dense Autoencoder (IAMAutoencoder class)
│   └── detector.py             # AnomalyDetector ensemble class (IF + SVM + AE)
├── genai/
│   └── insights.py             # Claude-powered GenAI security alert generation
├── aws/
│   ├── cloudwatch_client.py    # CloudWatch Logs ingestion (boto3)
│   └── dynamodb_store.py       # DynamoDB NoSQL persistence (DynamoDBStore class)
├── dashboard/
│   └── app.py                  # Streamlit real-time dashboard (Plotly charts)
├── main.py                     # CLI: pipeline / generate / train / score / insights
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
- Threshold set at 95th percentile of training reconstruction errors

### Ensemble
- Weighted combination: 40% IF + 30% SVM + 30% AE
- Users with ensemble score > 0.65 are flagged for investigation

---

## Results on Synthetic Data

| Metric | Value |
|---|---|
| True Positive Rate | >95% |
| False Positive Rate | <10% |
| Users analyzed | 55 (50 normal + 5 adversarial) |
| Log events | ~120,000 over 30 days |

Injected anomaly patterns: off-hours access from suspicious IPs, privilege escalation API bursts, missing MFA with high session duration, credential harvesting (CreateAccessKey + GetSecretValue bursts).

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML models | scikit-learn (IsolationForest, OneClassSVM), TensorFlow/Keras |
| GenAI | Anthropic Claude API |
| Feature engineering | pandas, numpy |
| SQL storage | SQLite |
| NoSQL storage | AWS DynamoDB (boto3) |
| Log ingestion | AWS CloudWatch Logs Insights (boto3) |
| Dashboard | Streamlit, Plotly |
| Version control | Git (open-source) |

---

Built by [Chinthan Dinesh](https://github.com/DChinthan) · [github.com/DChinthan/iam-anomaly-detector](https://github.com/DChinthan/iam-anomaly-detector)
