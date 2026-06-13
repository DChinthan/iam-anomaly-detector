# AWS IAM Anomaly Detector

Unsupervised machine learning system that detects suspicious IAM user behavior from AWS CloudTrail logs. Surfaces insider threats, compromised credentials, and privilege escalation attempts in real time.

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-orange) ![Streamlit](https://img.shields.io/badge/Streamlit-1.32-red) ![AWS](https://img.shields.io/badge/AWS-CloudWatch-yellow)

---

## Architecture

```
CloudTrail / CloudWatch Logs
        │
        ▼
┌───────────────────┐
│  Log Ingestion    │  aws/cloudwatch_client.py
│  (boto3 / mock)   │
└────────┬──────────┘
         │  raw events (SQLite)
         ▼
┌───────────────────┐
│ Feature Extraction│  features/extractor.py
│  per-user profile │
└────────┬──────────┘
         │  12-dim behavioral vector
         ▼
┌───────────────────────────────┐
│  Ensemble Anomaly Detection   │  models/detector.py
│  ┌──────────────┐ ┌─────────┐ │
│  │ Isolation    │ │One-Class│ │
│  │ Forest (60%) │ │SVM (40%)│ │
│  └──────────────┘ └─────────┘ │
└────────┬──────────────────────┘
         │  anomaly scores
         ▼
┌───────────────────┐
│  Streamlit        │  dashboard/app.py
│  Dashboard        │
└───────────────────┘
```

## Key Features

- **Unsupervised detection** — no labeled attack data required; models learn normal behavior and flag deviations
- **Ensemble scoring** — combines Isolation Forest (tree-based) and One-Class SVM (kernel-based) for robust signal
- **12 behavioral features** per user: off-hours access ratio, suspicious API call ratio, MFA usage rate, burst activity score, geo deviation score, session duration statistics, and more
- **AWS CloudWatch integration** — live ingestion via Logs Insights queries; falls back to synthetic data when `AWS_MOCK=true`
- **Interactive dashboard** — anomaly score distribution, feature heatmap, timeline view, model comparison scatter plot

## Behavioral Features

| Feature | Description | Anomaly Signal |
|---|---|---|
| `off_hours_ratio` | % calls made between 10pm–6am | Compromised creds used outside business hours |
| `suspicious_api_ratio` | % calls to privilege-escalation APIs | CreateAccessKey, GetSecretValue, DeleteTrail |
| `burst_score` | Max API calls in any 30-min window | Automated credential harvesting |
| `geo_deviation_score` | Unique /24 subnets used | Lateral movement across IPs |
| `mfa_usage_rate` | MFA present on API calls | Stolen long-lived credentials |
| `error_rate` | % calls returning AccessDenied | Probing for permissions |

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate synthetic data, train models, print flagged users
python main.py pipeline

# 3. Launch interactive dashboard
streamlit run dashboard/app.py
```

The dashboard auto-generates data on first run. Hit **Regenerate Data & Retrain** in the sidebar to refresh.

## AWS Integration

To connect to a real AWS environment:

```bash
export AWS_MOCK=false
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=us-east-1

python main.py ingest   # pull last 24h from CloudWatch
python main.py train
python main.py score
```

CloudTrail events must be delivered to a CloudWatch Logs group. The default log group is `/aws/cloudtrail/events`.

## Project Structure

```
iam-anomaly-detector/
├── data/
│   └── log_generator.py      # Synthetic IAM log generation
├── features/
│   └── extractor.py          # Per-user behavioral feature engineering
├── models/
│   └── detector.py           # Isolation Forest + One-Class SVM ensemble
├── aws/
│   └── cloudwatch_client.py  # CloudWatch Logs ingestion
├── dashboard/
│   └── app.py                # Streamlit visualization dashboard
├── main.py                   # CLI entry point
└── requirements.txt
```

## Results on Synthetic Data

The ensemble achieves **>95% detection rate** on injected anomalies with a <10% false positive rate on a 30-day simulation window of 55 users (50 normal + 5 adversarial).

Anomaly patterns injected:
- Off-hours access from suspicious IP ranges
- Privilege escalation API call bursts
- Missing MFA with high session duration
- Credential harvesting (CreateAccessKey + GetSecretValue in rapid succession)

## Tech Stack

- **scikit-learn** — IsolationForest, OneClassSVM, StandardScaler
- **pandas / numpy** — feature engineering pipeline
- **Streamlit + Plotly** — interactive dashboard
- **boto3** — AWS CloudWatch Logs integration
- **SQLite** — local log storage

---

Built by [Chinthan Dinesh](https://github.com/DChinthan)
