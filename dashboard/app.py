"""
Streamlit dashboard for the IAM Anomaly Detector.
Run with: streamlit run dashboard/app.py
"""

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from data.log_generator import generate_logs
from features.extractor import load_logs, extract_features
from models.detector import AnomalyDetector
from genai.insights import analyze_batch, SecurityAlert
from dashboard.auth import require_login, can

st.set_page_config(
    page_title="IAM Anomaly Detector",
    page_icon="🔐",
    layout="wide",
)

DB_PATH = "data/iam_logs.db"
CLOUD_PROVIDER = os.getenv("CLOUD_PROVIDER", "aws")  # aws | gcp | mock — mirrors main.py


def _get_store():
    """Same routing as main.py's _get_store() — previously this file hardcoded
    DynamoDBStore regardless of CLOUD_PROVIDER (see README Limitation #1)."""
    if CLOUD_PROVIDER == "gcp":
        from gcp.firestore_store import FirestoreStore
        return FirestoreStore()
    from aws.dynamodb_store import DynamoDBStore
    return DynamoDBStore()

# ── auth ──────────────────────────────────────────────────────────────────────

user = require_login()

# ── sidebar ───────────────────────────────────────────────────────────────────

st.sidebar.title("🔐 IAM Anomaly Detector")
st.sidebar.markdown(
    "**GenAI-powered** detection of suspicious AWS IAM behavior using  \n"
    "Isolation Forest · One-Class SVM · TensorFlow Autoencoder"
)

st.sidebar.header("Controls")
use_live_data = st.sidebar.toggle(
    f"Use live ingested data ({CLOUD_PROVIDER.upper()})",
    value=False,
    help="Off = regenerate synthetic demo data (default). On = load whatever's "
         "already in data/iam_logs.db from `python main.py ingest`, and persist "
         "scores to the real store for CLOUD_PROVIDER instead of always DynamoDB.",
)
days = st.sidebar.slider("Simulation window (days)", 7, 90, 30, disabled=use_live_data)
threshold = st.sidebar.slider("Anomaly score threshold", 0.40, 0.95, 0.65, 0.05)
run_genai = st.sidebar.toggle("GenAI Security Insights", value=True) and can(user, "view_genai")

if can(user, "retrain"):
    if st.sidebar.button("🔄 Regenerate Data & Retrain"):
        st.cache_data.clear()
else:
    st.sidebar.caption("Retrain controls require the admin role.")

# ── data pipeline ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner="Loading data, extracting features, training models…")
def run_pipeline(days: int, use_live: bool, cloud_provider: str):
    if use_live:
        if not os.path.exists(DB_PATH):
            raise FileNotFoundError(
                f"No data at {DB_PATH} — run `python main.py ingest` first "
                f"(with CLOUD_PROVIDER={cloud_provider} set) to populate real events."
            )
    else:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        generate_logs(days=days, output_db=DB_PATH)
    raw = load_logs(DB_PATH)
    features = extract_features(raw)
    if use_live:
        # Live data may be too small a sample (even 1 user) to fit a fresh
        # ensemble — reuse the already-trained model instead, mirroring
        # main.py's cmd_score(), which loads rather than refits.
        detector = AnomalyDetector.load()
    else:
        detector = AnomalyDetector()
        detector.fit(features)
    scored = detector.score(features)
    store = _get_store()
    store.bulk_put(scored)
    return raw, features, scored

raw_df, features_df, scored_df = run_pipeline(days, use_live_data, CLOUD_PROVIDER)
scored_df = scored_df.copy()
scored_df["flagged"] = scored_df["ensemble_score"] > threshold

# ── header ────────────────────────────────────────────────────────────────────

st.title(f"{CLOUD_PROVIDER.upper()} IAM Anomaly Detection Dashboard")
st.markdown(
    "Unsupervised ML ensemble trained on normal behavior — no labeled attack data required. "
    "**GenAI layer** (Claude) generates analyst-grade security alerts for flagged users."
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Log Events", f"{len(raw_df):,}")
col2.metric("Users Analyzed", f"{len(scored_df):,}")
col3.metric("Flagged Anomalies", f"{scored_df['flagged'].sum():,}", delta_color="inverse")

flagged_true = scored_df[scored_df["is_anomaly"] == 1]
if len(flagged_true):
    col4.metric(
        "True Positive Rate",
        f"{flagged_true['flagged'].mean()*100:.0f}%",
        help="% of ground-truth anomalous users correctly flagged",
    )

st.divider()

# ── genai alerts ─────────────────────────────────────────────────────────────

if run_genai and scored_df["flagged"].any():
    st.subheader("GenAI Security Intelligence Alerts")
    st.caption("Claude analyzes each flagged user's behavioral profile and generates structured incident reports.")

    with st.spinner("Generating AI security alerts…"):
        alerts: list[SecurityAlert] = analyze_batch(scored_df, top_n=5)

    for alert in alerts:
        color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}[alert.severity]
        with st.expander(f"{color} **{alert.severity}** — {alert.user_id} | {alert.attack_pattern}"):
            st.markdown(f"**Analysis:** {alert.raw_explanation}")
            st.markdown("**Key Signals:**")
            for sig in alert.key_signals:
                st.markdown(f"  - {sig}")
            st.markdown(f"**Recommendation:** {alert.recommendation}")

    st.divider()

# ── score distribution ────────────────────────────────────────────────────────

col_left, col_right = st.columns([3, 2])

with col_left:
    st.subheader("Anomaly Score Distribution")
    fig = px.histogram(
        scored_df,
        x="ensemble_score",
        color=scored_df["is_anomaly"].map({0: "Normal", 1: "Anomalous"}),
        nbins=40,
        color_discrete_map={"Normal": "#4C78A8", "Anomalous": "#E45756"},
        labels={"ensemble_score": "Ensemble Score", "color": "Ground Truth"},
        barmode="overlay",
        opacity=0.75,
    )
    fig.add_vline(x=threshold, line_dash="dash", line_color="orange",
                  annotation_text=f"Threshold {threshold}")
    st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.subheader("Flagged Users")
    flagged = scored_df[scored_df["flagged"]].sort_values("ensemble_score", ascending=False)
    display_cols = [
        "ensemble_score", "iso_score", "svm_score", "ae_score", "confidence",
        "suspicious_api_ratio", "off_hours_ratio", "burst_score",
    ]
    if can(user, "view_user_ids"):
        display_cols = ["user_id"] + display_cols
    else:
        st.caption("User identities hidden — viewer role sees aggregate signals only.")
    st.dataframe(
        flagged[display_cols].round(3),
        use_container_width=True,
        hide_index=True,
    )

st.divider()

# ── model comparison ──────────────────────────────────────────────────────────

st.subheader("Model Comparison: Isolation Forest · One-Class SVM · TF Autoencoder")
col_a, col_b = st.columns(2)

with col_a:
    fig2 = px.scatter(
        scored_df,
        x="iso_score", y="svm_score",
        color=scored_df["is_anomaly"].map({0: "Normal", 1: "Anomalous"}),
        hover_data=["user_id", "ensemble_score"],
        color_discrete_map={"Normal": "#4C78A8", "Anomalous": "#E45756"},
        labels={"iso_score": "Isolation Forest", "svm_score": "One-Class SVM"},
        title="Isolation Forest vs One-Class SVM",
    )
    fig2.add_vline(x=threshold, line_dash="dot", line_color="orange")
    fig2.add_hline(y=threshold, line_dash="dot", line_color="orange")
    st.plotly_chart(fig2, use_container_width=True)

with col_b:
    fig3 = px.scatter(
        scored_df,
        x="ensemble_score", y="ae_score",
        color=scored_df["is_anomaly"].map({0: "Normal", 1: "Anomalous"}),
        hover_data=["user_id"],
        color_discrete_map={"Normal": "#4C78A8", "Anomalous": "#E45756"},
        labels={"ensemble_score": "Ensemble Score", "ae_score": "TF Autoencoder"},
        title="Ensemble Score vs TF Autoencoder Reconstruction Error",
    )
    st.plotly_chart(fig3, use_container_width=True)

st.divider()

# ── feature heatmap ───────────────────────────────────────────────────────────

st.subheader("Feature Heatmap — Top 20 Users by Anomaly Score")
top20 = scored_df.nlargest(20, "ensemble_score")
feature_cols = [
    "off_hours_ratio", "suspicious_api_ratio", "mfa_usage_rate",
    "burst_score", "geo_deviation_score", "error_rate", "unique_ips",
]
heat = top20[feature_cols].copy()
for col in feature_cols:
    rng = heat[col].max() - heat[col].min()
    heat[col] = (heat[col] - heat[col].min()) / (rng + 1e-9)
    if col == "mfa_usage_rate":
        heat[col] = 1 - heat[col]

fig4 = go.Figure(data=go.Heatmap(
    z=heat.values,
    x=feature_cols,
    y=top20["user_id"].tolist(),
    colorscale="RdYlGn_r",
))
fig4.update_layout(height=450, xaxis_title="Feature", yaxis_title="User")
st.plotly_chart(fig4, use_container_width=True)

st.divider()

# ── timeline ──────────────────────────────────────────────────────────────────

st.subheader("API Call Volume Over Time")
flagged_users = set(scored_df[scored_df["flagged"]]["user_id"])
timeline = raw_df.copy()
timeline["date"] = timeline["timestamp"].dt.date
timeline["user_type"] = timeline["user_id"].apply(
    lambda u: "Anomalous" if u in flagged_users else "Normal"
)
daily = timeline.groupby(["date", "user_type"]).size().reset_index(name="calls")
fig5 = px.area(
    daily, x="date", y="calls", color="user_type",
    color_discrete_map={"Normal": "#4C78A8", "Anomalous": "#E45756"},
    labels={"calls": "API Calls", "date": "Date"},
)
st.plotly_chart(fig5, use_container_width=True)

_provider_stack = "GCP Cloud Logging + Firestore" if CLOUD_PROVIDER == "gcp" else "AWS CloudWatch + DynamoDB"
st.caption(
    "Stack: scikit-learn (IsolationForest + OneClassSVM) · TensorFlow/Keras Autoencoder · "
    f"Anthropic Claude API (GenAI) · {_provider_stack} · Streamlit + Plotly"
)
