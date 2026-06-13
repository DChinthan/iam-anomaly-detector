"""
Streamlit dashboard for the IAM Anomaly Detector.
Run with: streamlit run dashboard/app.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

from data.log_generator import generate_logs
from features.extractor import load_logs, extract_features
from models.detector import train, score

st.set_page_config(
    page_title="IAM Anomaly Detector",
    page_icon="🔐",
    layout="wide",
)

DB_PATH = "data/iam_logs.db"

# ── sidebar ───────────────────────────────────────────────────────────────────

st.sidebar.title("🔐 IAM Anomaly Detector")
st.sidebar.markdown("Unsupervised ML-based detection of suspicious AWS IAM behavior")

st.sidebar.header("Controls")
days = st.sidebar.slider("Simulation window (days)", 7, 90, 30)
threshold = st.sidebar.slider("Anomaly score threshold", 0.40, 0.95, 0.65, 0.05)

if st.sidebar.button("🔄 Regenerate Data & Retrain"):
    st.cache_data.clear()

# ── data pipeline ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner="Generating logs and training models…")
def run_pipeline(days: int):
    import os
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    generate_logs(days=days, output_db=DB_PATH)
    raw = load_logs(DB_PATH)
    features = extract_features(raw)
    models = train(features)
    scored = score(features, models)
    scored["flagged"] = scored["ensemble_score"] > 0.65
    return raw, features, scored

raw_df, features_df, scored_df = run_pipeline(days)
scored_df["flagged"] = scored_df["ensemble_score"] > threshold

# ── header ────────────────────────────────────────────────────────────────────

st.title("AWS IAM Anomaly Detection Dashboard")
st.markdown(
    "Ensemble of **Isolation Forest** + **One-Class SVM** trained on normal user behavior."
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Log Events", f"{len(raw_df):,}")
col2.metric("Users Analyzed", f"{len(scored_df):,}")
col3.metric("Flagged Anomalies", f"{scored_df['flagged'].sum():,}", delta_color="inverse")
col4.metric(
    "Detection Rate",
    f"{scored_df[scored_df['is_anomaly']==1]['flagged'].mean()*100:.0f}%",
    help="% of true anomalous users flagged",
)

st.divider()

# ── anomaly score distribution ────────────────────────────────────────────────

col_left, col_right = st.columns([3, 2])

with col_left:
    st.subheader("Anomaly Score Distribution")
    fig = px.histogram(
        scored_df,
        x="ensemble_score",
        color=scored_df["is_anomaly"].map({0: "Normal", 1: "Anomalous"}),
        nbins=40,
        color_discrete_map={"Normal": "#4C78A8", "Anomalous": "#E45756"},
        labels={"ensemble_score": "Ensemble Anomaly Score", "color": "Ground Truth"},
        barmode="overlay",
        opacity=0.75,
    )
    fig.add_vline(x=threshold, line_dash="dash", line_color="orange",
                  annotation_text=f"Threshold={threshold}")
    st.plotly_chart(fig, use_container_width=True)

with col_right:
    st.subheader("Flagged Users")
    flagged = scored_df[scored_df["flagged"]].sort_values("ensemble_score", ascending=False)
    st.dataframe(
        flagged[["user_id", "ensemble_score", "suspicious_api_ratio",
                 "off_hours_ratio", "burst_score", "mfa_usage_rate"]].round(3),
        use_container_width=True,
        hide_index=True,
    )

st.divider()

# ── feature breakdown ─────────────────────────────────────────────────────────

st.subheader("Feature Heatmap — Top 20 Users by Anomaly Score")

top20 = scored_df.nlargest(20, "ensemble_score")
feature_cols = [
    "off_hours_ratio", "suspicious_api_ratio", "mfa_usage_rate",
    "burst_score", "geo_deviation_score", "error_rate", "unique_ips",
]
heat_data = top20[feature_cols].copy()

# Normalize each feature to [0,1] for visualization
for col in feature_cols:
    rng = heat_data[col].max() - heat_data[col].min()
    heat_data[col] = (heat_data[col] - heat_data[col].min()) / (rng + 1e-9)
    if col == "mfa_usage_rate":
        heat_data[col] = 1 - heat_data[col]  # low MFA = more suspicious

fig2 = go.Figure(data=go.Heatmap(
    z=heat_data.values,
    x=feature_cols,
    y=top20["user_id"].tolist(),
    colorscale="RdYlGn_r",
    hoverongaps=False,
))
fig2.update_layout(height=450, xaxis_title="Feature", yaxis_title="User")
st.plotly_chart(fig2, use_container_width=True)

st.divider()

# ── timeline ──────────────────────────────────────────────────────────────────

st.subheader("API Call Volume Over Time")
flagged_users = scored_df[scored_df["flagged"]]["user_id"].tolist()
timeline = raw_df.copy()
timeline["date"] = timeline["timestamp"].dt.date
timeline["user_type"] = timeline["user_id"].apply(
    lambda u: "Anomalous" if u in flagged_users else "Normal"
)
daily = timeline.groupby(["date", "user_type"]).size().reset_index(name="calls")
fig3 = px.area(
    daily, x="date", y="calls", color="user_type",
    color_discrete_map={"Normal": "#4C78A8", "Anomalous": "#E45756"},
    labels={"calls": "API Calls", "date": "Date"},
)
st.plotly_chart(fig3, use_container_width=True)

# ── model comparison ──────────────────────────────────────────────────────────

st.subheader("Model Comparison: Isolation Forest vs One-Class SVM")
fig4 = px.scatter(
    scored_df,
    x="iso_score",
    y="svm_score",
    color=scored_df["is_anomaly"].map({0: "Normal", 1: "Anomalous"}),
    hover_data=["user_id", "ensemble_score"],
    color_discrete_map={"Normal": "#4C78A8", "Anomalous": "#E45756"},
    labels={"iso_score": "Isolation Forest Score", "svm_score": "One-Class SVM Score"},
)
fig4.add_vline(x=threshold, line_dash="dot", line_color="orange")
fig4.add_hline(y=threshold, line_dash="dot", line_color="orange")
st.plotly_chart(fig4, use_container_width=True)

st.caption(
    "Built with scikit-learn (IsolationForest + OneClassSVM) | "
    "AWS CloudWatch integration | Streamlit + Plotly dashboard"
)
