"""
Extracts behavioral features per user from raw IAM log data.
Each row in the output represents one user's aggregated profile
over the analysis window.
"""

import sqlite3
import pandas as pd
import numpy as np
from typing import Optional


def load_logs(db_path: str = "data/iam_logs.db") -> pd.DataFrame:
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM iam_logs", conn)
    conn.close()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    return df


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregates per-user behavioral signals into a flat feature vector.
    Features are designed to surface credential misuse, privilege escalation,
    and lateral movement patterns.
    """
    suspicious_apis = {
        "CreateAccessKey", "AttachUserPolicy", "CreateUser",
        "PutUserPolicy", "DeleteTrail", "StopLogging",
        "GetSecretValue", "ListSecrets", "AssumeRole",
    }

    def off_hours_ratio(hours: pd.Series) -> float:
        off = ((hours < 6) | (hours > 22)).sum()
        return off / max(len(hours), 1)

    def geo_deviation_score(ips: pd.Series) -> float:
        # Proxy: number of unique /24 subnets used
        subnets = ips.apply(lambda ip: ".".join(ip.split(".")[:3]))
        return subnets.nunique()

    def suspicious_api_ratio(calls: pd.Series) -> float:
        return calls.isin(suspicious_apis).sum() / max(len(calls), 1)

    def burst_score(timestamps: pd.Series) -> float:
        # Max calls in any 30-minute sliding window
        ts_sorted = timestamps.sort_values()
        window = pd.Timedelta(minutes=30)
        counts = [
            ((ts_sorted >= t) & (ts_sorted < t + window)).sum()
            for t in ts_sorted
        ]
        return max(counts) if counts else 0

    records = []
    for user_id, group in df.groupby("user_id"):
        record = {
            "user_id": user_id,
            "total_api_calls": len(group),
            "unique_ips": group["source_ip"].nunique(),
            "unique_regions": group["region"].nunique(),
            "off_hours_ratio": off_hours_ratio(group["hour"]),
            "mfa_usage_rate": group["mfa_used"].mean(),
            "error_rate": (group["error_code"].notna()).mean(),
            "suspicious_api_ratio": suspicious_api_ratio(group["api_call"]),
            "avg_session_duration": group["session_duration_seconds"].mean(),
            "max_session_duration": group["session_duration_seconds"].max(),
            "geo_deviation_score": geo_deviation_score(group["source_ip"]),
            "burst_score": burst_score(group["timestamp"]),
            "weekend_ratio": (group["day_of_week"] >= 5).mean(),
            "is_anomaly": group["is_anomaly"].max(),  # ground truth label
        }
        records.append(record)

    features_df = pd.DataFrame(records)
    return features_df


FEATURE_COLS = [
    "total_api_calls",
    "unique_ips",
    "unique_regions",
    "off_hours_ratio",
    "mfa_usage_rate",
    "error_rate",
    "suspicious_api_ratio",
    "avg_session_duration",
    "max_session_duration",
    "geo_deviation_score",
    "burst_score",
    "weekend_ratio",
]
