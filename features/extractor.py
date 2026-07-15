"""
Extracts behavioral features per user from raw IAM log data.
Each row in the output represents one user's aggregated profile
over the analysis window.
"""

import pandas as pd
import numpy as np
from dataclasses import dataclass, field
from typing import Optional

from data.db import get_engine


@dataclass
class UserProfile:
    """Structured representation of a single user's behavioral fingerprint."""

    user_id: str
    total_api_calls: int = 0
    unique_ips: int = 0
    unique_regions: int = 0
    off_hours_ratio: float = 0.0
    mfa_usage_rate: float = 0.0
    error_rate: float = 0.0
    suspicious_api_ratio: float = 0.0
    avg_session_duration: float = 0.0
    max_session_duration: float = 0.0
    geo_deviation_score: float = 0.0
    burst_score: float = 0.0
    weekend_ratio: float = 0.0
    is_anomaly: int = 0

    def to_dict(self) -> dict:
        return self.__dict__


SUSPICIOUS_APIS = frozenset({
    "CreateAccessKey", "AttachUserPolicy", "CreateUser",
    "PutUserPolicy", "DeleteTrail", "StopLogging",
    "GetSecretValue", "ListSecrets", "AssumeRole",
})

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


class FeatureExtractor:
    """
    Transforms raw IAM event logs into a per-user behavioral feature matrix.
    Features capture login patterns, geographic signals, API abuse indicators,
    and temporal anomalies that correspond to known IAM attack patterns.
    """

    def __init__(self, burst_window_minutes: int = 30):
        self.burst_window = pd.Timedelta(minutes=burst_window_minutes)

    def _off_hours_ratio(self, hours: pd.Series) -> float:
        return ((hours < 6) | (hours > 22)).sum() / max(len(hours), 1)

    def _geo_deviation_score(self, ips: pd.Series) -> float:
        subnets = ips.apply(lambda ip: ".".join(ip.split(".")[:3]))
        return float(subnets.nunique())

    def _suspicious_api_ratio(self, calls: pd.Series) -> float:
        return calls.isin(SUSPICIOUS_APIS).sum() / max(len(calls), 1)

    def _burst_score(self, timestamps: pd.Series) -> float:
        """Max API calls in any sliding burst window."""
        ts = timestamps.sort_values()
        if ts.empty:
            return 0.0
        counts = [
            int(((ts >= t) & (ts < t + self.burst_window)).sum())
            for t in ts
        ]
        return float(max(counts))

    def _profile_user(self, user_id: str, group: pd.DataFrame) -> UserProfile:
        return UserProfile(
            user_id=user_id,
            total_api_calls=len(group),
            unique_ips=group["source_ip"].nunique(),
            unique_regions=group["region"].nunique(),
            off_hours_ratio=self._off_hours_ratio(group["hour"]),
            mfa_usage_rate=float(group["mfa_used"].mean()),
            error_rate=float(group["error_code"].notna().mean()),
            suspicious_api_ratio=self._suspicious_api_ratio(group["api_call"]),
            avg_session_duration=float(group["session_duration_seconds"].mean()),
            max_session_duration=float(group["session_duration_seconds"].max()),
            geo_deviation_score=self._geo_deviation_score(group["source_ip"]),
            burst_score=self._burst_score(group["timestamp"]),
            weekend_ratio=float((group["day_of_week"] >= 5).mean()),
            is_anomaly=int(group["is_anomaly"].max()),
        )

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        if df.empty:
            # groupby on an empty frame yields zero groups, so
            # pd.DataFrame([]) below would have no columns at all — return
            # the correct (empty) schema instead so callers like
            # AnomalyDetector.score() can safely index FEATURE_COLS.
            return pd.DataFrame(columns=list(UserProfile.__dataclass_fields__.keys()))
        df["hour"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        profiles = [
            self._profile_user(uid, grp).to_dict()
            for uid, grp in df.groupby("user_id")
        ]
        return pd.DataFrame(profiles)


def load_logs(db_path: str = "data/iam_logs.db") -> pd.DataFrame:
    """Loads from SQLite by default; set DATABASE_URL to read from Postgres/RDS instead."""
    engine = get_engine(db_path)
    df = pd.read_sql_query("SELECT * FROM iam_logs", engine)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    return FeatureExtractor().fit_transform(df)
