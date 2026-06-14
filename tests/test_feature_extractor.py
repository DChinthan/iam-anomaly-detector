"""Tests for the FeatureExtractor and UserProfile classes."""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from features.extractor import FeatureExtractor, UserProfile, FEATURE_COLS, SUSPICIOUS_APIS


def _make_log_df(events: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["is_anomaly"] = df.get("is_anomaly", 0)
    return df


def _base_event(user="u001", hour=10, api="GetObject", ip="10.0.0.1",
                mfa=1, error=None, ts_offset_days=0):
    ts = datetime(2024, 1, 1, hour, 0, 0) + timedelta(days=ts_offset_days)
    return {
        "timestamp": ts.isoformat(),
        "user_id": user,
        "source_ip": ip,
        "api_call": api,
        "region": "us-east-1",
        "session_duration_seconds": 300,
        "mfa_used": mfa,
        "error_code": error,
        "is_anomaly": 0,
    }


class TestUserProfile:
    def test_to_dict_includes_all_feature_cols(self):
        profile = UserProfile(user_id="u001")
        d = profile.to_dict()
        for col in FEATURE_COLS:
            assert col in d, f"Missing feature column: {col}"

    def test_default_values_are_zero(self):
        profile = UserProfile(user_id="u001")
        assert profile.total_api_calls == 0
        assert profile.off_hours_ratio == 0.0


class TestFeatureExtractor:
    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_output_has_one_row_per_user(self):
        events = [_base_event(user="u001"), _base_event(user="u002")]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert len(result) == 2
        assert set(result["user_id"]) == {"u001", "u002"}

    def test_total_api_calls_counted_correctly(self):
        events = [_base_event(user="u001") for _ in range(7)]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert result.iloc[0]["total_api_calls"] == 7

    def test_off_hours_ratio_all_business_hours(self):
        events = [_base_event(hour=h) for h in range(8, 18)]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert result.iloc[0]["off_hours_ratio"] == 0.0

    def test_off_hours_ratio_all_off_hours(self):
        events = [_base_event(hour=h) for h in [0, 1, 2, 3, 23]]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert result.iloc[0]["off_hours_ratio"] == 1.0

    def test_mfa_usage_rate(self):
        events = [_base_event(mfa=1)] * 3 + [_base_event(mfa=0)] * 1
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert abs(result.iloc[0]["mfa_usage_rate"] - 0.75) < 1e-6

    def test_suspicious_api_ratio_zero_for_normal_apis(self):
        events = [_base_event(api="GetObject"), _base_event(api="ListBuckets")]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert result.iloc[0]["suspicious_api_ratio"] == 0.0

    def test_suspicious_api_ratio_nonzero_for_suspicious(self):
        events = [_base_event(api="CreateAccessKey"), _base_event(api="GetObject")]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert result.iloc[0]["suspicious_api_ratio"] == 0.5

    def test_error_rate(self):
        events = [_base_event(error="AccessDenied")] * 2 + [_base_event(error=None)] * 8
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert abs(result.iloc[0]["error_rate"] - 0.2) < 1e-6

    def test_unique_ips(self):
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        events = [_base_event(ip=ip) for ip in ips]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert result.iloc[0]["unique_ips"] == 3

    def test_geo_deviation_different_subnets(self):
        events = [
            _base_event(ip="10.0.1.1"),
            _base_event(ip="10.0.2.1"),
            _base_event(ip="192.168.1.1"),
        ]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert result.iloc[0]["geo_deviation_score"] == 3.0

    def test_burst_score_detected(self):
        # 20 events within 10 minutes = should produce high burst score
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [{
            "timestamp": (base + timedelta(minutes=i * 0.4)).isoformat(),
            "user_id": "u001",
            "source_ip": "10.0.0.1",
            "api_call": "GetObject",
            "region": "us-east-1",
            "session_duration_seconds": 60,
            "mfa_used": 1,
            "error_code": None,
            "is_anomaly": 0,
        } for i in range(20)]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert result.iloc[0]["burst_score"] >= 20

    def test_feature_cols_all_present(self):
        events = [_base_event() for _ in range(5)]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        for col in FEATURE_COLS:
            assert col in result.columns

    def test_no_nan_in_output(self):
        events = [_base_event() for _ in range(5)]
        df = _make_log_df(events)
        result = self.extractor.fit_transform(df)
        assert not result[FEATURE_COLS].isnull().any().any()
