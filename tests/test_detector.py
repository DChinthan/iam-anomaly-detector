"""Tests for AnomalyDetector ensemble and IAMAutoencoder."""

import pytest
import numpy as np
import pandas as pd
from features.extractor import FEATURE_COLS


def _make_features(n_normal=30, n_anomalous=5, seed=42) -> pd.DataFrame:
    """Minimal synthetic feature frame — no DB required."""
    rng = np.random.default_rng(seed)

    normal = pd.DataFrame({
        "user_id": [f"n{i}" for i in range(n_normal)],
        "total_api_calls": rng.integers(20, 80, n_normal),
        "unique_ips": rng.integers(1, 5, n_normal),
        "unique_regions": rng.integers(1, 3, n_normal),
        "off_hours_ratio": rng.uniform(0.0, 0.05, n_normal),
        "mfa_usage_rate": rng.uniform(0.85, 1.0, n_normal),
        "error_rate": rng.uniform(0.0, 0.05, n_normal),
        "suspicious_api_ratio": rng.uniform(0.0, 0.05, n_normal),
        "avg_session_duration": rng.uniform(300, 1800, n_normal),
        "max_session_duration": rng.uniform(1800, 3600, n_normal),
        "geo_deviation_score": rng.uniform(1, 3, n_normal),
        "burst_score": rng.uniform(1, 10, n_normal),
        "weekend_ratio": rng.uniform(0.0, 0.3, n_normal),
        "is_anomaly": [0] * n_normal,
    })

    anomalous = pd.DataFrame({
        "user_id": [f"a{i}" for i in range(n_anomalous)],
        "total_api_calls": rng.integers(200, 500, n_anomalous),
        "unique_ips": rng.integers(15, 30, n_anomalous),
        "unique_regions": rng.integers(3, 5, n_anomalous),
        "off_hours_ratio": rng.uniform(0.7, 1.0, n_anomalous),
        "mfa_usage_rate": rng.uniform(0.0, 0.1, n_anomalous),
        "error_rate": rng.uniform(0.3, 0.8, n_anomalous),
        "suspicious_api_ratio": rng.uniform(0.5, 1.0, n_anomalous),
        "avg_session_duration": rng.uniform(7200, 86400, n_anomalous),
        "max_session_duration": rng.uniform(86400, 172800, n_anomalous),
        "geo_deviation_score": rng.uniform(10, 20, n_anomalous),
        "burst_score": rng.uniform(80, 150, n_anomalous),
        "weekend_ratio": rng.uniform(0.7, 1.0, n_anomalous),
        "is_anomaly": [1] * n_anomalous,
    })

    return pd.concat([normal, anomalous], ignore_index=True)


class TestAnomalyDetector:
    @pytest.fixture(scope="class")
    def trained(self, tmp_path_factory):
        from models.detector import AnomalyDetector
        import os
        # Point saved models to a temp dir so tests don't pollute the repo
        tmp = tmp_path_factory.mktemp("models")
        import models.detector as det_mod
        import models.autoencoder as ae_mod
        original_det = det_mod.MODEL_PATH
        original_ae = ae_mod.MODEL_PATH
        original_sc = ae_mod.SCALER_PATH
        det_mod.MODEL_PATH = tmp / "ensemble.pkl"
        ae_mod.MODEL_PATH = tmp / "autoencoder.keras"
        ae_mod.SCALER_PATH = tmp / "ae_scaler.pkl"

        features = _make_features()
        detector = AnomalyDetector()
        detector.fit(features)
        scored = detector.score(features)

        yield scored, features

        det_mod.MODEL_PATH = original_det
        ae_mod.MODEL_PATH = original_ae
        ae_mod.SCALER_PATH = original_sc

    def test_score_columns_present(self, trained):
        scored, _ = trained
        for col in ["iso_score", "svm_score", "ae_score", "ensemble_score", "flagged"]:
            assert col in scored.columns

    def test_scores_in_zero_one_range(self, trained):
        scored, _ = trained
        for col in ["iso_score", "svm_score", "ae_score", "ensemble_score"]:
            assert scored[col].between(0, 1).all(), f"{col} out of [0,1]"

    def test_anomalous_users_score_higher_than_normal(self, trained):
        scored, _ = trained
        mean_normal = scored[scored["is_anomaly"] == 0]["ensemble_score"].mean()
        mean_anomalous = scored[scored["is_anomaly"] == 1]["ensemble_score"].mean()
        assert mean_anomalous > mean_normal

    def test_at_least_one_anomaly_flagged(self, trained):
        scored, _ = trained
        flagged_anomalies = scored[(scored["flagged"]) & (scored["is_anomaly"] == 1)]
        assert len(flagged_anomalies) >= 1

    def test_row_count_preserved(self, trained):
        scored, features = trained
        assert len(scored) == len(features)

    def test_flagged_is_boolean(self, trained):
        scored, _ = trained
        assert scored["flagged"].dtype == bool
