"""
Ensemble anomaly detector: Isolation Forest + One-Class SVM + TF Autoencoder.

All three models are trained on normal user profiles only (unsupervised).
Final ensemble score is a weighted combination of the three signals.
"""

import numpy as np
import pandas as pd
import pickle
from pathlib import Path
from typing import Optional
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from features.extractor import FEATURE_COLS
from models.autoencoder import IAMAutoencoder
from models import drift

MODEL_PATH = Path("models/saved/ensemble.pkl")
AE_AVAILABLE = True


class AnomalyDetector:
    """
    Production-grade ensemble detector combining three complementary
    unsupervised algorithms:
      - IsolationForest: tree-based, fast, handles high-dim well
      - OneClassSVM: kernel-based, captures non-linear decision boundaries
      - IAMAutoencoder: deep reconstruction error, learns temporal patterns
    """

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self._iso: Optional[Pipeline] = None
        self._svm: Optional[Pipeline] = None
        self._ae: Optional[IAMAutoencoder] = None

    def _make_pipeline(self, model) -> Pipeline:
        return Pipeline([
            ("scaler", StandardScaler()),
            ("model", model),
        ])

    def fit(self, features_df: pd.DataFrame) -> "AnomalyDetector":
        normal = features_df[features_df["is_anomaly"] == 0]
        X = normal[FEATURE_COLS].fillna(0).values

        self._iso = self._make_pipeline(
            IsolationForest(
                n_estimators=300,
                contamination=self.contamination,
                random_state=42,
            )
        )
        self._svm = self._make_pipeline(
            OneClassSVM(kernel="rbf", nu=self.contamination, gamma="scale")
        )

        self._iso.fit(X)
        self._svm.fit(X)

        self._ae = IAMAutoencoder(latent_dim=4, epochs=80)
        self._ae.fit(X)

        self.save()
        drift.save_baseline(features_df)
        print(f"Ensemble trained on {len(X)} normal user profiles")
        return self

    def score(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Adds iso_score, svm_score, ae_score, ensemble_score, flagged columns."""
        X = features_df[FEATURE_COLS].fillna(0).values

        iso_raw = self._iso.decision_function(X)
        iso_scores = 1 - self._normalize(iso_raw)

        svm_raw = self._svm.decision_function(X)
        svm_scores = 1 - self._normalize(svm_raw)

        ae_scores = self._ae.anomaly_scores(X)
        ae_raw_errors = self._ae.raw_reconstruction_errors(X)
        ae_threshold_exceeded = ae_raw_errors > self._ae.threshold

        ensemble = iso_scores * 0.40 + svm_scores * 0.30 + ae_scores * 0.30
        flagged = ensemble > 0.65

        result = features_df.copy()
        result["iso_score"] = iso_scores
        result["svm_score"] = svm_scores
        result["ae_score"] = ae_scores
        result["ensemble_score"] = ensemble
        result["flagged"] = flagged
        # Secondary confirmation signal: the autoencoder's own 95th-percentile
        # reconstruction-error threshold from training, independent of the
        # ensemble's 0.65 cutoff. Agreement between the two raises confidence
        # that a flagged user is a true anomaly rather than a borderline score.
        result["ae_threshold_exceeded"] = ae_threshold_exceeded
        result["confidence"] = np.select(
            [flagged & ae_threshold_exceeded, flagged],
            ["CONFIRMED", "SUSPECTED"],
            default="CLEAR",
        )
        return result

    @staticmethod
    def _normalize(arr: np.ndarray) -> np.ndarray:
        lo, hi = arr.min(), arr.max()
        return (arr - lo) / (hi - lo + 1e-9)

    def save(self):
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({"iso": self._iso, "svm": self._svm}, f)
        self._ae.save()

    @classmethod
    def load(cls) -> "AnomalyDetector":
        instance = cls()
        with open(MODEL_PATH, "rb") as f:
            models = pickle.load(f)
        instance._iso = models["iso"]
        instance._svm = models["svm"]
        instance._ae = IAMAutoencoder.load()
        return instance


# Module-level convenience wrappers kept for backward compatibility

def train(features_df: pd.DataFrame) -> AnomalyDetector:
    detector = AnomalyDetector()
    detector.fit(features_df)
    return detector


def score(features_df: pd.DataFrame, detector: AnomalyDetector = None) -> pd.DataFrame:
    if detector is None:
        detector = AnomalyDetector.load()
    return detector.score(features_df)
