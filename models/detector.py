"""
Ensemble anomaly detector combining Isolation Forest and One-Class SVM.
Both models are trained on normal-user behavior only (unsupervised),
then score every user at inference time.
"""

import numpy as np
import pandas as pd
import pickle
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from features.extractor import FEATURE_COLS


MODEL_PATH = Path("models/saved/ensemble.pkl")


def _build_pipeline(model):
    return Pipeline([
        ("scaler", StandardScaler()),
        ("model", model),
    ])


def train(features_df: pd.DataFrame) -> dict:
    """
    Train on normal users only. Returns trained pipelines + scaler.
    Labels: 1 = anomaly, 0 = normal (from ground truth column).
    """
    normal_df = features_df[features_df["is_anomaly"] == 0]
    X_train = normal_df[FEATURE_COLS].fillna(0).values

    iso_pipeline = _build_pipeline(
        IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    )
    svm_pipeline = _build_pipeline(
        OneClassSVM(kernel="rbf", nu=0.05, gamma="scale")
    )

    iso_pipeline.fit(X_train)
    svm_pipeline.fit(X_train)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"iso": iso_pipeline, "svm": svm_pipeline}, f)

    print(f"Models trained on {len(X_train)} normal users -> {MODEL_PATH}")
    return {"iso": iso_pipeline, "svm": svm_pipeline}


def load_models() -> dict:
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def score(features_df: pd.DataFrame, models: dict = None) -> pd.DataFrame:
    """
    Returns features_df with added anomaly score columns.
    Scores are normalized to [0, 1] where higher = more anomalous.
    """
    if models is None:
        models = load_models()

    X = features_df[FEATURE_COLS].fillna(0).values

    # IsolationForest: decision_function returns negative = anomaly
    iso_raw = models["iso"].decision_function(X)
    iso_scores = 1 - (iso_raw - iso_raw.min()) / (iso_raw.max() - iso_raw.min() + 1e-9)

    # One-Class SVM: decision_function returns negative = anomaly
    svm_raw = models["svm"].decision_function(X)
    svm_scores = 1 - (svm_raw - svm_raw.min()) / (svm_raw.max() - svm_raw.min() + 1e-9)

    result = features_df.copy()
    result["iso_score"] = iso_scores
    result["svm_score"] = svm_scores
    result["ensemble_score"] = (iso_scores * 0.6 + svm_scores * 0.4)
    result["flagged"] = result["ensemble_score"] > 0.65
    return result
