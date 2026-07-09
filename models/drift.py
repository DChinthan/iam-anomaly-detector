"""
Model drift detection for the IAM anomaly ensemble.

Real-world IAM behavior shifts over time (new tools, new regions, org
growth) — if the ensemble's notion of "normal" goes stale, it silently
starts producing more false positives/negatives. This module snapshots the
training-time normal feature distribution and compares freshly scored
"known normal" traffic against it using Population Stability Index (PSI)
and a Kolmogorov-Smirnov test, per feature.

Typical usage:
    from models.drift import save_baseline, check_drift
    save_baseline(features_df)          # called once, right after AnomalyDetector.fit()
    report = check_drift(recent_normal_features_df)   # run periodically (e.g. daily cron)
"""
import json
import numpy as np
import pandas as pd
from pathlib import Path
from scipy import stats

from features.extractor import FEATURE_COLS

BASELINE_PATH = Path("models/saved/drift_baseline.json")

PSI_WARN = 0.10    # PSI > 0.10  -> moderate drift, keep an eye on it
PSI_ALERT = 0.25   # PSI > 0.25  -> significant drift, consider retraining


def save_baseline(features_df: pd.DataFrame) -> None:
    """Snapshots the training-time normal distribution for later drift comparison."""
    normal = features_df[features_df["is_anomaly"] == 0]
    baseline = {col: normal[col].tolist() for col in FEATURE_COLS}
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(json.dumps(baseline))


def has_baseline() -> bool:
    return BASELINE_PATH.exists()


def _psi(expected: np.ndarray, actual: np.ndarray, bins: int = 10) -> float:
    """Population Stability Index between two 1-D distributions."""
    edges = np.histogram_bin_edges(expected, bins=bins)
    exp_counts = np.histogram(expected, bins=edges)[0] / max(len(expected), 1)
    act_counts = np.histogram(actual, bins=edges)[0] / max(len(actual), 1)
    exp_counts = np.clip(exp_counts, 1e-4, None)
    act_counts = np.clip(act_counts, 1e-4, None)
    return float(np.sum((act_counts - exp_counts) * np.log(act_counts / exp_counts)))


def check_drift(current_normal_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compares current "known normal" traffic against the saved training baseline.
    Returns one row per feature with PSI, KS statistic, and a status verdict.
    """
    if not has_baseline():
        raise FileNotFoundError(
            "No drift baseline found — call save_baseline() once after training."
        )
    baseline = json.loads(BASELINE_PATH.read_text())

    rows = []
    for col in FEATURE_COLS:
        expected = np.array(baseline[col])
        actual = current_normal_df[col].to_numpy()
        if len(expected) == 0 or len(actual) == 0:
            continue
        psi = _psi(expected, actual)
        ks_stat, ks_pvalue = stats.ks_2samp(expected, actual)
        status = "ALERT" if psi > PSI_ALERT else "WARN" if psi > PSI_WARN else "OK"
        rows.append({
            "feature": col,
            "psi": round(psi, 4),
            "ks_stat": round(float(ks_stat), 4),
            "ks_pvalue": round(float(ks_pvalue), 4),
            "status": status,
        })
    return pd.DataFrame(rows).sort_values("psi", ascending=False).reset_index(drop=True)


def overall_status(report: pd.DataFrame) -> str:
    if (report["status"] == "ALERT").any():
        return "ALERT"
    if (report["status"] == "WARN").any():
        return "WARN"
    return "OK"
