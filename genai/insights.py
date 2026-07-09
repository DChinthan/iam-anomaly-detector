"""
GenAI security intelligence layer powered by Claude.

For each flagged user, generates a structured natural-language security alert
explaining which behavioral signals triggered the anomaly, the likely attack
pattern, and recommended remediation steps.

Set ANTHROPIC_API_KEY to enable live AI analysis.
Falls back to rule-based templates when the key is absent (demo mode).
"""

import os
from dataclasses import dataclass, asdict
from typing import Optional

import anthropic

from genai import cache as genai_cache

MOCK_MODE = not bool(os.getenv("ANTHROPIC_API_KEY"))
_CLIENT = None  # type: Optional[anthropic.Anthropic]


def _client() -> anthropic.Anthropic:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _CLIENT


@dataclass
class SecurityAlert:
    user_id: str
    severity: str          # CRITICAL / HIGH / MEDIUM
    attack_pattern: str
    key_signals: list[str]
    recommendation: str
    raw_explanation: str


def _severity(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.70:
        return "HIGH"
    return "MEDIUM"


def _build_prompt(user_row: dict) -> str:
    return f"""You are a cloud security analyst reviewing an AWS IAM anomaly detection alert.

A machine learning ensemble (Isolation Forest + One-Class SVM + TensorFlow Autoencoder) flagged
the following IAM user as anomalous based on their 30-day behavioral profile.

User: {user_row['user_id']}
Ensemble anomaly score: {user_row['ensemble_score']:.3f} (threshold: 0.65)

Behavioral features:
- Off-hours API calls: {user_row['off_hours_ratio']*100:.1f}% of activity
- Suspicious API ratio: {user_row['suspicious_api_ratio']*100:.1f}% (CreateAccessKey, GetSecretValue, etc.)
- MFA usage rate: {user_row['mfa_usage_rate']*100:.1f}%
- Unique source IPs: {int(user_row['unique_ips'])}
- Geographic deviation score: {user_row['geo_deviation_score']:.1f} unique subnets
- Burst score (max calls/30 min): {user_row['burst_score']:.0f}
- Error rate (AccessDenied etc.): {user_row['error_rate']*100:.1f}%
- Avg session duration: {user_row['avg_session_duration']:.0f}s
- Isolation Forest score: {user_row['iso_score']:.3f}
- One-Class SVM score: {user_row['svm_score']:.3f}
- Autoencoder reconstruction error: {user_row['ae_score']:.3f}

Provide a concise security analysis in this exact JSON format:
{{
  "attack_pattern": "<one-line name, e.g. Credential Harvesting / Privilege Escalation>",
  "key_signals": ["<signal 1>", "<signal 2>", "<signal 3>"],
  "recommendation": "<concrete immediate remediation steps in 2 sentences>",
  "explanation": "<3-4 sentence analyst narrative explaining why this profile is suspicious>"
}}"""


def _mock_alert(user_row: dict) -> SecurityAlert:
    """Rule-based fallback when no API key is configured."""
    signals = []
    if user_row["off_hours_ratio"] > 0.3:
        signals.append(f"Off-hours access: {user_row['off_hours_ratio']*100:.0f}% of calls outside 6am–10pm")
    if user_row["suspicious_api_ratio"] > 0.15:
        signals.append(f"High suspicious API ratio: {user_row['suspicious_api_ratio']*100:.0f}%")
    if user_row["mfa_usage_rate"] < 0.5:
        signals.append(f"Low MFA coverage: only {user_row['mfa_usage_rate']*100:.0f}% of calls authenticated with MFA")
    if user_row["burst_score"] > 30:
        signals.append(f"Burst activity detected: {user_row['burst_score']:.0f} calls in 30 min")
    if user_row["unique_ips"] > 10:
        signals.append(f"Geo deviation: {int(user_row['unique_ips'])} distinct source IPs")
    if not signals:
        signals = ["Ensemble anomaly score exceeded threshold across multiple behavioral dimensions"]

    pattern = "Credential Harvesting" if user_row["suspicious_api_ratio"] > 0.2 else \
              "Off-Hours Unauthorized Access" if user_row["off_hours_ratio"] > 0.4 else \
              "Privilege Escalation Attempt"

    recommendation = (
        "Immediately disable this user's access keys and review CloudTrail for affected resources. "
        "Enforce MFA, rotate secrets, and investigate source IPs against known threat intelligence feeds."
    )
    explanation = (
        f"User {user_row['user_id']} exhibits a behavioral profile inconsistent with legitimate activity. "
        f"The combination of {', '.join(signals[:2]).lower()} suggests {pattern.lower()}. "
        f"The ensemble anomaly score of {user_row['ensemble_score']:.2f} exceeds the detection threshold, "
        f"with all three models (IF, SVM, Autoencoder) independently flagging this user."
    )

    return SecurityAlert(
        user_id=user_row["user_id"],
        severity=_severity(user_row["ensemble_score"]),
        attack_pattern=pattern,
        key_signals=signals,
        recommendation=recommendation,
        raw_explanation=explanation,
    )


def _live_alert(user_row: dict) -> SecurityAlert:
    import json
    message = _client().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=600,
        messages=[{"role": "user", "content": _build_prompt(user_row)}],
    )
    try:
        raw = message.content[0].text
        data = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
        return SecurityAlert(
            user_id=user_row["user_id"],
            severity=_severity(user_row["ensemble_score"]),
            attack_pattern=data.get("attack_pattern", "Unknown"),
            key_signals=data.get("key_signals", []),
            recommendation=data.get("recommendation", ""),
            raw_explanation=data.get("explanation", raw),
        )
    except Exception:
        return _mock_alert(user_row)


def analyze_user(user_row: dict, use_cache: bool = True) -> SecurityAlert:
    """
    Generate a GenAI security alert for a flagged IAM user.
    Uses Claude when ANTHROPIC_API_KEY is set, otherwise uses rule-based fallback.
    Results are cached (see genai/cache.py) so repeated calls for a user whose
    score hasn't materially changed don't re-hit the Claude API.
    """
    score = user_row["ensemble_score"]
    if use_cache:
        cached = genai_cache.get(user_row["user_id"], score)
        if cached is not None:
            return SecurityAlert(**cached)

    alert = _mock_alert(user_row) if MOCK_MODE else _live_alert(user_row)

    if use_cache:
        genai_cache.put(user_row["user_id"], score, asdict(alert))
    return alert


def analyze_batch(scored_df, top_n: int = 5) -> list[SecurityAlert]:
    """Analyze the top_n highest-scoring flagged users."""
    flagged = (
        scored_df[scored_df["flagged"]]
        .sort_values("ensemble_score", ascending=False)
        .head(top_n)
    )
    return [analyze_user(row) for _, row in flagged.iterrows()]
