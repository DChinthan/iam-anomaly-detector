"""
TTL cache for GenAI security alerts.

Claude calls cost money and add latency, and the Streamlit dashboard calls
analyze_batch() on every rerun (slider drag, page refresh, etc.) — without a
cache, the same 5 flagged users get re-analyzed by Claude repeatedly even
when their scores haven't changed. Entries are keyed on (user_id, score
bucket) so a materially different score still busts the cache, but small
score jitter between pipeline runs doesn't trigger a needless API call.
"""
import json
import time
from pathlib import Path
from typing import Optional

CACHE_PATH = Path("data/genai_cache.json")
TTL_SECONDS = 60 * 60   # re-analyze after an hour even if the score bucket is unchanged
SCORE_BUCKET = 0.05     # scores within this band are treated as "the same" for caching


def _load() -> dict:
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text())
    return {}


def _save(cache: dict) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2))


def _key(user_id: str, score: float) -> str:
    bucket = round(score / SCORE_BUCKET) * SCORE_BUCKET
    return f"{user_id}:{bucket:.2f}"


def get(user_id: str, score: float) -> Optional[dict]:
    entry = _load().get(_key(user_id, score))
    if entry and (time.time() - entry["cached_at"]) < TTL_SECONDS:
        return entry["alert"]
    return None


def put(user_id: str, score: float, alert: dict) -> None:
    cache = _load()
    cache[_key(user_id, score)] = {"cached_at": time.time(), "alert": alert}
    _save(cache)


def clear() -> None:
    if CACHE_PATH.exists():
        CACHE_PATH.unlink()
