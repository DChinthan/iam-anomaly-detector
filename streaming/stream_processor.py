"""
Incremental anomaly scoring over a live event stream.

Replaces the batch generate -> train -> score cycle for real-time monitoring:
events arrive one at a time from Kafka/Kinesis (or the in-memory mock),
get appended to the durable store, and any user whose rolling window
changed gets rescored against the already-trained ensemble. The ensemble
itself is still trained offline/batch (models/detector.py) — this module
only handles *inference* on the live path, which is the realistic split
for a streaming security pipeline.

Run with: python main.py stream
"""
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Optional

import pandas as pd

from streaming.event_stream import EventStreamConsumer
from data.db import get_engine, insert_events
from features.extractor import FeatureExtractor
from models.detector import AnomalyDetector
from aws.dynamodb_store import DynamoDBStore

DB_PATH = "data/iam_logs.db"
WINDOW_SIZE = 500     # events retained per user for rolling scoring
RESCORE_EVERY = 20    # rescore dirty users after this many new events


class StreamProcessor:
    """Consumes events, maintains a per-user rolling window, and rescores
    incrementally instead of re-running the full batch pipeline."""

    def __init__(self, db_path: str = DB_PATH, window_size: int = WINDOW_SIZE, store=None):
        """`store` defaults to DynamoDBStore (unchanged behavior) but accepts
        any object implementing bulk_put(scored_df) — e.g. gcp.firestore_store.
        FirestoreStore — so main.py's CLOUD_PROVIDER routing can swap the
        persistence backend without this class knowing which cloud it's on."""
        self.db_path = db_path
        self.window_size = window_size
        self._engine = get_engine(db_path)
        self._buffers: Dict[str, Deque[dict]] = defaultdict(lambda: deque(maxlen=window_size))
        self._detector = AnomalyDetector.load()
        self._store = store if store is not None else DynamoDBStore()
        self._extractor = FeatureExtractor()
        self._dirty_users: set = set()

    def _ingest(self, event: dict) -> None:
        event.setdefault("is_anomaly", 0)
        self._buffers[event["user_id"]].append(event)
        self._dirty_users.add(event["user_id"])
        insert_events(self._engine, [event])

    def _rescore_dirty(self) -> pd.DataFrame:
        if not self._dirty_users:
            return pd.DataFrame()
        rows = []
        for user_id in self._dirty_users:
            rows.extend(self._buffers[user_id])
        df = pd.DataFrame(rows)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        features = self._extractor.fit_transform(df)
        scored = self._detector.score(features)
        self._store.bulk_put(scored)
        self._dirty_users.clear()
        return scored

    def run(
        self,
        consumer: Optional[EventStreamConsumer] = None,
        max_events: Optional[int] = None,
        on_alert: Optional[Callable[[pd.Series], None]] = None,
    ) -> int:
        """Blocks and scores events as they arrive. Returns events processed.
        Pass max_events for a bounded run (tests, demos); omit for a
        long-running consumer loop."""
        consumer = consumer or EventStreamConsumer()
        processed = 0
        idle_polls = 0
        try:
            while max_events is None or processed < max_events:
                event = consumer.poll(timeout=1.0)
                if event is None:
                    idle_polls += 1
                    if max_events is not None and idle_polls > max_events:
                        break
                    continue
                idle_polls = 0
                self._ingest(event)
                processed += 1
                if processed % RESCORE_EVERY == 0 or processed == max_events:
                    self._emit_alerts(on_alert)
            if self._dirty_users:
                self._emit_alerts(on_alert)
        finally:
            consumer.close()
        return processed

    def _emit_alerts(self, on_alert) -> None:
        scored = self._rescore_dirty()
        if scored.empty:
            return
        for _, row in scored[scored["flagged"]].iterrows():
            if on_alert:
                on_alert(row)
            else:
                print(
                    f"[STREAM ALERT] {row['user_id']} "
                    f"ensemble_score={row['ensemble_score']:.3f} "
                    f"confidence={row['confidence']}"
                )
