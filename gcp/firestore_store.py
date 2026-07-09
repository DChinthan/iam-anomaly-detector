"""
NoSQL storage layer for IAM anomaly results using GCP Firestore.

Persists scored user profiles and generated alerts so they can be queried
across sessions without re-running the ML pipeline. Mirrors
aws/dynamodb_store.py's public method signatures exactly (put_result,
get_result, get_flagged, bulk_put) so main.py's CLOUD_PROVIDER routing can
swap stores without touching any call site.

Set GCP_MOCK=true (default) to use a local JSON file as a Firestore stand-in.
"""

import os
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

MOCK_MODE = os.getenv("GCP_MOCK", "true").lower() == "true"
MOCK_FILE = Path("data/firestore_mock.json")
COLLECTION_NAME = os.getenv("FIRESTORE_COLLECTION", "iam-anomaly-results")


def _load_mock() -> dict:
    if MOCK_FILE.exists():
        return json.loads(MOCK_FILE.read_text())
    return {"Items": []}


def _save_mock(store: dict):
    MOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    MOCK_FILE.write_text(json.dumps(store, indent=2))


def _get_collection():
    from google.cloud import firestore
    client = firestore.Client(project=os.getenv("GCP_PROJECT"))
    return client.collection(COLLECTION_NAME)


class FirestoreStore:
    """
    Document store for IAM anomaly detection results.
    Document ID: user_id
    Queryable field: analysis_timestamp
    """

    def put_result(self, user_id: str, result: dict) -> None:
        """Persist a scored user profile to the NoSQL store."""
        item = {
            "user_id": user_id,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            **{k: str(v) if isinstance(v, float) else v for k, v in result.items()},
        }
        if MOCK_MODE:
            store = _load_mock()
            store["Items"] = [i for i in store["Items"] if i["user_id"] != user_id]
            store["Items"].append(item)
            _save_mock(store)
        else:
            _get_collection().document(user_id).set(item)

    def get_result(self, user_id: str) -> Optional[dict]:
        """Retrieve latest result for a user."""
        if MOCK_MODE:
            store = _load_mock()
            matches = [i for i in store["Items"] if i["user_id"] == user_id]
            return max(matches, key=lambda x: x["analysis_timestamp"]) if matches else None
        else:
            doc = _get_collection().document(user_id).get()
            return doc.to_dict() if doc.exists else None

    def get_flagged(self) -> list[dict]:
        """Return all currently flagged users."""
        if MOCK_MODE:
            store = _load_mock()
            return [i for i in store["Items"] if i.get("flagged") is True]
        else:
            docs = _get_collection().where("flagged", "==", True).stream()
            return [doc.to_dict() for doc in docs]

    def bulk_put(self, scored_df) -> int:
        """Persist entire scored DataFrame to Firestore."""
        count = 0
        for _, row in scored_df.iterrows():
            self.put_result(
                row["user_id"],
                {
                    "ensemble_score": float(row["ensemble_score"]),
                    "iso_score": float(row["iso_score"]),
                    "svm_score": float(row["svm_score"]),
                    "ae_score": float(row["ae_score"]),
                    "flagged": bool(row["flagged"]),
                    "off_hours_ratio": float(row["off_hours_ratio"]),
                    "suspicious_api_ratio": float(row["suspicious_api_ratio"]),
                    "burst_score": float(row["burst_score"]),
                },
            )
            count += 1
        mode = "mock JSON" if MOCK_MODE else f"Firestore ({COLLECTION_NAME})"
        print(f"Persisted {count} user results to {mode}")
        return count
