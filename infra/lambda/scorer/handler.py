"""
Lambda entry point for scheduled batch scoring in production.

Pulls recent events from CloudWatch across every configured region,
extracts features, scores with the pre-trained ensemble, and persists
results to DynamoDB — the same steps as `python main.py ingest && python
main.py score`, packaged for EventBridge-triggered execution
(see infra/terraform/lambda.tf).
"""
import sys

sys.path.insert(0, "/var/task")  # project root is bundled alongside this handler

# The Lambda base image's system SQLite is older than 3.8.3 — too old for
# SQLAlchemy's sqlite dialect, which needs it (see Dockerfile). Swap in
# pysqlite3-binary's bundled modern SQLite before anything imports sqlite3.
__import__("pysqlite3")
sys.modules["sqlite3"] = sys.modules.pop("pysqlite3")

from aws.cloudwatch_client import ingest_to_db
from features.extractor import load_logs, extract_features
from models.detector import AnomalyDetector
from aws.dynamodb_store import DynamoDBStore

DB_PATH = "/tmp/iam_logs.db"  # Lambda's only writable path outside /var/task


def handler(event, context):
    ingest_to_db(db_path=DB_PATH)
    raw = load_logs(DB_PATH)
    features = extract_features(raw)

    detector = AnomalyDetector.load()
    scored = detector.score(features)

    store = DynamoDBStore()
    count = store.bulk_put(scored)

    flagged = scored[scored["flagged"]]
    return {
        "usersScored": count,
        "usersFlagged": int(len(flagged)),
        "flaggedUserIds": flagged["user_id"].tolist(),
    }
