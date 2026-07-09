"""
CLI entry point for the IAM Anomaly Detector.

Usage:
    python main.py pipeline          # generate + train + score (end-to-end)
    python main.py generate          # generate synthetic logs
    python main.py train             # extract features and train all models
    python main.py score             # score users, persist to DynamoDB, print flagged
    python main.py insights          # run GenAI analysis on flagged users
    python main.py ingest            # pull live events from CloudWatch
    python main.py lanl [--input data/auth.txt.gz] [--limit 500000]
                                     # ingest LANL auth log dataset
    python main.py stream            # consume live events and score incrementally
    python main.py stream-simulate [count] [delay]  # publish synthetic live events
    python main.py stream-demo [count]  # end-to-end mock-mode demo (producer + consumer)
    python main.py drift             # check current traffic for model drift vs training baseline

Set CLOUD_PROVIDER=aws|gcp|mock to pick the ingestion/storage backend for
ingest/score/stream (default: aws, unchanged from before this existed).
"mock" is an explicit alias for the default local-only demo path — it
behaves identically to CLOUD_PROVIDER=aws in its default AWS_MOCK=true
configuration, since that already makes zero real AWS calls.
"""

import os
import sys
from data.log_generator import generate_logs
from features.extractor import load_logs, extract_features
from models.detector import AnomalyDetector
from aws.cloudwatch_client import ingest_to_db
from aws.dynamodb_store import DynamoDBStore
from genai.insights import analyze_batch

DB_PATH = "data/iam_logs.db"
CLOUD_PROVIDER = os.getenv("CLOUD_PROVIDER", "aws")  # aws | gcp | mock


def _get_store():
    """Returns the persistence backend for CLOUD_PROVIDER — DynamoDBStore
    (aws/mock) or FirestoreStore (gcp). Both implement the same bulk_put/
    get_flagged/get_result/put_result interface, so callers never branch."""
    if CLOUD_PROVIDER == "gcp":
        from gcp.firestore_store import FirestoreStore
        return FirestoreStore()
    return DynamoDBStore()


def _ingest():
    """Runs the ingestion backend for CLOUD_PROVIDER. gcp uses Cloud Logging
    across GCP_REGIONS; aws/mock use CloudWatch Logs Insights across
    AWS_REGIONS (mock mode by default, so this makes zero real AWS calls)."""
    if CLOUD_PROVIDER == "gcp":
        from gcp.cloud_logging_client import ingest_to_db as gcp_ingest_to_db
        return gcp_ingest_to_db(db_path=DB_PATH)
    return ingest_to_db(db_path=DB_PATH)


def cmd_generate():
    generate_logs(days=30, output_db=DB_PATH)


def cmd_train():
    raw = load_logs(DB_PATH)
    features = extract_features(raw)
    AnomalyDetector().fit(features)


def cmd_score():
    raw = load_logs(DB_PATH)
    features = extract_features(raw)
    result = AnomalyDetector.load().score(features)

    store = _get_store()
    store.bulk_put(result)

    flagged = result[result["flagged"]].sort_values("ensemble_score", ascending=False)
    print(f"\n{'='*70}")
    print(f"FLAGGED USERS  ({len(flagged)} of {len(result)} total)")
    print(f"{'='*70}")
    print(flagged[[
        "user_id", "ensemble_score", "iso_score", "svm_score", "ae_score",
        "suspicious_api_ratio", "off_hours_ratio", "burst_score",
    ]].to_string(index=False))


def cmd_insights():
    raw = load_logs(DB_PATH)
    features = extract_features(raw)
    result = AnomalyDetector.load().score(features)
    alerts = analyze_batch(result, top_n=5)
    for alert in alerts:
        print(f"\n[{alert.severity}] {alert.user_id} — {alert.attack_pattern}")
        for sig in alert.key_signals:
            print(f"  • {sig}")
        print(f"  Recommendation: {alert.recommendation}")


def cmd_pipeline():
    cmd_generate()
    cmd_train()
    cmd_score()
    cmd_insights()


def cmd_ingest():
    _ingest()


def cmd_lanl():
    from data.lanl_adapter import ingest as lanl_ingest
    gz = sys.argv[2] if len(sys.argv) > 2 else "data/auth.txt.gz"
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 500_000
    lanl_ingest(gz, DB_PATH, limit)


def cmd_stream():
    from streaming.stream_processor import StreamProcessor
    StreamProcessor(db_path=DB_PATH, store=_get_store()).run()


def cmd_stream_simulate():
    from streaming.simulate_producer import simulate
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.05
    simulate(count, delay)


def cmd_stream_demo():
    """Runs a producer + consumer in the same process against the in-memory
    mock queue, so the streaming path can be demoed with no Kafka cluster."""
    import threading
    from streaming.simulate_producer import simulate
    from streaming.stream_processor import StreamProcessor

    count = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    producer_thread = threading.Thread(target=simulate, args=(count, 0.02), daemon=True)
    producer_thread.start()

    StreamProcessor(db_path=DB_PATH, store=_get_store()).run(max_events=count)
    producer_thread.join()


def cmd_drift():
    from models import drift
    raw = load_logs(DB_PATH)
    features = extract_features(raw)
    normal = features[features["is_anomaly"] == 0]
    report = drift.check_drift(normal)
    print(f"\n{'='*70}\nMODEL DRIFT REPORT  (overall: {drift.overall_status(report)})\n{'='*70}")
    print(report.to_string(index=False))


COMMANDS = {
    "pipeline": cmd_pipeline,
    "generate": cmd_generate,
    "train": cmd_train,
    "score": cmd_score,
    "insights": cmd_insights,
    "ingest": cmd_ingest,
    "lanl": cmd_lanl,
    "stream": cmd_stream,
    "stream-simulate": cmd_stream_simulate,
    "stream-demo": cmd_stream_demo,
    "drift": cmd_drift,
}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "pipeline"
    if cmd not in COMMANDS:
        print(f"Unknown command '{cmd}'. Available: {list(COMMANDS.keys())}")
        sys.exit(1)
    COMMANDS[cmd]()
