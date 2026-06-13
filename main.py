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
"""

import sys
from data.log_generator import generate_logs
from features.extractor import load_logs, extract_features
from models.detector import AnomalyDetector
from aws.cloudwatch_client import ingest_to_db
from aws.dynamodb_store import DynamoDBStore
from genai.insights import analyze_batch

DB_PATH = "data/iam_logs.db"


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

    store = DynamoDBStore()
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
    ingest_to_db(db_path=DB_PATH)


def cmd_lanl():
    from data.lanl_adapter import ingest as lanl_ingest
    gz = sys.argv[2] if len(sys.argv) > 2 else "data/auth.txt.gz"
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 500_000
    lanl_ingest(gz, DB_PATH, limit)


COMMANDS = {
    "pipeline": cmd_pipeline,
    "generate": cmd_generate,
    "train": cmd_train,
    "score": cmd_score,
    "insights": cmd_insights,
    "ingest": cmd_ingest,
    "lanl": cmd_lanl,
}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "pipeline"
    if cmd not in COMMANDS:
        print(f"Unknown command '{cmd}'. Available: {list(COMMANDS.keys())}")
        sys.exit(1)
    COMMANDS[cmd]()
