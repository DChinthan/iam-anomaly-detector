"""
CLI entry point.

Usage:
    python main.py generate          # generate synthetic logs
    python main.py train             # extract features and train models
    python main.py score             # score all users, print flagged ones
    python main.py pipeline          # run all steps end-to-end
    python main.py ingest            # pull from CloudWatch (or mock)
"""

import sys
from data.log_generator import generate_logs
from features.extractor import load_logs, extract_features
from models.detector import train, score
from aws.cloudwatch_client import ingest_to_db

DB_PATH = "data/iam_logs.db"


def cmd_generate():
    generate_logs(days=30, output_db=DB_PATH)


def cmd_train():
    raw = load_logs(DB_PATH)
    features = extract_features(raw)
    train(features)


def cmd_score():
    raw = load_logs(DB_PATH)
    features = extract_features(raw)
    result = score(features)
    flagged = result[result["flagged"]].sort_values("ensemble_score", ascending=False)
    print(f"\n{'='*60}")
    print(f"FLAGGED USERS ({len(flagged)} of {len(result)} total)")
    print(f"{'='*60}")
    print(flagged[["user_id", "ensemble_score", "suspicious_api_ratio",
                    "off_hours_ratio", "burst_score"]].to_string(index=False))


def cmd_pipeline():
    cmd_generate()
    cmd_train()
    cmd_score()


def cmd_ingest():
    ingest_to_db(db_path=DB_PATH)


COMMANDS = {
    "generate": cmd_generate,
    "train": cmd_train,
    "score": cmd_score,
    "pipeline": cmd_pipeline,
    "ingest": cmd_ingest,
}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "pipeline"
    if cmd not in COMMANDS:
        print(f"Unknown command: {cmd}. Available: {list(COMMANDS.keys())}")
        sys.exit(1)
    COMMANDS[cmd]()
