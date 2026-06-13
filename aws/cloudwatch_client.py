"""
CloudWatch log ingestion layer.
Fetches IAM/CloudTrail events from CloudWatch Logs Insights and
normalises them into the same schema used by the local SQLite store.
Set AWS_MOCK=true (default) to use synthetic data without real AWS creds.
"""

import os
import json
import random
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

MOCK_MODE = os.getenv("AWS_MOCK", "true").lower() == "true"


def _get_boto_client():
    import boto3
    return boto3.client(
        "logs",
        region_name=os.getenv("AWS_REGION", "us-east-1"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )


def _mock_cloudwatch_events(limit: int = 500) -> list[dict]:
    """Returns mock CloudTrail events shaped like CloudWatch Logs Insights results."""
    api_calls = [
        "GetObject", "PutObject", "ListBuckets", "DescribeInstances",
        "GetUser", "ListRoles", "GetPolicy", "CreateAccessKey",
        "GetSecretValue", "AssumeRole",
    ]
    ips = ["10.0.0.{}".format(i) for i in range(1, 30)]
    users = ["user_{:03d}".format(i) for i in range(1, 11)]
    now = datetime.utcnow()

    events = []
    for _ in range(limit):
        ts = now - timedelta(hours=random.randint(0, 72))
        events.append({
            "timestamp": ts.isoformat(),
            "user_id": random.choice(users),
            "source_ip": random.choice(ips),
            "api_call": random.choice(api_calls),
            "region": random.choice(["us-east-1", "us-west-2"]),
            "session_duration_seconds": random.randint(60, 3600),
            "mfa_used": int(random.random() > 0.15),
            "error_code": None,
        })
    return events


def _real_cloudwatch_events(log_group: str, hours: int = 24) -> list[dict]:
    client = _get_boto_client()
    end_ms = int(datetime.utcnow().timestamp() * 1000)
    start_ms = end_ms - hours * 3600 * 1000

    query = """
        fields @timestamp, userIdentity.userName as user_id,
               sourceIPAddress as source_ip, eventName as api_call,
               awsRegion as region, errorCode as error_code
        | filter eventSource = 'iam.amazonaws.com' or eventSource = 's3.amazonaws.com'
        | sort @timestamp desc
        | limit 10000
    """
    resp = client.start_query(
        logGroupName=log_group,
        startTime=start_ms,
        endTime=end_ms,
        queryString=query,
    )
    query_id = resp["queryId"]

    import time
    while True:
        result = client.get_query_results(queryId=query_id)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(1)

    events = []
    for row in result.get("results", []):
        record = {f["field"]: f["value"] for f in row}
        events.append({
            "timestamp": record.get("@timestamp", datetime.utcnow().isoformat()),
            "user_id": record.get("user_id", "unknown"),
            "source_ip": record.get("source_ip", "0.0.0.0"),
            "api_call": record.get("api_call", "Unknown"),
            "region": record.get("region", "us-east-1"),
            "session_duration_seconds": random.randint(60, 3600),
            "mfa_used": 0,
            "error_code": record.get("error_code") or None,
        })
    return events


def ingest_to_db(
    db_path: str = "data/iam_logs.db",
    log_group: Optional[str] = None,
    hours: int = 24,
) -> int:
    if MOCK_MODE:
        events = _mock_cloudwatch_events()
    else:
        events = _real_cloudwatch_events(log_group or "/aws/cloudtrail/events", hours)

    conn = sqlite3.connect(db_path)
    inserted = 0
    for e in events:
        conn.execute(
            "INSERT INTO iam_logs (timestamp, user_id, source_ip, api_call, region, "
            "session_duration_seconds, mfa_used, error_code) VALUES (?,?,?,?,?,?,?,?)",
            (e["timestamp"], e["user_id"], e["source_ip"], e["api_call"],
             e["region"], e["session_duration_seconds"], e["mfa_used"], e["error_code"]),
        )
        inserted += 1
    conn.commit()
    conn.close()
    print(f"Ingested {inserted} events from {'mock' if MOCK_MODE else 'CloudWatch'}")
    return inserted
