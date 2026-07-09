"""
Generates synthetic AWS IAM CloudTrail-style logs with realistic patterns
and injected anomalies for training and demo purposes.
"""

import random
import json
from datetime import datetime, timedelta
from pathlib import Path

from data.db import get_engine, insert_events

NORMAL_USERS = [f"user_{i:03d}" for i in range(1, 51)]
ANOMALOUS_USERS = [f"user_{i:03d}" for i in range(51, 56)]

NORMAL_IPS = [
    "192.168.1.{}".format(i) for i in range(1, 30)
] + [
    "10.0.0.{}".format(i) for i in range(1, 20)
]

SUSPICIOUS_IPS = (
    ["45.33.32.{}".format(i) for i in range(100, 110)]
    + ["185.220.101.{}".format(i) for i in range(1, 5)]
)

AWS_API_CALLS = {
    "normal": [
        "GetObject", "PutObject", "ListBuckets", "DescribeInstances",
        "GetUser", "ListRoles", "GetPolicy", "DescribeSecurityGroups",
    ],
    "suspicious": [
        "CreateAccessKey", "AttachUserPolicy", "CreateUser",
        "PutUserPolicy", "DeleteTrail", "StopLogging",
        "GetSecretValue", "ListSecrets", "AssumeRole",
    ],
}

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]


def _normal_login_hour():
    return random.choices(
        range(24),
        weights=[1,1,1,1,1,2,5,10,15,15,12,10,8,10,12,15,15,12,8,5,4,3,2,1],
        k=1
    )[0]


def generate_logs(days: int = 30, output_db: str = "data/iam_logs.db") -> str:
    Path(output_db).parent.mkdir(parents=True, exist_ok=True)
    engine = get_engine(output_db)

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    records = []

    for user in NORMAL_USERS:
        daily_calls = random.randint(20, 80)
        for _ in range(days * daily_calls):
            ts = start_time + timedelta(
                days=random.randint(0, days - 1),
                hours=_normal_login_hour(),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59),
            )
            records.append((
                ts.isoformat(),
                user,
                random.choice(NORMAL_IPS),
                random.choice(AWS_API_CALLS["normal"]),
                random.choice(REGIONS[:2]),
                random.randint(60, 3600),
                1 if random.random() > 0.1 else 0,
                None,
                0,
            ))

    for user in ANOMALOUS_USERS:
        # Anomaly type 1: off-hours access
        for _ in range(days * 40):
            ts = start_time + timedelta(
                days=random.randint(0, days - 1),
                hours=random.choice([0, 1, 2, 3, 23]),
                minutes=random.randint(0, 59),
            )
            records.append((
                ts.isoformat(),
                user,
                random.choice(SUSPICIOUS_IPS),
                random.choice(AWS_API_CALLS["suspicious"]),
                random.choice(REGIONS),
                random.randint(3600, 86400),
                0,
                random.choice([None, None, "AccessDenied"]),
                1,
            ))

        # Anomaly type 2: credential harvesting burst
        burst_offset = random.randint(0, max(0, days - 2))
        burst_day = start_time + timedelta(days=burst_offset)
        for _ in range(random.randint(50, 100)):
            ts = burst_day + timedelta(minutes=random.randint(0, 30))
            records.append((
                ts.isoformat(),
                user,
                random.choice(SUSPICIOUS_IPS),
                random.choice(["CreateAccessKey", "GetSecretValue", "ListSecrets"]),
                "us-east-1",
                random.randint(10, 120),
                0,
                None,
                1,
            ))

    random.shuffle(records)
    columns = [
        "timestamp", "user_id", "source_ip", "api_call", "region",
        "session_duration_seconds", "mfa_used", "error_code", "is_anomaly",
    ]
    insert_events(engine, [dict(zip(columns, row)) for row in records])

    print(f"Generated {len(records):,} log entries -> {output_db}")
    return output_db


if __name__ == "__main__":
    generate_logs()
