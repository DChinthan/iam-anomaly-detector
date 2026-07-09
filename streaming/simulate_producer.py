"""
Simulates a live IAM/CloudTrail event feed by publishing events one at a
time onto the event stream (Kafka or the in-memory mock), instead of the
bulk-generate-into-SQLite path used by data/log_generator.py.

Run with: python main.py stream-simulate [event_count] [delay_seconds]
"""
import random
import sys
import time
from datetime import datetime

from streaming.event_stream import EventStreamProducer
from data.log_generator import (
    NORMAL_USERS, ANOMALOUS_USERS, NORMAL_IPS, SUSPICIOUS_IPS,
    AWS_API_CALLS, REGIONS, _normal_login_hour,
)


def _random_normal_event() -> dict:
    user = random.choice(NORMAL_USERS)
    ts = datetime.utcnow().replace(hour=_normal_login_hour())
    return {
        "timestamp": ts.isoformat(),
        "user_id": user,
        "source_ip": random.choice(NORMAL_IPS),
        "api_call": random.choice(AWS_API_CALLS["normal"]),
        "region": random.choice(REGIONS[:2]),
        "session_duration_seconds": random.randint(60, 3600),
        "mfa_used": 1 if random.random() > 0.1 else 0,
        "error_code": None,
        "is_anomaly": 0,
    }


def _random_anomalous_event() -> dict:
    user = random.choice(ANOMALOUS_USERS)
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": user,
        "source_ip": random.choice(SUSPICIOUS_IPS),
        "api_call": random.choice(AWS_API_CALLS["suspicious"]),
        "region": random.choice(REGIONS),
        "session_duration_seconds": random.randint(10, 120),
        "mfa_used": 0,
        "error_code": random.choice([None, "AccessDenied"]),
        "is_anomaly": 1,
    }


def simulate(event_count: int = 200, delay_seconds: float = 0.05, anomaly_rate: float = 0.08) -> None:
    producer = EventStreamProducer()
    for i in range(event_count):
        event = _random_anomalous_event() if random.random() < anomaly_rate else _random_normal_event()
        producer.produce(event)
        if (i + 1) % 20 == 0:
            print(f"  published {i + 1}/{event_count} events")
        time.sleep(delay_seconds)
    producer.flush()
    print(f"Done — published {event_count} events to the stream")


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    delay = float(sys.argv[2]) if len(sys.argv) > 2 else 0.05
    simulate(count, delay)
