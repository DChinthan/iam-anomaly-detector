"""
Cloud Logging ingestion layer (GCP backend).
Fetches IAM/Cloud Audit Log entries from Google Cloud Logging and
normalises them into the same schema used by the local SQLite store.
Set GCP_MOCK=true (default) to use synthetic data without real GCP credentials.

Cloud Logging asymmetry vs. CloudWatch Logs Insights (aws/cloudwatch_client.py):
Cloud Logging is a global, project-scoped API — there is no per-region
endpoint to connect to the way `_get_boto_client(region)` picks a regional
CloudWatch client. GCP_REGIONS therefore does NOT select a connection
target; every region in the list is queried through the same client. It's
used to filter/tag entries by `resource.labels.location`, since the
*audited resources* (Compute instances, GKE clusters, etc.) are still
regional even though the Logging API that serves their audit trail isn't.
This keeps the multi-region loop structure identical to the AWS module
while being honest about what "region" means on each side — see
gcp/README.md for the full writeup.
"""

import os
import random
from datetime import datetime, timedelta
from typing import Optional

from data.db import get_engine, insert_events

MOCK_MODE = os.getenv("GCP_MOCK", "true").lower() == "true"

GCP_PROJECT = os.getenv("GCP_PROJECT", "iam-anomaly-detector")

# Comma-separated list, e.g. "us-central1,us-east1,europe-west1". Unlike
# AWS_REGIONS, this doesn't change which API endpoint is called (Cloud
# Logging has none) — see the module docstring.
GCP_REGIONS = [
    r.strip() for r in os.getenv("GCP_REGIONS", "us-central1,us-east1").split(",") if r.strip()
]


def _get_logging_client():
    from google.cloud import logging as gcp_logging
    return gcp_logging.Client(project=GCP_PROJECT)


def _mock_audit_log_events(region: str, limit: int = 500) -> list[dict]:
    """Returns mock events shaped like real GCP Cloud Audit Log entries:
    protoPayload.{methodName, resourceName, authenticationInfo, requestMetadata}."""
    methods = [
        "storage.objects.get", "storage.objects.create", "compute.instances.list",
        "compute.instances.get", "iam.serviceAccounts.get", "iam.roles.get",
        "google.iam.admin.v1.CreateServiceAccountKey", "SetIamPolicy",
        "google.iam.admin.v1.CreateServiceAccount", "AccessSecretVersion",
    ]
    ips = ["35.190.0.{}".format(i) for i in range(1, 30)]
    users = ["user_{:03d}@example.com".format(i) for i in range(1, 11)]
    now = datetime.utcnow()

    events = []
    for _ in range(limit):
        ts = now - timedelta(hours=random.randint(0, 72))
        events.append({
            "timestamp": ts.isoformat(),
            "protoPayload": {
                "methodName": random.choice(methods),
                "resourceName": f"projects/{GCP_PROJECT}/regions/{region}/resources/{random.randint(1000, 9999)}",
                "authenticationInfo": {"principalEmail": random.choice(users)},
                "requestMetadata": {"callerIp": random.choice(ips)},
                "status": {} if random.random() > 0.1 else {"code": 7, "message": "PERMISSION_DENIED"},
            },
            "resource": {"labels": {"location": region}},
        })
    return events


def _real_audit_log_events(region: str, hours: int = 24, log_name: Optional[str] = None) -> list[dict]:
    from google.cloud import logging as gcp_logging

    client = _get_logging_client()
    start_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
    log_name = log_name or "cloudaudit.googleapis.com%2Factivity"

    filter_str = (
        f'logName="projects/{GCP_PROJECT}/logs/{log_name}" '
        f'AND resource.labels.location="{region}" '
        f'AND timestamp>="{start_time}"'
    )
    entries = client.list_entries(
        filter_=filter_str, order_by=gcp_logging.DESCENDING, page_size=1000,
    )

    events = []
    for entry in entries:
        events.append({
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else datetime.utcnow().isoformat(),
            "protoPayload": entry.payload or {},
            "resource": {"labels": {"location": region}},
        })
    return events


def _normalize_event(raw: dict, region: str) -> dict:
    """Flattens a Cloud Audit Log-shaped event into the 9-column schema
    features/extractor.py expects (same schema aws/cloudwatch_client.py produces)."""
    payload = raw.get("protoPayload", {}) or {}
    auth_info = payload.get("authenticationInfo", {}) or {}
    request_meta = payload.get("requestMetadata", {}) or {}
    status = payload.get("status", {}) or {}
    resource_location = raw.get("resource", {}).get("labels", {}).get("location", region)

    return {
        "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
        "user_id": auth_info.get("principalEmail", "unknown"),
        "source_ip": request_meta.get("callerIp", "0.0.0.0"),
        "api_call": payload.get("methodName", "Unknown"),
        "region": resource_location,
        "session_duration_seconds": random.randint(60, 3600),
        "mfa_used": int(random.random() > 0.15),
        "error_code": status.get("message") or None,
        "is_anomaly": 0,
    }


def ingest_to_db(
    db_path: str = "data/iam_logs.db",
    log_name: Optional[str] = None,
    hours: int = 24,
) -> int:
    """Pulls Cloud Audit Log entries tagged with every region in GCP_REGIONS
    and merges them into the local store. See the module docstring for why
    "region" is a filter tag here rather than a connection endpoint, unlike
    AWS_REGIONS in aws/cloudwatch_client.py."""
    engine = get_engine(db_path)
    total_inserted = 0
    for region in GCP_REGIONS:
        if MOCK_MODE:
            raw_events = _mock_audit_log_events(region)
        else:
            raw_events = _real_audit_log_events(region, hours, log_name)
        events = [_normalize_event(e, region) for e in raw_events]
        count = insert_events(engine, events)
        total_inserted += count
        print(f"  [{region}] ingested {count} events")

    print(f"Ingested {total_inserted} events total from "
          f"{'mock' if MOCK_MODE else 'Cloud Logging'} across {len(GCP_REGIONS)} region(s)")
    return total_inserted
