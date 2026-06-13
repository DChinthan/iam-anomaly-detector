"""
Adapter for the Los Alamos National Laboratory (LANL) Unified Host and
Network Dataset — auth.txt.gz

LANL auth log format (CSV, no header):
  time, src_user@domain, dst_user@domain, src_computer, dst_computer,
  auth_type, logon_type, auth_orientation, result

This adapter:
  1. Streams the gzip file line by line (handles multi-GB files without
     loading everything into memory)
  2. Maps each event to our IAM log schema
  3. Derives session durations from LogOn/LogOff pairs per user
  4. Writes results to the SQLite database used by the rest of the pipeline

Download instructions:
  1. Visit  csr.lanl.gov/data/cyber1/
  2. Accept the data use agreement (free, instant)
  3. Download auth.txt.gz  (~1.5 GB)
  4. Place it in the data/ folder of this project

Then run:
  python data/lanl_adapter.py --input data/auth.txt.gz --limit 500000

The --limit flag means you only need the first 500k lines (~40 MB uncompressed),
which is more than enough to train and demonstrate the models.
"""

import argparse
import gzip
import hashlib
import random
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# Reference epoch — LANL time values are seconds since start of capture
REFERENCE_DATE = datetime(2024, 1, 1, 0, 0, 0)

# Auth type → MFA proxy:
#   Kerberos = MFA-equivalent (ticket-based), everything else = no MFA
MFA_AUTH_TYPES = {"Kerberos"}

# Auth type + logon type → AWS API call equivalent
API_CALL_MAP = {
    ("Kerberos", "Interactive"):     "ConsoleLogin",
    ("Kerberos", "Network"):         "AssumeRole",
    ("Kerberos", "Batch"):           "GetSessionToken",
    ("Kerberos", "Service"):         "GetUser",
    ("NTLM",     "Interactive"):     "ConsoleLogin",
    ("NTLM",     "Network"):         "GetObject",
    ("NTLM",     "Batch"):           "ListBuckets",
    ("Negotiate", "Interactive"):    "ConsoleLogin",
    ("Negotiate", "Network"):        "DescribeInstances",
    ("Negotiate", "Batch"):          "GetPolicy",
    ("Negotiate", "Service"):        "ListRoles",
}
DEFAULT_API_CALL = "GetUser"

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
IP_PREFIXES = ["10.0.{}.{}", "192.168.{}.{}", "172.16.{}.{}"]


def _computer_to_ip(computer: str) -> str:
    """Deterministically map a computer name to a stable synthetic IP."""
    h = int(hashlib.md5(computer.encode()).hexdigest(), 16)
    prefix = IP_PREFIXES[h % len(IP_PREFIXES)]
    return prefix.format((h >> 8) % 256, (h >> 16) % 254 + 1)


def _computer_to_region(computer: str) -> str:
    h = int(hashlib.md5(computer.encode()).hexdigest(), 16)
    return REGIONS[h % len(REGIONS)]


def _parse_user(raw: str) -> str:
    """Strip @DOMAIN suffix from LANL user strings."""
    return raw.split("@")[0] if "@" in raw else raw


def _api_call(auth_type: str, logon_type: str) -> str:
    return API_CALL_MAP.get((auth_type, logon_type), DEFAULT_API_CALL)


def stream_events(gz_path: str, limit: int):
    """Yield parsed event dicts from the gzip file."""
    opener = gzip.open if gz_path.endswith(".gz") else open
    with opener(gz_path, "rt", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            parts = line.strip().split(",")
            if len(parts) < 9:
                continue
            (time_s, src_user, dst_user, src_comp, dst_comp,
             auth_type, logon_type, orientation, result) = parts[:9]

            try:
                ts = REFERENCE_DATE + timedelta(seconds=int(time_s))
            except ValueError:
                continue

            yield {
                "timestamp":    ts,
                "user_id":      _parse_user(src_user),
                "source_ip":    _computer_to_ip(src_comp),
                "api_call":     _api_call(auth_type.strip(), logon_type.strip()),
                "region":       _computer_to_region(dst_comp),
                "mfa_used":     1 if auth_type.strip() in MFA_AUTH_TYPES else 0,
                "error_code":   "AccessDenied" if result.strip() == "Fail" else None,
                "orientation":  orientation.strip(),
                "auth_type":    auth_type.strip(),
                "raw_time":     int(time_s),
            }


def _compute_session_durations(events: list[dict]) -> dict[str, list[int]]:
    """
    Estimate session duration per user by pairing LogOn/LogOff events.
    Returns {user_id: [duration_seconds, ...]}
    """
    sessions: dict[str, list[int]] = defaultdict(list)
    logon_time: dict[str, int] = {}

    for e in sorted(events, key=lambda x: x["raw_time"]):
        uid = e["user_id"]
        if e["orientation"] == "LogOn":
            logon_time[uid] = e["raw_time"]
        elif e["orientation"] == "LogOff" and uid in logon_time:
            duration = e["raw_time"] - logon_time.pop(uid)
            if 0 < duration < 86400:
                sessions[uid].append(duration)

    return sessions


def ingest(gz_path: str, db_path: str, limit: int = 500_000) -> int:
    print(f"Streaming up to {limit:,} events from {gz_path} …")
    events = list(stream_events(gz_path, limit))
    print(f"  Parsed {len(events):,} valid events from {len(set(e['user_id'] for e in events)):,} users")

    session_durations = _compute_session_durations(events)

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TABLE IF EXISTS iam_logs")
    conn.execute("""
        CREATE TABLE iam_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            api_call TEXT NOT NULL,
            region TEXT NOT NULL,
            session_duration_seconds INTEGER NOT NULL,
            mfa_used INTEGER NOT NULL,
            error_code TEXT,
            is_anomaly INTEGER DEFAULT 0
        )
    """)

    # Track which user's session durations we've already drawn from
    session_idx: dict[str, int] = defaultdict(int)

    records = []
    for e in events:
        uid = e["user_id"]
        durs = session_durations.get(uid, [])
        if durs:
            idx = session_idx[uid] % len(durs)
            duration = durs[idx]
            session_idx[uid] += 1
        else:
            duration = random.randint(60, 1800)

        records.append((
            e["timestamp"].isoformat(),
            uid,
            e["source_ip"],
            e["api_call"],
            e["region"],
            duration,
            e["mfa_used"],
            e["error_code"],
            0,
        ))

    conn.executemany(
        "INSERT INTO iam_logs "
        "(timestamp, user_id, source_ip, api_call, region, "
        "session_duration_seconds, mfa_used, error_code, is_anomaly) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        records,
    )
    conn.commit()
    conn.close()
    print(f"Wrote {len(records):,} records → {db_path}")
    return len(records)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest LANL auth logs into IAM Anomaly Detector")
    parser.add_argument("--input", default="data/auth.txt.gz", help="Path to auth.txt.gz")
    parser.add_argument("--db", default="data/iam_logs.db", help="Output SQLite path")
    parser.add_argument("--limit", type=int, default=500_000,
                        help="Max lines to read (default: 500,000 ≈ 40 MB uncompressed)")
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"""
File not found: {args.input}

To download the LANL dataset:
  1. Go to:  csr.lanl.gov/data/cyber1/
  2. Accept the data use agreement (free)
  3. Download auth.txt.gz  (~1.5 GB)
  4. Place it at: {args.input}
  5. Re-run this script

The first 500,000 lines are enough to run the full pipeline.
""")
        raise SystemExit(1)

    ingest(args.input, args.db, args.limit)
    print("\nNext steps:")
    print("  python main.py train")
    print("  python main.py score")
    print("  streamlit run dashboard/app.py")
