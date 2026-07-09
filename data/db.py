"""
Database engine abstraction for the IAM log store.

Local/dev (default): SQLite file, zero setup — unchanged from before.
Production: Postgres/RDS — set DATABASE_URL, e.g.
  postgresql+psycopg2://user:pass@rds-endpoint.amazonaws.com:5432/iam_anomaly

Both backends share the same iam_logs schema and are accessed through a
single SQLAlchemy engine so log_generator, cloudwatch_client, the streaming
processor, and the feature extractor don't need to know which store is active.
"""
import os
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

DATABASE_URL = os.getenv("DATABASE_URL")  # unset -> SQLite

_engine_cache: dict = {}


def get_engine(sqlite_path: str = "data/iam_logs.db") -> Engine:
    url = DATABASE_URL or f"sqlite:///{sqlite_path}"
    if url in _engine_cache:
        return _engine_cache[url]

    engine = create_engine(url)
    is_postgres = engine.dialect.name == "postgresql"
    id_col = "id SERIAL PRIMARY KEY" if is_postgres else "id INTEGER PRIMARY KEY AUTOINCREMENT"
    with engine.begin() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS iam_logs (
                {id_col},
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
        """))
    _engine_cache[url] = engine
    return engine


def insert_events(engine: Engine, records: list[dict]) -> int:
    """Bulk-inserts iam_logs rows. Each dict must carry the 9 schema columns
    (id is auto-generated)."""
    if not records:
        return 0
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO iam_logs
                (timestamp, user_id, source_ip, api_call, region,
                 session_duration_seconds, mfa_used, error_code, is_anomaly)
                VALUES (:timestamp, :user_id, :source_ip, :api_call, :region,
                        :session_duration_seconds, :mfa_used, :error_code, :is_anomaly)
            """),
            records,
        )
    return len(records)
