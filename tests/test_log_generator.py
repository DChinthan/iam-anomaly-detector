"""Tests for the synthetic IAM log generator."""

import os
import sqlite3
import pytest
from data.log_generator import generate_logs


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test_logs.db")


class TestLogGenerator:
    def test_generates_nonzero_rows(self, tmp_db):
        generate_logs(days=3, output_db=tmp_db)
        conn = sqlite3.connect(tmp_db)
        count = conn.execute("SELECT COUNT(*) FROM iam_logs").fetchone()[0]
        conn.close()
        assert count > 0

    def test_schema_columns_exist(self, tmp_db):
        generate_logs(days=3, output_db=tmp_db)
        conn = sqlite3.connect(tmp_db)
        cursor = conn.execute("PRAGMA table_info(iam_logs)")
        cols = {row[1] for row in cursor.fetchall()}
        conn.close()
        required = {
            "timestamp", "user_id", "source_ip", "api_call",
            "region", "session_duration_seconds", "mfa_used",
            "error_code", "is_anomaly",
        }
        assert required.issubset(cols)

    def test_contains_anomalous_and_normal_users(self, tmp_db):
        generate_logs(days=5, output_db=tmp_db)
        conn = sqlite3.connect(tmp_db)
        labels = {
            row[0]
            for row in conn.execute("SELECT DISTINCT is_anomaly FROM iam_logs")
        }
        conn.close()
        assert 0 in labels
        assert 1 in labels

    def test_timestamps_are_valid_iso(self, tmp_db):
        from datetime import datetime
        generate_logs(days=2, output_db=tmp_db)
        conn = sqlite3.connect(tmp_db)
        rows = conn.execute("SELECT timestamp FROM iam_logs LIMIT 20").fetchall()
        conn.close()
        for (ts,) in rows:
            datetime.fromisoformat(ts)  # raises if invalid

    def test_session_durations_positive(self, tmp_db):
        generate_logs(days=2, output_db=tmp_db)
        conn = sqlite3.connect(tmp_db)
        min_dur = conn.execute(
            "SELECT MIN(session_duration_seconds) FROM iam_logs"
        ).fetchone()[0]
        conn.close()
        assert min_dur > 0

    def test_mfa_used_is_binary(self, tmp_db):
        generate_logs(days=2, output_db=tmp_db)
        conn = sqlite3.connect(tmp_db)
        values = {
            row[0]
            for row in conn.execute("SELECT DISTINCT mfa_used FROM iam_logs")
        }
        conn.close()
        assert values.issubset({0, 1})
