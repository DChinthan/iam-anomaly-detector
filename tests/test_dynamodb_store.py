"""Tests for DynamoDBStore (mock mode only)."""

import pytest
import os
import json
from pathlib import Path
from aws.dynamodb_store import DynamoDBStore


@pytest.fixture(autouse=True)
def mock_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_MOCK", "true")
    mock_file = tmp_path / "dynamodb_mock.json"
    import aws.dynamodb_store as store_mod
    monkeypatch.setattr(store_mod, "MOCK_FILE", mock_file)
    yield mock_file


class TestDynamoDBStore:
    def test_put_and_get_result(self, mock_mode):
        store = DynamoDBStore()
        store.put_result("u001", {"ensemble_score": 0.8, "flagged": True})
        result = store.get_result("u001")
        assert result is not None
        assert result["user_id"] == "u001"

    def test_get_nonexistent_returns_none(self, mock_mode):
        store = DynamoDBStore()
        assert store.get_result("nonexistent_user") is None

    def test_put_overwrites_previous_result(self, mock_mode):
        store = DynamoDBStore()
        store.put_result("u001", {"ensemble_score": 0.5, "flagged": False})
        store.put_result("u001", {"ensemble_score": 0.9, "flagged": True})
        result = store.get_result("u001")
        assert result["flagged"] in (True, "True")

    def test_get_flagged_returns_only_flagged(self, mock_mode):
        store = DynamoDBStore()
        store.put_result("u001", {"ensemble_score": 0.9, "flagged": True})
        store.put_result("u002", {"ensemble_score": 0.2, "flagged": False})
        flagged = store.get_flagged()
        user_ids = {r["user_id"] for r in flagged}
        assert "u001" in user_ids
        assert "u002" not in user_ids

    def test_bulk_put_returns_count(self, mock_mode):
        import pandas as pd
        store = DynamoDBStore()
        df = pd.DataFrame([{
            "user_id": f"u{i}",
            "ensemble_score": 0.5,
            "iso_score": 0.5,
            "svm_score": 0.5,
            "ae_score": 0.5,
            "flagged": False,
            "off_hours_ratio": 0.1,
            "suspicious_api_ratio": 0.0,
            "burst_score": 5.0,
        } for i in range(10)])
        count = store.bulk_put(df)
        assert count == 10
