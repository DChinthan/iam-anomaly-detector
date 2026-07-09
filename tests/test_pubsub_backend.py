"""
Tests for the Pub/Sub streaming backend — mock-mode only, no real GCP
project/credentials/emulator required.

google-cloud-pubsub is only imported lazily inside pubsub_backend.py's
functions (same pattern as boto3 in aws/ and confluent_kafka in
event_stream.py), so importing the module never requires the package to be
installed. The producer/consumer round-trip is exercised by monkeypatching
pubsub_backend's four functions with an in-memory fake channel, which
verifies event_stream.py's STREAM_MODE=pubsub branch wires up correctly
without touching real Pub/Sub.
"""

import queue

import streaming.event_stream as event_stream
import streaming.pubsub_backend as pubsub_backend


def test_pubsub_backend_imports_without_google_cloud_pubsub_installed():
    # If this raised at import time, pubsub support would be a hard
    # dependency for every user of the project, like AWS_MOCK/STREAM_MODE=mock.
    assert hasattr(pubsub_backend, "make_publisher")
    assert hasattr(pubsub_backend, "make_subscriber")
    assert hasattr(pubsub_backend, "publish")
    assert hasattr(pubsub_backend, "pull_one")


class _FakeChannel:
    """Stands in for a real Pub/Sub topic+subscription pair with a plain queue."""

    def __init__(self):
        self.queue: "queue.Queue[bytes]" = queue.Queue()

    def close(self) -> None:
        pass


def test_event_stream_pubsub_roundtrip(monkeypatch):
    channel = _FakeChannel()

    def fake_make_publisher():
        return channel, "fake-topic-path"

    def fake_make_subscriber():
        return channel, "fake-subscription-path"

    def fake_publish(client, topic_path, payload: bytes) -> None:
        client.queue.put(payload)

    def fake_pull_one(client, subscription_path, timeout: float = 1.0):
        try:
            return client.queue.get(timeout=timeout)
        except queue.Empty:
            return None

    monkeypatch.setattr(pubsub_backend, "make_publisher", fake_make_publisher)
    monkeypatch.setattr(pubsub_backend, "make_subscriber", fake_make_subscriber)
    monkeypatch.setattr(pubsub_backend, "publish", fake_publish)
    monkeypatch.setattr(pubsub_backend, "pull_one", fake_pull_one)
    monkeypatch.setattr(event_stream, "STREAM_MODE", "pubsub")

    producer = event_stream.EventStreamProducer()
    consumer = event_stream.EventStreamConsumer()

    event = {"user_id": "u001", "api_call": "GetSecretValue"}
    producer.produce(event)
    producer.flush()

    received = consumer.poll(timeout=1.0)
    assert received == event

    consumer.close()


def test_event_stream_mock_mode_unaffected_by_pubsub_support(monkeypatch):
    """Default STREAM_MODE (mock) must keep working exactly as before —
    adding the pubsub branch shouldn't change the fallthrough behavior."""
    monkeypatch.setattr(event_stream, "STREAM_MODE", "mock")

    producer = event_stream.EventStreamProducer()
    consumer = event_stream.EventStreamConsumer()

    event = {"user_id": "u002", "api_call": "GetObject"}
    producer.produce(event)

    received = consumer.poll(timeout=1.0)
    assert received == event
