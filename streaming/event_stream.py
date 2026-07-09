"""
Event stream abstraction over Kafka (confluent-kafka), GCP Pub/Sub, or an
in-memory mock queue, so the rest of the pipeline doesn't care which broker
is behind it — streaming/stream_processor.py only ever calls
produce()/poll()/flush()/close() and never branches on STREAM_MODE itself.

Set STREAM_MODE=kafka + KAFKA_BROKERS to point at a real Kafka cluster
(e.g. MSK), or STREAM_MODE=pubsub to use GCP Pub/Sub (see
streaming/pubsub_backend.py for real-vs-emulator setup). Defaults to
STREAM_MODE=mock, an in-process queue useful for local dev/tests without
standing up infrastructure — the same pattern the project already uses for
AWS_MOCK, GCP_MOCK, and ANTHROPIC_API_KEY.
"""
import json
import os
import queue
from typing import Optional

STREAM_MODE = os.getenv("STREAM_MODE", "mock")  # mock | kafka | pubsub
KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "iam-cloudtrail-events")

# Shared in-process queue backing mock mode — a producer and consumer created
# in the same process (e.g. simulate_producer.py feeding stream_processor.py)
# talk to each other through this.
_MOCK_QUEUE: "queue.Queue[bytes]" = queue.Queue()


class EventStreamProducer:
    """Publishes IAM/CloudTrail-style events onto the stream."""

    def __init__(self, topic: str = KAFKA_TOPIC):
        self.topic = topic
        self._producer = None
        self._pubsub_client = None
        self._pubsub_topic_path = None
        if STREAM_MODE == "kafka":
            from confluent_kafka import Producer
            self._producer = Producer({"bootstrap.servers": KAFKA_BROKERS})
        elif STREAM_MODE == "pubsub":
            from streaming.pubsub_backend import make_publisher
            self._pubsub_client, self._pubsub_topic_path = make_publisher()

    def produce(self, event: dict) -> None:
        payload = json.dumps(event).encode("utf-8")
        if STREAM_MODE == "kafka":
            self._producer.produce(
                self.topic, value=payload,
                key=event.get("user_id", "").encode("utf-8"),
            )
            self._producer.poll(0)
        elif STREAM_MODE == "pubsub":
            from streaming.pubsub_backend import publish
            publish(self._pubsub_client, self._pubsub_topic_path, payload)
        else:
            _MOCK_QUEUE.put(payload)

    def flush(self) -> None:
        if STREAM_MODE == "kafka":
            self._producer.flush()
        # Pub/Sub's publish() already blocks on future.result() per message,
        # so there's nothing to flush.


class EventStreamConsumer:
    """Consumes IAM/CloudTrail-style events from the stream."""

    def __init__(self, topic: str = KAFKA_TOPIC, group_id: str = "iam-anomaly-scorer"):
        self.topic = topic
        self._consumer = None
        self._pubsub_client = None
        self._pubsub_subscription_path = None
        if STREAM_MODE == "kafka":
            from confluent_kafka import Consumer
            self._consumer = Consumer({
                "bootstrap.servers": KAFKA_BROKERS,
                "group.id": group_id,
                "auto.offset.reset": "latest",
            })
            self._consumer.subscribe([topic])
        elif STREAM_MODE == "pubsub":
            from streaming.pubsub_backend import make_subscriber
            self._pubsub_client, self._pubsub_subscription_path = make_subscriber()

    def poll(self, timeout: float = 1.0) -> Optional[dict]:
        if STREAM_MODE == "kafka":
            msg = self._consumer.poll(timeout)
            if msg is None or msg.error():
                return None
            return json.loads(msg.value())
        elif STREAM_MODE == "pubsub":
            from streaming.pubsub_backend import pull_one
            payload = pull_one(self._pubsub_client, self._pubsub_subscription_path, timeout)
            return json.loads(payload) if payload else None
        try:
            payload = _MOCK_QUEUE.get(timeout=timeout)
            return json.loads(payload)
        except queue.Empty:
            return None

    def close(self) -> None:
        if STREAM_MODE == "kafka":
            self._consumer.close()
        elif STREAM_MODE == "pubsub":
            self._pubsub_client.close()
