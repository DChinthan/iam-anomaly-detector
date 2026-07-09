"""
Pub/Sub backend for streaming/event_stream.py's STREAM_MODE=pubsub option.

Uses google-cloud-pubsub. Real mode needs a GCP project with the topic and
subscription this module targets (see infra/terraform-gcp/pubsub.tf). For
local development without a GCP billing account, point PUBSUB_EMULATOR_HOST
at the official Pub/Sub emulator:

    gcloud beta emulators pubsub start --project=iam-anomaly-detector
    $(gcloud beta emulators pubsub env-init)   # sets PUBSUB_EMULATOR_HOST

The google-cloud-pubsub client automatically talks to the emulator instead
of the real service when that env var is set — no code branching needed
here for emulator vs. real Pub/Sub.

This module is only imported when STREAM_MODE=pubsub (see event_stream.py) —
the mock and kafka paths never touch it, so google-cloud-pubsub isn't a
hard dependency for the rest of the project, the same way confluent-kafka
isn't required unless STREAM_MODE=kafka.

Note: unlike EventStreamProducer/Consumer's `topic` constructor argument
(used for Kafka topics and the in-memory mock queue), the topic and
subscription here always come from PUBSUB_TOPIC / PUBSUB_SUBSCRIPTION —
GCP Pub/Sub topics and subscriptions are provisioned 1:1 pairs (see the
Terraform module) rather than a runtime-chosen consumer group like Kafka's.
"""
import os
from typing import Optional

GCP_PROJECT = os.getenv("GCP_PROJECT", "iam-anomaly-detector")
PUBSUB_TOPIC = os.getenv("PUBSUB_TOPIC", "iam-cloudtrail-events")
PUBSUB_SUBSCRIPTION = os.getenv("PUBSUB_SUBSCRIPTION", "iam-anomaly-scorer-sub")


def make_publisher():
    from google.cloud import pubsub_v1
    client = pubsub_v1.PublisherClient()
    topic_path = client.topic_path(GCP_PROJECT, PUBSUB_TOPIC)
    return client, topic_path


def make_subscriber():
    from google.cloud import pubsub_v1
    client = pubsub_v1.SubscriberClient()
    subscription_path = client.subscription_path(GCP_PROJECT, PUBSUB_SUBSCRIPTION)
    return client, subscription_path


def publish(client, topic_path: str, payload: bytes) -> None:
    future = client.publish(topic_path, data=payload)
    future.result(timeout=10)


def pull_one(client, subscription_path: str, timeout: float = 1.0) -> Optional[bytes]:
    """Pulls at most one message, acking it, and returns its raw payload
    bytes (or None on timeout/empty) — mirrors EventStreamConsumer.poll()'s
    contract so event_stream.py's pubsub branch stays a thin wrapper."""
    response = client.pull(
        request={"subscription": subscription_path, "max_messages": 1},
        timeout=timeout,
    )
    if not response.received_messages:
        return None
    msg = response.received_messages[0]
    client.acknowledge(
        request={"subscription": subscription_path, "ack_ids": [msg.ack_id]}
    )
    return msg.message.data
