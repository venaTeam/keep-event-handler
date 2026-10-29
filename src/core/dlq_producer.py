"""Producer for the DLQ topic (see docs/deploy/dlq-replay.md).

Terminal processing failures are diverted to KAFKA_DLQ_TOPIC in the same
AppChi-style envelope keep-ingestions writes (_send_to_dlq) and
keep-reconciler parses (payload["alert"] = event, payload["error"]["message"]
= cause). Unknown extra fields are ignored by the reconciler, so routing
metadata is carried for debuggability — with alertraw removed, this message
is the durable record of a lost event.
"""

import json
import logging
from typing import Any

from confluent_kafka import Producer

from src.config.config import config
from src.config.consts import (
    KAFKA_DLQ_TOPIC,
    KAFKA_DLQ_BOOTSTRAP_SERVERS,
    KAFKA_DLQ_SECURITY_PROTOCOL,
    KAFKA_DLQ_SASL_MECHANISM,
    KAFKA_DLQ_SASL_USERNAME,
    KAFKA_DLQ_SASL_PASSWORD,
)

logger = logging.getLogger(__name__)

_FLUSH_TIMEOUT_SECONDS = 10.0

_producer: Producer | None = None


def _bootstrap_servers() -> str:
    """Accept the reconciler's JSON list or a plain comma-separated string."""
    try:
        parsed = json.loads(KAFKA_DLQ_BOOTSTRAP_SERVERS)
        if isinstance(parsed, list):
            return ",".join(parsed)
    except (json.JSONDecodeError, TypeError):
        pass
    return str(KAFKA_DLQ_BOOTSTRAP_SERVERS)


def _get_producer() -> Producer | None:
    global _producer
    if _producer is None:
        try:
            _producer = Producer(
                {
                    "bootstrap.servers": _bootstrap_servers(),
                    "security.protocol": KAFKA_DLQ_SECURITY_PROTOCOL,
                    "sasl.mechanism": KAFKA_DLQ_SASL_MECHANISM,
                    "sasl.username": KAFKA_DLQ_SASL_USERNAME,
                    "sasl.password": KAFKA_DLQ_SASL_PASSWORD,
                }
            )
        except Exception:
            logger.exception("Failed to create DLQ producer")
    return _producer


def _build_dlq_payload(
    event: Any,
    error_message: str,
    *,
    tenant_id: str | None = None,
    provider_type: str | None = None,
    provider_id: str | None = None,
    fingerprint: str | None = None,
    api_key_name: str | None = None,
    provider_name: str | None = None,
    event_type: str | None = None,
    trace_id: str | None = None,
    dlq_replay_count: int | None = None,
    reason: str | None = None,
) -> dict:
    """
    AppChi-style envelope — byte-compatible with keep-ingestions'
    _send_to_dlq and the reconciler's parser: payload["alert"] is the inner
    event, payload["error"]["message"] the cause. Extra keys ride along for
    debuggability and are ignored by the reconciler.
    """
    is_batch = (
        isinstance(event, list)
        and bool(event)
        and all(isinstance(item, dict) for item in event)
    )
    if not isinstance(event, dict) and not is_batch:
        # poison by construction — a non-dict payload must still get a DLQ
        # attempt (json.dumps(default=str) below stringifies it). A batch stays a
        # list: the reconciler resends it to /alerts/event as one request.
        event = {"_unserializable_payload": event}
    return {
        "alert": event,
        # keep-reconciler doesn't replay poison/malformed (they fail the same
        # way every time) and keeps retrying outage failures.
        "error": {"message": error_message, "reason": reason},
        "trace_id": trace_id,
        "tenant_id": tenant_id,
        "provider_type": provider_type,
        "provider_id": provider_id,
        "fingerprint": fingerprint,
        "api_key_name": api_key_name,
        "provider_name": provider_name,
        "event_type": event_type,
        "source_topic": config("KAFKA_TOPIC", default="keep-events"),
        "dlq_topic": KAFKA_DLQ_TOPIC,
        # The reconciler stops replaying an alert after a number of rounds.
        "dlq_replay_count": dlq_replay_count,
    }


def produce_to_dlq(
    payload: dict,
    error: Exception,
    tenant_id: str | None = None,
    provider_type: str | None = None,
    reason: str | None = None,
) -> bool:
    """Divert a failed event to KAFKA_DLQ_TOPIC. Never raises.

    `payload` is the Kafka message payload as decoded in _process_message —
    the inner 'event' is re-wrapped under 'alert' per the AppChi contract.
    Returns True if the event was delivered (synchronously flushed); False
    means the divert failed — with alertraw removed there is no fallback
    table, so the caller logs the loss and commits.
    """
    producer = _get_producer()
    if producer is None:
        return False

    is_dict = isinstance(payload, dict)
    inner_event = (
        payload.get("event")
        if is_dict and payload.get("event") is not None
        else payload
    )
    dlq_payload = _build_dlq_payload(
        inner_event,
        f"{type(error).__name__}: {error}",
        tenant_id=tenant_id,
        provider_type=provider_type,
        provider_id=payload.get("provider_id") if is_dict else None,
        fingerprint=payload.get("fingerprint") if is_dict else None,
        api_key_name=payload.get("api_key_name") if is_dict else None,
        provider_name=payload.get("provider_name") if is_dict else None,
        event_type=payload.get("event_type") if is_dict else "alert",
        trace_id=payload.get("trace_id") if is_dict else None,
        dlq_replay_count=payload.get("dlq_replay_count") if is_dict else None,
        reason=reason,
    )

    # Payload defect tracking: poison messages may themselves be unserializable.
    try:
        value = json.dumps(dlq_payload, default=str).encode("utf-8")
    except Exception:
        logger.exception("Failed to serialize DLQ payload")
        return False

    alert = dlq_payload["alert"]
    fingerprint = (
        alert.get("fingerprint") if isinstance(alert, dict) else dlq_payload["fingerprint"]
    )
    # flush() returning 0 only means the queue is empty: a message the broker
    # rejected leaves it too. The delivery report says whether it landed.
    delivery_errors = []

    def on_delivery(err, _msg):
        if err is not None:
            delivery_errors.append(err)

    try:
        producer.produce(
            KAFKA_DLQ_TOPIC,
            key=fingerprint,  # partition by fingerprint, so one fingerprint
            # keeps its DLQ order like the main-topic producer.
            value=value,
            on_delivery=on_delivery,
        )
        remaining = producer.flush(_FLUSH_TIMEOUT_SECONDS)
        if remaining > 0:
            logger.warning(
                "DLQ flush left %d message(s) undelivered — treating as failure",
                remaining,
            )
            return False
        if delivery_errors:
            logger.error(
                "DLQ broker rejected the message: %s", delivery_errors[0]
            )
            return False
    except Exception:
        logger.exception("Failed to produce to DLQ topic")
        return False

    logger.warning(
        "Terminal failure diverted to DLQ topic",
        extra={
            "dlq_topic": KAFKA_DLQ_TOPIC,
            "tenant_id": tenant_id,
            "fingerprint": fingerprint,
        },
    )
    return True


def close() -> None:
    """Flush and release on shutdown. Bounded, never raises."""
    global _producer
    if _producer is not None:
        try:
            _producer.flush(_FLUSH_TIMEOUT_SECONDS)
        except Exception:
            logger.exception("Failed to flush DLQ producer on shutdown")
        _producer = None
