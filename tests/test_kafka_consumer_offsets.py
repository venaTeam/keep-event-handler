"""Offsets are only ever committed for records this consumer actually
processed — no implicit store, no commit on revoke.
"""
import json
from unittest.mock import MagicMock, patch

from src.core.kafka_consumer import KafkaEventConsumer, RetryBudget


def _make_msg(topic, partition, offset):
    msg = MagicMock()
    msg.value.return_value = json.dumps(
        {
            "trace_id": f"trace-{partition}-{offset}",
            "tenant_id": "t1",
            "event": {"data": "x"},
            "provider_type": "grafana",
        }
    ).encode("utf-8")
    msg.error.return_value = None
    msg.topic.return_value = topic
    msg.partition.return_value = partition
    msg.offset.return_value = offset
    return msg


def _consumer_with_mock_kafka():
    mock_consumer_instance = MagicMock()
    with patch("src.core.kafka_consumer.Consumer", return_value=mock_consumer_instance):
        consumer = KafkaEventConsumer()
    consumer._consumer = mock_consumer_instance
    return consumer, mock_consumer_instance


def test_auto_offset_store_is_disabled():
    """Auto-store fills the moment a record is DELIVERED, so any argument-less
    commit() would mark unprocessed records done."""
    with patch("src.core.kafka_consumer.Consumer", return_value=MagicMock()):
        conf = KafkaEventConsumer()._build_consumer_config()

    assert conf["enable.auto.offset.store"] is False
    assert conf["enable.auto.commit"] is False


def test_revoke_does_not_commit():
    """The silent offset leak: a revoke-time commit() flushes the store,
    burning records abandoned mid-batch for redelivery."""
    consumer, mock_kafka = _consumer_with_mock_kafka()

    consumer._on_revoke(mock_kafka, [MagicMock(partition=0, topic="keep-events")])

    mock_kafka.commit.assert_not_called()


def test_shutdown_then_revoke_never_commits_the_abandoned_records():
    """End-to-end of the leak: SIGTERM mid-batch, then the rebalance that
    follows consumer.close()."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(300000, shutdown_event=consumer._shutdown_event)
    msgs = [_make_msg("keep-events", 0, o) for o in range(5)]

    def process(msg, _budget):
        if msg.offset() == 1:
            consumer._shutdown_event.set()
        return True

    with patch.object(consumer, "_process_message", side_effect=process):
        consumer._process_batch(msgs, budget)

    consumer._on_revoke(mock_kafka, msgs)

    # Exactly one commit, and it is the explicit message-addressed one for the
    # last processed record (offset 1). Offsets 2..4 are redelivered.
    assert mock_kafka.commit.call_count == 1
    committed = mock_kafka.commit.call_args
    assert committed.args[0].offset() == 1
    assert committed.kwargs == {"asynchronous": False}


def test_processed_records_commit_by_message_not_by_store():
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(300000)

    with patch.object(consumer, "_process_message", return_value=True):
        consumer._process_batch([_make_msg("keep-events", 3, 42)], budget)

    # message= form: addresses the offset directly, never reads the store.
    assert mock_kafka.commit.call_args.args[0].offset() == 42
