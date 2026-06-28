"""
Tests for batch consume + contiguous-offset commit per partition.
"""
import json
from unittest.mock import MagicMock, patch

from src.core.kafka_consumer import KafkaEventConsumer, RetryBudget


def _make_msg(topic, partition, offset, tenant="t1"):
    msg = MagicMock()
    msg.value.return_value = json.dumps(
        {
            "trace_id": f"trace-{partition}-{offset}",
            "tenant_id": tenant,
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


def test_contiguous_commit_stops_at_first_unresolved():
    """
    A 5-record partition where record 3 (offset 2) is genuinely unresolved
    (returns should_commit=False) commits offset 2's predecessor — i.e. the
    record at offset 1 — and does NOT commit offsets 2..4.
    """
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)

    msgs = [_make_msg("keep-events", 0, o) for o in range(5)]

    # offsets 0,1 -> committed True; offset 2 -> unresolved (False);
    # offsets 3,4 -> would be True but must never be reached.
    def process_side_effect(msg, b):
        return msg.offset() != 2

    with patch.object(consumer, "_process_message", side_effect=process_side_effect) as mp:
        consumer._process_batch(msgs, budget)

    # Processing stopped at the unresolved record (offsets 0,1,2 tried; 3,4 not).
    processed_offsets = [c.args[0].offset() for c in mp.call_args_list]
    assert processed_offsets == [0, 1, 2]

    # Commit boundary is the last contiguous resolved record (offset 1).
    mock_kafka.commit.assert_called_once()
    committed_msg = mock_kafka.commit.call_args.args[0]
    assert committed_msg.offset() == 1


def test_poison_record_counts_as_resolved_and_does_not_break_contiguity():
    """A poison record handled by the terminal sink returns should_commit=True,
    so it counts as resolved and the chain continues past it."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)

    msgs = [_make_msg("keep-events", 0, o) for o in range(3)]

    # All resolved (poison at offset 1 still returns True via terminal handling).
    with patch.object(consumer, "_process_message", return_value=True):
        consumer._process_batch(msgs, budget)

    # Whole batch resolved -> commit boundary is the highest offset (2).
    mock_kafka.commit.assert_called_once()
    assert mock_kafka.commit.call_args.args[0].offset() == 2


def test_batch_of_one_equivalence():
    """BATCH_SIZE=1: one record, success -> commit that record once."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)

    msg = _make_msg("keep-events", 0, 7)
    with patch.object(consumer, "_process_message", return_value=True):
        consumer._process_batch([msg], budget)

    mock_kafka.commit.assert_called_once_with(msg, asynchronous=False)
    assert mock_kafka.commit.call_args.args[0].offset() == 7


def test_per_partition_grouping_preserves_order_and_independent_commits():
    """
    Two partitions in one batch, delivered out of order. Each partition is
    processed in ascending offset order and committed independently at its own
    contiguous boundary.
    """
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)

    # Partition 0: offsets 0,1 (both ok). Partition 1: offsets 0 ok, 1 fails.
    p0_0 = _make_msg("keep-events", 0, 0)
    p0_1 = _make_msg("keep-events", 0, 1)
    p1_0 = _make_msg("keep-events", 1, 0)
    p1_1 = _make_msg("keep-events", 1, 1)
    # Intentionally shuffled delivery order.
    msgs = [p0_1, p1_1, p0_0, p1_0]

    def process_side_effect(msg, b):
        # Partition 1 offset 1 is unresolved.
        return not (msg.partition() == 1 and msg.offset() == 1)

    order = []

    def record_order(msg, b):
        order.append((msg.partition(), msg.offset()))
        return process_side_effect(msg, b)

    with patch.object(consumer, "_process_message", side_effect=record_order):
        consumer._process_batch(msgs, budget)

    # Within each partition, ascending offset order was preserved.
    p0_order = [o for (p, o) in order if p == 0]
    p1_order = [o for (p, o) in order if p == 1]
    assert p0_order == [0, 1]
    assert p1_order == [0, 1]

    # Two commits: partition 0 boundary at offset 1, partition 1 boundary at 0.
    assert mock_kafka.commit.call_count == 2
    committed = {
        (c.args[0].partition(), c.args[0].offset())
        for c in mock_kafka.commit.call_args_list
    }
    assert committed == {(0, 1), (1, 0)}


def test_batch_logs_size_for_multi_record_batch(caplog):
    """A batch with >1 record emits an INFO log carrying batch_size."""
    import logging

    consumer, _ = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)

    msgs = [_make_msg("keep-events", 0, o) for o in range(3)]
    with patch.object(consumer, "_process_message", return_value=True):
        with caplog.at_level(logging.INFO):
            consumer._process_batch(msgs, budget)

    batch_logs = [r for r in caplog.records if r.message == "Consumed Kafka batch"]
    assert len(batch_logs) == 1
    assert getattr(batch_logs[0], "batch_size", None) == 3


def test_single_record_batch_does_not_log(caplog):
    """BATCH_SIZE=1 baseline: no batch log for a single-record poll."""
    import logging

    consumer, _ = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)

    msg = _make_msg("keep-events", 0, 0)
    with patch.object(consumer, "_process_message", return_value=True):
        with caplog.at_level(logging.INFO):
            consumer._process_batch([msg], budget)

    assert not [r for r in caplog.records if r.message == "Consumed Kafka batch"]


def test_batch_size_metric_observed():
    """The consume_batch_size histogram observes the batch length each poll."""
    consumer, _ = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)

    msgs = [_make_msg("keep-events", 0, o) for o in range(4)]
    with patch("src.core.kafka_consumer.consume_batch_size") as metric:
        with patch.object(consumer, "_process_message", return_value=True):
            consumer._process_batch(msgs, budget)

    metric.observe.assert_called_once_with(4)


def test_no_commit_when_first_record_unresolved():
    """If the very first record of a partition is unresolved, nothing commits
    for that partition (offset stays put, redelivered)."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)

    msgs = [_make_msg("keep-events", 0, o) for o in range(3)]
    with patch.object(consumer, "_process_message", return_value=False):
        consumer._process_batch(msgs, budget)

    mock_kafka.commit.assert_not_called()
