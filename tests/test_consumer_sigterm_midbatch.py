"""
Tests that SIGTERM is honored *between messages* of an in-flight batch.

Before this, `_process_batch` iterated the whole batch without re-checking the
shutdown flag: with KAFKA_CONSUMER_BATCH_SIZE=100 and up to
MAX_PROCESSING_RETRIES per message (each backing off up to
KAFKA_RETRY_MAX_SLEEP_SECONDS), a batch could outlive
terminationGracePeriodSeconds. Kubernetes then SIGKILLed the pod, so it never
sent LeaveGroup and the coordinator held its partitions unassigned for up to
session.timeout.ms — the stranded-partition stall behind the ingestion lag.
"""

import json
import threading
import time
from unittest.mock import MagicMock, patch

from src.config.consts import MAX_PROCESSING_RETRIES
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


def test_shutdown_midbatch_stops_processing_and_commits_progress():
    """SIGTERM after 2 of 5 records: records 0-1 are committed, 2-4 are left for
    redelivery (at-least-once), and the loop can exit inside its grace period."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)
    msgs = [_make_msg("keep-events", 0, o) for o in range(5)]

    processed = []

    def process(msg, b):
        processed.append(msg.offset())
        if msg.offset() == 1:
            # Simulate the SIGTERM handler firing while this message is in flight.
            consumer._signal_handler(15, None)
        return True

    with patch.object(consumer, "_process_message", side_effect=process):
        consumer._process_batch(msgs, budget)

    assert processed == [0, 1]
    mock_kafka.commit.assert_called_once()
    assert mock_kafka.commit.call_args.args[0].offset() == 1


def test_shutdown_before_any_record_commits_nothing():
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)
    msgs = [_make_msg("keep-events", 0, o) for o in range(3)]

    consumer.stop()  # shutdown already signalled when the batch starts

    with patch.object(consumer, "_process_message", return_value=True) as mp:
        consumer._process_batch(msgs, budget)

    mp.assert_not_called()
    mock_kafka.commit.assert_not_called()


def test_shutdown_midbatch_does_not_start_another_partition():
    """Draining must not begin a fresh partition's records — everything it
    doesn't touch stays uncommitted and is redelivered."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)
    msgs = [
        _make_msg("keep-events", 0, 0),
        _make_msg("keep-events", 0, 1),
        _make_msg("keep-events", 1, 0),
        _make_msg("keep-events", 1, 1),
    ]

    def process(msg, b):
        if msg.partition() == 0 and msg.offset() == 0:
            consumer._signal_handler(15, None)
        return True

    with patch.object(consumer, "_process_message", side_effect=process) as mp:
        consumer._process_batch(msgs, budget)

    touched = {(c.args[0].partition(), c.args[0].offset()) for c in mp.call_args_list}
    assert touched == {(0, 0)}
    # Only partition 0's boundary is committed; partition 1 is untouched.
    assert mock_kafka.commit.call_count == 1
    committed = mock_kafka.commit.call_args.args[0]
    assert (committed.partition(), committed.offset()) == (0, 0)


def test_no_shutdown_processes_the_whole_batch():
    """Baseline: with no shutdown signalled, behaviour is unchanged."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000)
    msgs = [_make_msg("keep-events", 0, o) for o in range(4)]

    with patch.object(consumer, "_process_message", return_value=True) as mp:
        consumer._process_batch(msgs, budget)

    assert len(mp.call_args_list) == 4
    assert mock_kafka.commit.call_args.args[0].offset() == 3


def test_retry_backoff_wakes_immediately_on_shutdown():
    """A 30 s backoff that ignores SIGTERM burns the termination grace period
    doing nothing."""
    stop = threading.Event()
    budget = RetryBudget(max_poll_interval_ms=300000, stop_event=stop)

    timer = threading.Timer(0.05, stop.set)
    timer.start()
    try:
        started = time.monotonic()
        budget.sleep_for(attempt=4)  # would otherwise sleep 16s
        elapsed = time.monotonic() - started
    finally:
        timer.cancel()

    assert elapsed < 2


def test_retries_abort_on_shutdown_and_leave_the_message_uncommitted():
    """The in-flight message is abandoned for redelivery rather than retried
    (up to MAX_PROCESSING_RETRIES × KAFKA_RETRY_MAX_SLEEP_SECONDS) inside a
    grace period the pod no longer has."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(
        max_poll_interval_ms=300000, stop_event=consumer._shutdown_event
    )
    msg = _make_msg("keep-events", 0, 9)

    attempts = []

    def failing_process(event_dto):
        attempts.append(1)
        consumer._signal_handler(15, None)  # SIGTERM lands during attempt 1
        raise OSError("transient DB error")

    with patch("src.core.kafka_consumer.process_event_sync", side_effect=failing_process):
        with patch.object(consumer, "_record_terminal") as terminal:
            should_commit = consumer._process_message(msg, budget)

    assert should_commit is False  # unresolved -> not committed -> redelivered
    assert len(attempts) == 1  # no further retries after the signal
    terminal.assert_not_called()  # not a poison/terminal outcome


def test_retries_continue_normally_without_a_shutdown():
    """Baseline: with no signal, transient errors still exhaust their retries and
    end in the terminal sink (committed)."""
    consumer, _ = _consumer_with_mock_kafka()
    budget = RetryBudget(max_poll_interval_ms=300000, stop_event=consumer._shutdown_event)
    msg = _make_msg("keep-events", 0, 3)

    attempts = []

    def failing_process(event_dto):
        attempts.append(1)
        raise OSError("transient DB error")

    with patch("src.core.kafka_consumer.process_event_sync", side_effect=failing_process):
        with patch.object(consumer, "_record_terminal") as terminal:
            with patch.object(budget, "sleep_for", return_value=0.0):
                should_commit = consumer._process_message(msg, budget)

    assert should_commit is True
    assert len(attempts) == MAX_PROCESSING_RETRIES
    terminal.assert_called_once()


def test_offsets_are_never_stored_automatically():
    """librdkafka defaults `enable.auto.offset.store` to true, which advances an
    in-memory offset store the moment a record is *delivered*. A bare commit()
    would then flush offsets for records this batch deliberately abandoned,
    silently skipping them even though enable.auto.commit is false."""
    consumer, _ = _consumer_with_mock_kafka()
    conf = consumer._build_consumer_config()

    assert conf["enable.auto.commit"] is False
    assert conf["enable.auto.offset.store"] is False


def test_revoke_does_not_blind_commit_delivered_offsets():
    """The rebalance that follows a drain must not commit what the drain left
    uncommitted — otherwise honoring SIGTERM mid-batch loses the records it was
    protecting."""
    consumer, mock_kafka = _consumer_with_mock_kafka()

    consumer._on_revoke(mock_kafka, [MagicMock(partition=0)])

    mock_kafka.commit.assert_not_called()


def test_signal_handler_marks_health_stopping():
    consumer, _ = _consumer_with_mock_kafka()
    from src.core.consumer_health import Phase, consumer_health

    consumer._signal_handler(15, None)
    assert consumer_health.snapshot()["phase"] == Phase.STOPPING
    # Liveness must stay green while draining.
    assert consumer_health.liveness()[0] is True
