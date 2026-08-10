"""SIGTERM handling: stop mid-batch, commit only the resolved prefix, and never
sit out a backoff sleep inside the termination grace period.
"""
import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from src.core.kafka_consumer import (
    KafkaEventConsumer,
    PoisonMessageError,
    RetryBudget,
    ShutdownRequested,
)
from src.models.event_dto import EventDTO


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


# -- mid-batch shutdown -------------------------------------------------


def test_batch_stops_at_shutdown_and_commits_only_the_resolved_prefix():
    """A 100-message batch must not run to completion after SIGTERM: the pod
    gets SIGKILLed, skips LeaveGroup, and strands its partitions."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(300000, shutdown_event=consumer._shutdown_event)
    msgs = [_make_msg("keep-events", 0, o) for o in range(5)]

    def process(msg, _budget):
        if msg.offset() == 1:
            consumer._shutdown_event.set()  # SIGTERM lands after offset 1
        return True

    with patch.object(consumer, "_process_message", side_effect=process) as mp:
        consumer._process_batch(msgs, budget)

    assert [c.args[0].offset() for c in mp.call_args_list] == [0, 1]
    mock_kafka.commit.assert_called_once()
    assert mock_kafka.commit.call_args.args[0].offset() == 1


def test_shutdown_before_the_first_record_commits_nothing():
    consumer, mock_kafka = _consumer_with_mock_kafka()
    consumer._shutdown_event.set()
    budget = RetryBudget(300000, shutdown_event=consumer._shutdown_event)

    with patch.object(consumer, "_process_message") as mp:
        consumer._process_batch([_make_msg("keep-events", 0, 0)], budget)

    mp.assert_not_called()
    mock_kafka.commit.assert_not_called()


def test_shutdown_stops_remaining_partitions_too():
    consumer, mock_kafka = _consumer_with_mock_kafka()
    budget = RetryBudget(300000, shutdown_event=consumer._shutdown_event)
    msgs = [_make_msg("keep-events", 0, 0), _make_msg("keep-events", 1, 0)]

    def process(msg, _budget):
        consumer._shutdown_event.set()
        return True

    with patch.object(consumer, "_process_message", side_effect=process) as mp:
        consumer._process_batch(msgs, budget)

    assert len(mp.call_args_list) == 1
    # Only the partition that actually resolved a record is committed.
    assert mock_kafka.commit.call_count == 1


def test_uncommitted_records_are_redelivered_not_recorded_as_errors():
    """Records abandoned for shutdown are healthy — they must not reach the
    terminal AlertRaw(error=True) sink."""
    consumer, _ = _consumer_with_mock_kafka()
    budget = RetryBudget(300000, shutdown_event=consumer._shutdown_event)
    msgs = [_make_msg("keep-events", 0, o) for o in range(3)]

    def process(msg, _budget):
        consumer._shutdown_event.set()
        return True

    with patch.object(consumer, "_record_terminal") as terminal:
        with patch.object(consumer, "_process_message", side_effect=process):
            consumer._process_batch(msgs, budget)

    terminal.assert_not_called()


# -- interruptible backoff ----------------------------------------------


def test_backoff_wakes_immediately_on_shutdown():
    event = threading.Event()
    event.set()
    budget = RetryBudget(300000, shutdown_event=event)

    started = time.monotonic()
    slept = budget.sleep_for(4)  # would be 16s
    elapsed = time.monotonic() - started

    assert elapsed < 1.0
    assert slept < 1.0


def test_backoff_sleeps_when_not_shutting_down():
    event = threading.Event()
    budget = RetryBudget(300000, shutdown_event=event)

    started = time.monotonic()
    budget.sleep_for(0)  # 1s
    elapsed = time.monotonic() - started

    assert elapsed >= 0.9


def test_backoff_without_an_event_still_works():
    """The event is optional so existing callers/tests keep working."""
    budget = RetryBudget(300000)

    with patch("src.core.kafka_consumer.time.sleep") as sleep:
        budget.sleep_for(2)

    sleep.assert_called_once()
    assert sleep.call_args.args[0] == pytest.approx(4.0)


def test_shutting_down_is_false_without_an_event():
    assert RetryBudget(300000).shutting_down() is False


# -- retry loop ---------------------------------------------------------


def test_retry_loop_abandons_the_message_on_shutdown():
    consumer, _ = _consumer_with_mock_kafka()
    event = consumer._shutdown_event
    budget = RetryBudget(300000, shutdown_event=event)
    dto = EventDTO(
        tenant_id="t1",
        trace_id="trace-1",
        event={"data": "x"},
        provider_type="grafana",
    )

    def fail(_dto):
        event.set()  # SIGTERM lands during the first attempt
        raise OSError("db unreachable")

    with patch("src.core.kafka_consumer.process_event_sync", side_effect=fail):
        with patch.object(consumer, "_record_terminal") as terminal:
            with pytest.raises(ShutdownRequested):
                consumer._process_with_retries(dto, budget, {"tenant_id": "t1"})

    terminal.assert_not_called()


def test_shutdown_on_the_last_attempt_does_not_burn_the_record():
    """The exhaustion branches must not win over shutdown: a healthy record
    would be written to AlertRaw(error=True) and committed purely because the
    pod was terminating during a sync."""
    consumer, _ = _consumer_with_mock_kafka()
    event = consumer._shutdown_event
    budget = RetryBudget(300000, shutdown_event=event)
    dto = EventDTO(
        tenant_id="t1",
        trace_id="trace-1",
        event={"data": "x"},
        provider_type="grafana",
    )
    attempts = {"n": 0}

    def fail(_dto):
        attempts["n"] += 1
        if attempts["n"] == 3:  # MAX_PROCESSING_RETRIES -- the last attempt
            event.set()
        raise OSError("db unreachable")

    with patch("src.core.kafka_consumer.process_event_sync", side_effect=fail):
        with patch.object(consumer, "_record_terminal") as terminal:
            with pytest.raises(ShutdownRequested):
                consumer._process_with_retries(dto, budget, {"tenant_id": "t1"})

    terminal.assert_not_called()


def test_shutdown_with_an_exhausted_budget_does_not_burn_the_record():
    consumer, _ = _consumer_with_mock_kafka()
    event = consumer._shutdown_event
    budget = RetryBudget(1, shutdown_event=event)  # budget ~0 -> exhausted
    dto = EventDTO(
        tenant_id="t1",
        trace_id="trace-1",
        event={"data": "x"},
        provider_type="grafana",
    )

    def fail(_dto):
        event.set()
        raise OSError("db unreachable")

    with patch("src.core.kafka_consumer.process_event_sync", side_effect=fail):
        with patch.object(consumer, "_record_terminal") as terminal:
            with pytest.raises(ShutdownRequested):
                consumer._process_with_retries(dto, budget, {"tenant_id": "t1"})

    terminal.assert_not_called()


def test_poison_is_still_terminal_during_shutdown():
    """Only transient failures are abandoned: a malformed payload will fail
    identically on redelivery, so it stays committed."""
    consumer, _ = _consumer_with_mock_kafka()
    event = consumer._shutdown_event
    budget = RetryBudget(300000, shutdown_event=event)
    dto = EventDTO(
        tenant_id="t1",
        trace_id="trace-1",
        event={"data": "x"},
        provider_type="grafana",
    )

    def fail(_dto):
        event.set()
        raise PoisonMessageError("unknown event_type")

    with patch("src.core.kafka_consumer.process_event_sync", side_effect=fail):
        with patch.object(consumer, "_record_terminal") as terminal:
            consumer._process_with_retries(dto, budget, {"tenant_id": "t1"})

    terminal.assert_called_once()


def test_a_consumer_told_to_stop_before_start_never_joins_the_group():
    """Closes the handover window between the entrypoint's startup handlers
    and the consumer's own."""
    event = threading.Event()
    event.set()

    with patch("src.core.kafka_consumer.Consumer") as ctor:
        consumer = KafkaEventConsumer(shutdown_event=event)
        consumer.start()

    ctor.assert_not_called()


def test_message_is_unresolved_when_shutdown_interrupts_retries():
    """_process_message must return False so the offset is never committed."""
    consumer, _ = _consumer_with_mock_kafka()
    msg = _make_msg("keep-events", 0, 7)
    budget = RetryBudget(300000, shutdown_event=consumer._shutdown_event)

    with patch.object(
        consumer, "_process_with_retries", side_effect=ShutdownRequested("stop")
    ):
        with patch.object(consumer, "_record_terminal") as terminal:
            resolved = consumer._process_message(msg, budget)

    assert resolved is False
    terminal.assert_not_called()
