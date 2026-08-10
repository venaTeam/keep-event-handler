"""The consume loop and rebalance callbacks actually drive the probe state."""
from unittest.mock import MagicMock, patch

import pytest

from src.core.consumer_health import ConsumerPhase, consumer_health
from src.core.kafka_consumer import KafkaEventConsumer


@pytest.fixture(autouse=True)
def clean_health():
    consumer_health.reset_for_tests()
    yield
    consumer_health.reset_for_tests()


def _consumer_with_mock_kafka():
    mock_consumer_instance = MagicMock()
    # The rebalance callbacks rebuild readiness from consumer.assignment(),
    # never from the callback argument (the cooperative protocol delivers
    # deltas), so the mock has to answer it.
    mock_consumer_instance.assignment.return_value = []
    with patch("src.core.kafka_consumer.Consumer", return_value=mock_consumer_instance):
        consumer = KafkaEventConsumer()
    consumer._consumer = mock_consumer_instance
    return consumer, mock_consumer_instance


def _partition(topic="keep-events", partition=0):
    p = MagicMock()
    p.topic = topic
    p.partition = partition
    return p


def test_entering_the_loop_flips_the_phase_to_consuming():
    consumer, mock_kafka = _consumer_with_mock_kafka()
    polls = []

    def consume(**kwargs):
        polls.append(consumer_health.snapshot()["phase"])
        consumer._running = False
        return []

    mock_kafka.consume.side_effect = consume
    consumer._running = True

    consumer._consume_loop()

    assert polls == ["consuming"]


def test_empty_polls_keep_the_liveness_clock_fresh():
    """An idle topic must not read as a wedged loop."""
    consumer, mock_kafka = _consumer_with_mock_kafka()
    calls = {"n": 0}

    def consume(**kwargs):
        calls["n"] += 1
        if calls["n"] >= 3:
            consumer._running = False
        return []

    mock_kafka.consume.side_effect = consume
    consumer._running = True

    consumer._consume_loop()

    snap = consumer_health.snapshot()
    assert snap["last_poll_age_seconds"] is not None
    assert consumer_health.is_live()[0] is True


def test_assign_makes_the_pod_ready():
    consumer, mock_kafka = _consumer_with_mock_kafka()
    consumer_health.set_phase(ConsumerPhase.CONSUMING)

    assert consumer_health.is_ready()[0] is False  # nothing owned yet

    assigned = [_partition(partition=0), _partition(partition=1)]
    mock_kafka.assignment.return_value = assigned
    consumer._on_assign(mock_kafka, assigned)

    ready, reason = consumer_health.is_ready()
    assert ready is True
    assert "2 partition" in reason


def test_revoke_clears_the_assignment_but_holds_readiness_in_grace():
    consumer, mock_kafka = _consumer_with_mock_kafka()
    consumer_health.set_phase(ConsumerPhase.CONSUMING)
    consumer._on_assign(mock_kafka, [_partition()])

    consumer._on_revoke(mock_kafka, [_partition()])

    assert consumer_health.snapshot()["partitions"] == 0
    ready, reason = consumer_health.is_ready()
    assert ready is True
    assert "grace" in reason


def test_stop_marks_stopping_and_cleanup_marks_stopped():
    consumer, mock_kafka = _consumer_with_mock_kafka()
    consumer_health.set_phase(ConsumerPhase.CONSUMING)
    consumer._on_assign(mock_kafka, [_partition()])

    consumer.stop()
    assert consumer_health.snapshot()["phase"] == "stopping"
    # Draining: no longer counts toward the rollout, but must not be restarted.
    assert consumer_health.is_ready()[0] is False
    assert consumer_health.is_live()[0] is True

    consumer._cleanup()
    snap = consumer_health.snapshot()
    assert snap["phase"] == "stopped"
    assert snap["partitions"] == 0


def test_signal_handler_marks_stopping():
    consumer, _ = _consumer_with_mock_kafka()
    consumer_health.set_phase(ConsumerPhase.CONSUMING)

    consumer._signal_handler(15, None)

    assert consumer._shutdown_event.is_set()
    assert consumer_health.snapshot()["phase"] == "stopping"
