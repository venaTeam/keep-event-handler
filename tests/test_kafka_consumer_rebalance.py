"""Cooperative-sticky rebalancing.

NOTE: these tests use a mocked consumer, so they verify the application's half
of the protocol (incremental assign/unassign, no commit on lost, readiness
rebuilt from consumer.assignment()). They cannot validate protocol behaviour
against a real broker — that needs a dev-cluster full-group restart.
"""
from unittest.mock import MagicMock, patch

import pytest

from src.core.consumer_health import ConsumerPhase, consumer_health
from src.core.kafka_consumer import KafkaEventConsumer


@pytest.fixture(autouse=True)
def clean_health():
    consumer_health.reset_for_tests()
    yield
    consumer_health.reset_for_tests()


def _partition(partition, topic="keep-events"):
    p = MagicMock()
    p.topic = topic
    p.partition = partition
    return p


def _consumer(strategy=None, assignment=None):
    env = {} if strategy is None else {"KAFKA_PARTITION_ASSIGNMENT_STRATEGY": strategy}
    with patch.dict("os.environ", env, clear=False):
        with patch("src.core.kafka_consumer.Consumer", return_value=MagicMock()):
            consumer = KafkaEventConsumer()
    mock_kafka = MagicMock()
    mock_kafka.assignment.return_value = list(assignment or [])
    consumer._consumer = mock_kafka
    return consumer, mock_kafka


# -- configuration ------------------------------------------------------


def test_cooperative_sticky_is_the_default():
    consumer, _ = _consumer()

    assert consumer._build_consumer_config()["partition.assignment.strategy"] == (
        "cooperative-sticky"
    )


def test_strategy_is_the_rollback_lever():
    consumer, _ = _consumer(strategy="range,roundrobin")

    conf = consumer._build_consumer_config()
    assert conf["partition.assignment.strategy"] == "range,roundrobin"
    assert consumer._is_cooperative is False


def test_lost_handler_is_registered():
    """Without on_lost, confluent-kafka routes lost partitions to on_revoke as
    an ordinary rebalance."""
    with patch("src.core.kafka_consumer.Consumer") as ctor:
        consumer = KafkaEventConsumer()
        consumer._consume_loop = MagicMock()
        consumer._cleanup = MagicMock()
        with patch("src.core.kafka_consumer.signal.signal"):
            consumer.start()

    kwargs = ctor.return_value.subscribe.call_args.kwargs
    assert kwargs["on_lost"] == consumer._on_lost


# -- the application half of the protocol --------------------------------


def test_assign_applies_the_partitions_itself():
    """librdkafka does not apply a cooperative assignment for you; skipping
    this leaves the consumer processing nothing while looking healthy."""
    consumer, mock_kafka = _consumer()
    parts = [_partition(0), _partition(1)]

    consumer._on_assign(mock_kafka, parts)

    mock_kafka.incremental_assign.assert_called_once_with(parts)


def test_eager_does_not_call_incremental_assign():
    consumer, mock_kafka = _consumer(strategy="range,roundrobin")

    consumer._on_assign(mock_kafka, [_partition(0)])

    mock_kafka.incremental_assign.assert_not_called()


def test_revoke_unassigns_only_the_moved_partitions():
    consumer, mock_kafka = _consumer()
    moved = [_partition(1)]

    consumer._on_revoke(mock_kafka, moved)

    mock_kafka.incremental_unassign.assert_called_once_with(moved)


def test_partial_revoke_keeps_the_pod_ready():
    """The delta trap: recording the callback argument verbatim would read a
    partial revoke as 'I own nothing' and flip the pod NotReady, stalling a
    maxUnavailable: 0 rollout."""
    consumer, mock_kafka = _consumer(assignment=[_partition(0), _partition(2)])
    consumer_health.set_phase(ConsumerPhase.CONSUMING)

    consumer._on_revoke(mock_kafka, [_partition(1)])  # one partition moved away

    assert consumer_health.snapshot()["partitions"] == 2
    ready, reason = consumer_health.is_ready()
    assert ready is True
    assert "2 partition" in reason


def test_assignment_is_rebuilt_from_the_consumer_not_the_callback():
    consumer, mock_kafka = _consumer(assignment=[_partition(i) for i in range(4)])
    consumer_health.set_phase(ConsumerPhase.CONSUMING)

    consumer._on_assign(mock_kafka, [_partition(3)])  # delta of one

    assert consumer_health.snapshot()["partitions"] == 4


def test_assignment_falls_back_to_the_callback_partitions():
    consumer, mock_kafka = _consumer()
    mock_kafka.assignment.side_effect = RuntimeError("broker gone")
    consumer_health.set_phase(ConsumerPhase.CONSUMING)

    consumer._on_assign(mock_kafka, [_partition(0), _partition(1)])

    assert consumer_health.snapshot()["partitions"] == 2


# -- lost partitions -----------------------------------------------------


def test_lost_partitions_are_never_committed():
    """They may already be owned by another member — committing here writes an
    offset for records that member is re-processing."""
    consumer, mock_kafka = _consumer()

    consumer._on_lost(mock_kafka, [_partition(0)])

    mock_kafka.commit.assert_not_called()


def test_lost_partitions_are_unassigned_and_clear_readiness():
    consumer, mock_kafka = _consumer(assignment=[])
    consumer_health.set_phase(ConsumerPhase.CONSUMING)
    lost = [_partition(0)]

    consumer._on_lost(mock_kafka, lost)

    mock_kafka.incremental_unassign.assert_called_once_with(lost)
    assert consumer_health.snapshot()["partitions"] == 0
    # Still inside the revoke grace: a lost partition is a rebalance, not a
    # reason to fail the rollout instantly.
    assert consumer_health.is_ready()[0] is True
