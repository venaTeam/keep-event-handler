"""
Tests for cooperative-sticky rebalancing support.

Default (eager) rebalancing makes every member surrender **all** its partitions on
any membership change, so the whole group stops consuming — even the members whose
partitions never move. A 15-pod rollout is ~30 of those pauses, which is why a 20 s
end-to-end check eventually lands inside one.

Two things these tests pin:

* the default path stays byte-for-byte what it was, so the image ships inert;
* on the cooperative path the callbacks receive **deltas**, and readiness is
  rebuilt from `consumer.assignment()` rather than from the delta — recording the
  delta would flip a pod NotReady mid-rebalance and, with `maxUnavailable: 0`,
  stall the rollout.

⚠️ These use a mocked consumer. They verify *our* logic, not librdkafka's protocol
behaviour — cooperative mode still needs a live-broker test before it is enabled
anywhere.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.core.consumer_health import ConsumerHealth
from src.core.kafka_consumer import KafkaEventConsumer


def _tp(partition: int, topic: str = "keep-events"):
    tp = MagicMock()
    tp.partition = partition
    tp.topic = topic
    return tp


def _consumer(monkeypatch, strategy=None):
    monkeypatch.delenv("KAFKA_PARTITION_ASSIGNMENT_STRATEGY", raising=False)
    if strategy is not None:
        monkeypatch.setenv("KAFKA_PARTITION_ASSIGNMENT_STRATEGY", strategy)
    with patch("src.core.kafka_consumer.Consumer", return_value=MagicMock()):
        consumer = KafkaEventConsumer()
    consumer._consumer = MagicMock()
    return consumer


@pytest.fixture
def health(monkeypatch):
    """Fresh health object, so assignment state doesn't leak between tests."""
    fresh = ConsumerHealth()
    monkeypatch.setattr("src.core.kafka_consumer.consumer_health", fresh)
    return fresh


# --------------------------------------------------------------------------- #
# Default path stays inert
# --------------------------------------------------------------------------- #


def test_cooperative_sticky_is_the_default(monkeypatch):
    """Cooperative is the default, so deploying the image *is* the group
    migration — it cannot be a rolling deploy."""
    consumer = _consumer(monkeypatch)

    assert consumer._cooperative is True
    conf = consumer._build_consumer_config()
    assert conf["partition.assignment.strategy"] == "cooperative-sticky"


def test_eager_can_still_be_selected(monkeypatch):
    """The escape hatch back to eager, for a rollback — which is itself a full
    group restart."""
    consumer = _consumer(monkeypatch, "range,roundrobin")

    assert consumer._cooperative is False
    conf = consumer._build_consumer_config()
    assert conf["partition.assignment.strategy"] == "range,roundrobin"


def test_eager_assign_records_the_full_argument(monkeypatch, health):
    """Eager: the callback argument *is* the whole assignment, and librdkafka
    applies it — we must not call incremental_assign."""
    consumer = _consumer(monkeypatch, "range,roundrobin")

    consumer._on_assign(consumer._consumer, [_tp(0), _tp(1)])

    consumer._consumer.incremental_assign.assert_not_called()
    assert health.snapshot()["assigned_partitions"] == [0, 1]


def test_eager_revoke_clears_everything(monkeypatch, health):
    consumer = _consumer(monkeypatch, "range,roundrobin")
    health.set_assignment([0, 1])

    consumer._on_revoke(consumer._consumer, [_tp(0), _tp(1)])

    consumer._consumer.incremental_unassign.assert_not_called()
    assert health.snapshot()["assigned_partitions"] == []


# --------------------------------------------------------------------------- #
# Cooperative path
# --------------------------------------------------------------------------- #


def test_strategy_is_emitted_when_configured(monkeypatch):
    consumer = _consumer(monkeypatch, "cooperative-sticky")

    assert consumer._cooperative is True
    conf = consumer._build_consumer_config()
    assert conf["partition.assignment.strategy"] == "cooperative-sticky"


def test_cooperative_assign_applies_the_delta_itself(monkeypatch, health):
    """Under the cooperative protocol librdkafka does NOT apply the assignment —
    the application must, or the consumer silently consumes nothing while looking
    perfectly healthy."""
    consumer = _consumer(monkeypatch, "cooperative-sticky")
    consumer._consumer.assignment.return_value = [_tp(0), _tp(1), _tp(2)]

    consumer._on_assign(consumer._consumer, [_tp(2)])  # delta: one new partition

    consumer._consumer.incremental_assign.assert_called_once()
    # Readiness reflects everything owned, not just the delta.
    assert health.snapshot()["assigned_partitions"] == [0, 1, 2]


def test_cooperative_partial_revoke_keeps_the_pod_ready(monkeypatch, health):
    """The regression this guards: a partial revoke must not read as "I own
    nothing". Recording the delta would flip the pod NotReady mid-rebalance and
    stall a maxUnavailable: 0 rollout."""
    consumer = _consumer(monkeypatch, "cooperative-sticky")
    health.mark_consuming()
    health.set_assignment([0, 1, 2])
    health.record_poll()
    # Two partitions move away; one stays.
    consumer._consumer.assignment.return_value = [_tp(0)]

    consumer._on_revoke(consumer._consumer, [_tp(1), _tp(2)])

    consumer._consumer.incremental_unassign.assert_called_once()
    assert health.snapshot()["assigned_partitions"] == [0]
    assert health.readiness()[0] is True  # still consuming partition 0


def test_cooperative_full_revoke_clears_assignment(monkeypatch, health):
    consumer = _consumer(monkeypatch, "cooperative-sticky")
    health.set_assignment([0, 1])
    consumer._consumer.assignment.return_value = []

    consumer._on_revoke(consumer._consumer, [_tp(0), _tp(1)])

    assert health.snapshot()["assigned_partitions"] == []


# --------------------------------------------------------------------------- #
# on_lost
# --------------------------------------------------------------------------- #


def test_on_lost_never_commits(monkeypatch, health):
    """Lost partitions may already be owned by another member — committing for
    them is at best rejected and at worst overwrites a newer owner's progress."""
    consumer = _consumer(monkeypatch, "cooperative-sticky")
    consumer._consumer.assignment.return_value = []

    consumer._on_lost(consumer._consumer, [_tp(0), _tp(1)])

    consumer._consumer.commit.assert_not_called()


def test_on_lost_clears_assignment_on_the_eager_path(monkeypatch, health):
    consumer = _consumer(monkeypatch, "range,roundrobin")
    health.set_assignment([0, 1])

    consumer._on_lost(consumer._consumer, [_tp(0), _tp(1)])

    consumer._consumer.commit.assert_not_called()
    assert health.snapshot()["assigned_partitions"] == []


def test_on_lost_is_registered_so_it_does_not_fall_through_to_revoke(monkeypatch):
    """Without an explicit on_lost, confluent-kafka routes lost partitions to
    on_revoke — which treats them as an ordinary rebalance."""
    consumer = _consumer(monkeypatch)
    with patch("src.core.kafka_consumer.Consumer", return_value=consumer._consumer):
        with patch.object(consumer, "_consume_loop"), patch.object(consumer, "_cleanup"):
            with patch("src.core.kafka_consumer.signal.signal"):
                consumer.start()

    kwargs = consumer._consumer.subscribe.call_args.kwargs
    assert kwargs["on_lost"] == consumer._on_lost


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #


def test_unreadable_assignment_does_not_raise_into_the_rebalance(monkeypatch, health):
    """An exception escaping a rebalance callback leaves the consumer in an
    undefined state — worse than stale readiness."""
    consumer = _consumer(monkeypatch, "cooperative-sticky")
    health.set_assignment([0])
    consumer._consumer.assignment.side_effect = RuntimeError("not assigned")

    consumer._on_assign(consumer._consumer, [_tp(1)])  # must not raise

    # State left as it was rather than corrupted.
    assert health.snapshot()["assigned_partitions"] == [0]
