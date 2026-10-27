"""Unit tests for the consumer health state backing /readyz and /livez.

The clock is injected rather than frozen: the implementation deliberately uses
time.monotonic(), which freezegun does not patch.
"""
import pytest

from src.core.consumer_health import ConsumerHealth, ConsumerPhase


class FakeClock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakePartition:
    def __init__(self, topic: str, partition: int):
        self.topic = topic
        self.partition = partition


def make_health(clock=None, **kwargs) -> ConsumerHealth:
    defaults = dict(
        ready_max_poll_gap=90,
        live_max_poll_gap=300,
        revoke_grace=45,
        require_partitions=True,
    )
    defaults.update(kwargs)
    return ConsumerHealth(clock=clock or FakeClock(), **defaults)


def consuming(health: ConsumerHealth, partitions=(("keep-events", 0),)):
    health.set_phase(ConsumerPhase.CONSUMING)
    health.set_assignment([FakePartition(t, p) for t, p in partitions])
    health.mark_poll()
    return health


# -- startup ------------------------------------------------------------


def test_starting_is_live_but_not_ready():
    """The whole point of binding the server early: a booting pod must answer
    'alive, not ready' instead of refusing connections."""
    health = make_health()

    live, _ = health.is_live()
    ready, reason = health.is_ready()

    assert live is True
    assert ready is False
    assert "starting" in reason


def test_starting_stays_live_past_every_gap():
    clock = FakeClock()
    health = make_health(clock)

    clock.advance(10_000)

    assert health.is_live()[0] is True


# -- readiness ----------------------------------------------------------


def test_ready_when_consuming_with_partitions_and_recent_poll():
    health = consuming(make_health())

    ready, reason = health.is_ready()

    assert ready is True
    assert "1 partition" in reason


def test_not_ready_without_partitions():
    health = make_health()
    health.set_phase(ConsumerPhase.CONSUMING)
    health.mark_poll()

    ready, reason = health.is_ready()

    assert ready is False
    assert reason == "no partitions assigned"


def test_ready_without_partitions_when_requirement_relaxed():
    """The <= 15-partition topic case: a surge pod Kafka gives nothing is
    healthy, just idle, and must be able to go green."""
    health = make_health(require_partitions=False)
    health.set_phase(ConsumerPhase.CONSUMING)
    health.mark_poll()

    assert health.is_ready()[0] is True


def test_not_ready_when_poll_is_stale():
    clock = FakeClock()
    health = consuming(make_health(clock))

    clock.advance(91)

    ready, reason = health.is_ready()
    assert ready is False
    assert "no poll for" in reason


def test_empty_poll_keeps_readiness_green():
    """An idle topic must not look wedged — mark_poll() is called on every poll
    return, records or not."""
    clock = FakeClock()
    health = consuming(make_health(clock))

    for _ in range(10):
        clock.advance(60)
        health.mark_poll()

    assert health.is_ready()[0] is True


# -- rebalance ----------------------------------------------------------


def test_revoke_grace_keeps_pod_ready_during_a_rebalance():
    clock = FakeClock()
    health = consuming(make_health(clock))

    health.set_assignment([])  # everything revoked
    health.mark_revoke()
    clock.advance(30)
    health.mark_poll()

    ready, reason = health.is_ready()
    assert ready is True
    assert "grace" in reason


def test_revoke_grace_expires():
    clock = FakeClock()
    health = consuming(make_health(clock))

    health.set_assignment([])
    health.mark_revoke()
    clock.advance(46)
    health.mark_poll()

    ready, reason = health.is_ready()
    assert ready is False
    assert reason == "no partitions assigned"


def test_assignment_is_replaced_not_merged():
    """set_assignment takes the FULL set from consumer.assignment(); a partial
    cooperative revoke must not leave stale partitions behind."""
    health = make_health()
    health.set_assignment([FakePartition("keep-events", i) for i in range(3)])

    health.set_assignment([FakePartition("keep-events", 0)])

    assert health.snapshot()["partitions"] == 1


# -- liveness -----------------------------------------------------------


def test_live_while_polling():
    clock = FakeClock()
    health = consuming(make_health(clock))

    clock.advance(299)

    assert health.is_live()[0] is True


def test_not_live_when_loop_wedges():
    clock = FakeClock()
    health = consuming(make_health(clock))

    clock.advance(301)

    live, reason = health.is_live()
    assert live is False
    assert "no poll for" in reason


def test_live_gap_is_looser_than_ready_gap():
    """A pod that stops polling should go NotReady (stop taking rollout credit)
    well before it is restarted."""
    clock = FakeClock()
    health = consuming(make_health(clock))

    clock.advance(120)

    assert health.is_ready()[0] is False
    assert health.is_live()[0] is True


def test_stopping_is_live_but_not_ready():
    """Draining after SIGTERM: don't count for the rollout, don't get killed."""
    clock = FakeClock()
    health = consuming(make_health(clock))
    health.set_phase(ConsumerPhase.STOPPING)

    clock.advance(600)

    assert health.is_live()[0] is True
    assert health.is_ready()[0] is False


def test_phase_entry_seeds_the_poll_clock():
    """Entering the loop counts as a poll, so the first probe after startup
    isn't judged against a missing timestamp."""
    clock = FakeClock()
    health = make_health(clock)

    health.set_phase(ConsumerPhase.CONSUMING)
    health.set_assignment([FakePartition("keep-events", 0)])

    assert health.is_ready()[0] is True


def test_snapshot_shape():
    clock = FakeClock()
    health = consuming(make_health(clock))
    clock.advance(5)

    snap = health.snapshot()

    assert snap["phase"] == "consuming"
    assert snap["partitions"] == 1
    assert snap["last_poll_age_seconds"] == pytest.approx(5.0)
    assert snap["revoke_age_seconds"] is None
