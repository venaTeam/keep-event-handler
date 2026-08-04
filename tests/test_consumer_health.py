"""
Tests for the consumer health state that backs the K8s probes.

The old health server answered 200 on every path, so readiness lied (green
before the consumer was assigned anything) and liveness was meaningless (it only
proved the HTTP thread was alive). These tests pin the replacement semantics:

  readiness = consuming AND partitions assigned (or inside the revoke grace)
              AND a recent successful poll
  liveness  = consume-loop heartbeat, never failing during startup/shutdown
"""

from src.core.consumer_health import ConsumerHealth, Phase


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _health(clock=None, **kwargs):
    clock = clock or FakeClock()
    defaults = dict(
        ready_max_poll_gap=90, live_max_poll_gap=300, revoke_grace=45, clock=clock
    )
    defaults.update(kwargs)
    return ConsumerHealth(**defaults), clock


def test_starting_is_not_ready_but_is_alive():
    """The whole point of binding the health server before init_services: during
    the schema wait the pod must report a truthful 'not ready' while liveness
    stays green, instead of refusing connections and getting killed at ~90 s."""
    health, _ = _health()

    ready, payload = health.readiness()
    assert ready is False
    assert payload["phase"] == Phase.STARTING

    alive, _ = health.liveness()
    assert alive is True


def test_not_ready_while_consuming_without_assignment():
    health, _ = _health()
    health.mark_consuming()
    health.record_poll()

    ready, payload = health.readiness()
    assert ready is False
    assert "no partitions assigned" in payload["reason"]


def test_not_ready_before_first_poll():
    health, _ = _health()
    health.mark_consuming()
    health.set_assignment([0, 1])

    ready, payload = health.readiness()
    assert ready is False
    assert "no successful poll" in payload["reason"]


def test_ready_when_assigned_and_recently_polled():
    health, clock = _health()
    health.mark_consuming()
    health.set_assignment([3, 1, 2])
    health.record_poll()

    ready, payload = health.readiness()
    assert ready is True
    assert payload["phase"] == Phase.CONSUMING
    assert payload["assigned_partitions"] == [1, 2, 3]

    clock.advance(10)
    assert health.readiness()[0] is True


def test_not_ready_when_poll_is_stale():
    health, clock = _health()
    health.mark_consuming()
    health.set_assignment([0])
    health.record_poll()

    clock.advance(91)
    ready, payload = health.readiness()
    assert ready is False
    assert "exceeds 90s" in payload["reason"]


def test_revoke_grace_keeps_pod_ready_through_a_rebalance():
    """A routine rebalance must not instantly flip the pod NotReady — that would
    stall a maxUnavailable: 0 rollout."""
    health, clock = _health()
    health.mark_consuming()
    health.set_assignment([0])
    health.record_poll()

    health.clear_assignment()
    ready, payload = health.readiness()
    assert ready is True
    assert "grace" in payload["reason"]

    # ...but a revoke that never resolves does eventually go NotReady.
    clock.advance(46)
    ready, payload = health.readiness()
    assert ready is False
    assert "no partitions assigned" in payload["reason"]


def test_reassignment_clears_the_grace_window():
    health, clock = _health()
    health.mark_consuming()
    health.set_assignment([0])
    health.record_poll()

    health.clear_assignment()  # opens the grace window
    clock.advance(10)
    health.set_assignment([5])
    health.record_poll()

    clock.advance(50)  # past the revoke grace, but we are assigned again
    assert health.readiness()[0] is True


def test_never_assigned_consumer_gets_no_revoke_grace():
    """The grace only applies to a consumer that actually held partitions. A pod
    that has never been assigned anything must never report ready, or a rollout
    would advance on a pod that isn't consuming."""
    health, _ = _health()
    health.mark_consuming()
    health.record_poll()

    health.clear_assignment()
    ready, payload = health.readiness()
    assert ready is False
    assert "no partitions assigned" in payload["reason"]


def test_liveness_fails_only_on_a_stalled_loop():
    health, clock = _health()
    health.mark_consuming()
    health.set_assignment([0])
    health.record_poll()

    clock.advance(120)  # past readiness gap, still well inside liveness
    assert health.readiness()[0] is False
    assert health.liveness()[0] is True

    clock.advance(200)  # 320s total
    alive, payload = health.liveness()
    assert alive is False
    assert "stalled" in payload["reason"]


def test_liveness_catches_a_loop_that_never_polls():
    """A loop that wedges before its first poll is measured from loop start."""
    health, clock = _health()
    health.mark_consuming()

    clock.advance(301)
    alive, payload = health.liveness()
    assert alive is False
    assert "stalled" in payload["reason"]


def test_liveness_stays_green_while_draining():
    """Never let liveness kill a pod that is shutting down: that truncates the
    in-flight batch and skips the clean LeaveGroup."""
    health, clock = _health()
    health.mark_consuming()
    health.set_assignment([0])
    health.record_poll()
    health.mark_stopping()

    clock.advance(600)
    assert health.liveness()[0] is True
    assert health.readiness()[0] is False


def test_stopped_clears_assignment_and_is_not_ready():
    health, _ = _health()
    health.mark_consuming()
    health.set_assignment([0, 1])
    health.record_poll()
    health.mark_stopped()

    ready, payload = health.readiness()
    assert ready is False
    assert payload["assigned_partitions"] == []
