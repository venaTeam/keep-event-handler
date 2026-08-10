"""Process-wide consumer health state, and the two probe decisions built on it.

Why this exists as a module-level singleton rather than state on
KafkaEventConsumer: the health server has to bind *before* init_services(), so
kubelet gets "alive, not ready" instead of connection-refused during the schema
wait. At that point no consumer object exists yet, so the probes cannot reach
into one.

All timestamps are time.monotonic(). A wall-clock step (NTP correction, a
container clock jump) must never be able to make a wedged consume loop look
freshly polled.
"""
import logging
import threading
import time
from enum import Enum
from typing import Iterable, Optional, Tuple

from src.config.config import config

logger = logging.getLogger(__name__)


class ConsumerPhase(str, Enum):
    """Lifecycle of the consume loop, as the probes see it."""

    STARTING = "starting"  # process up, loop not running yet (init/schema wait)
    CONSUMING = "consuming"  # loop entered
    STOPPING = "stopping"  # SIGTERM received, draining
    STOPPED = "stopped"  # loop exited, consumer closed


# Readiness fails if the last poll is older than this. Readiness gates the
# rollout (maxUnavailable: 0), so it should react faster than liveness.
READY_MAX_POLL_GAP_SECONDS = config(
    "KEEP_CONSUMER_READY_MAX_POLL_GAP_SECONDS", default=90, cast=int
)

# Liveness fails if the loop stops polling for this long. MUST stay above the
# retry budget (KAFKA_RETRY_POLL_GAP_SAFETY_FACTOR * max.poll.interval.ms),
# or Kubernetes will kill pods that are retrying exactly as designed.
LIVE_MAX_POLL_GAP_SECONDS = config(
    "KEEP_CONSUMER_LIVE_MAX_POLL_GAP_SECONDS", default=300, cast=int
)

# Readiness stays green this long after a revoke, so an ordinary rebalance
# doesn't flip the whole group NotReady at once and stall a maxUnavailable: 0
# rollout.
REVOKE_GRACE_SECONDS = config(
    "KEEP_CONSUMER_REVOKE_GRACE_SECONDS", default=45, cast=int
)

# Set false when the topic has fewer partitions than replicas: with
# maxSurge: 1 Kubernetes adds one more pod than there are partitions, Kafka
# legitimately assigns it none, and a strict "owns >= 1 partition" rule would
# never go green — stalling every rolling update forever.
READY_REQUIRE_PARTITIONS = config(
    "KEEP_CONSUMER_READY_REQUIRE_PARTITIONS", default=True, cast=bool
)


class ConsumerHealth:
    """Lock-guarded snapshot of what the consume loop is doing.

    Writers are the consumer (poll loop + rebalance callbacks); readers are the
    probe handlers on the health server thread.
    """

    def __init__(
        self,
        clock=time.monotonic,
        ready_max_poll_gap: int = READY_MAX_POLL_GAP_SECONDS,
        live_max_poll_gap: int = LIVE_MAX_POLL_GAP_SECONDS,
        revoke_grace: int = REVOKE_GRACE_SECONDS,
        require_partitions: bool = READY_REQUIRE_PARTITIONS,
    ):
        self._clock = clock
        self._ready_max_poll_gap = ready_max_poll_gap
        self._live_max_poll_gap = live_max_poll_gap
        self._revoke_grace = revoke_grace
        self._require_partitions = require_partitions

        self._lock = threading.Lock()
        self._phase = ConsumerPhase.STARTING
        self._assignment: frozenset = frozenset()
        self._last_poll: Optional[float] = None
        self._last_revoke: Optional[float] = None

    # -- writers ---------------------------------------------------------

    def set_phase(self, phase: ConsumerPhase) -> None:
        with self._lock:
            if phase == self._phase:
                return
            self._phase = phase
            if phase == ConsumerPhase.CONSUMING:
                # Measure the first poll gap from loop entry, not from an
                # absent timestamp — otherwise the probes would have to treat
                # "never polled" and "stopped polling" identically.
                self._last_poll = self._clock()
        logger.info("Consumer phase -> %s", phase.value)

    def mark_poll(self) -> None:
        """Called on every poll return, including empty ones. An empty poll is
        proof the loop is alive; requiring records would make an idle topic
        look wedged."""
        with self._lock:
            self._last_poll = self._clock()

    def set_assignment(self, partitions: Iterable) -> None:
        """Record the FULL current assignment.

        Callers must pass consumer.assignment(), never the callback argument:
        under the cooperative protocol the callbacks deliver deltas, so
        recording the argument verbatim would read a partial revoke as "I own
        nothing" and flap the pod NotReady mid-rebalance.
        """
        current = frozenset((p.topic, p.partition) for p in partitions)
        with self._lock:
            self._assignment = current

    def mark_revoke(self) -> None:
        with self._lock:
            self._last_revoke = self._clock()

    def reset_for_tests(self) -> None:
        with self._lock:
            self._phase = ConsumerPhase.STARTING
            self._assignment = frozenset()
            self._last_poll = None
            self._last_revoke = None

    # -- readers ---------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            now = self._clock()
            return {
                "phase": self._phase.value,
                "partitions": len(self._assignment),
                "last_poll_age_seconds": (
                    None if self._last_poll is None else round(now - self._last_poll, 3)
                ),
                "revoke_age_seconds": (
                    None
                    if self._last_revoke is None
                    else round(now - self._last_revoke, 3)
                ),
            }

    def is_live(self) -> Tuple[bool, str]:
        """Liveness = the consume loop is still polling.

        Always green while starting or draining: a slow schema wait is exactly
        the case this probe must NOT kill, and a pod told to terminate should
        leave on its own rather than be restarted mid-drain.
        """
        with self._lock:
            phase = self._phase
            last_poll = self._last_poll
            now = self._clock()

        if phase != ConsumerPhase.CONSUMING:
            return True, f"phase={phase.value}"

        gap = now - last_poll if last_poll is not None else None
        if gap is not None and gap > self._live_max_poll_gap:
            return False, f"no poll for {gap:.1f}s (limit {self._live_max_poll_gap}s)"
        return True, "polling"

    def is_ready(self) -> Tuple[bool, str]:
        """Readiness = actually consuming: loop running, partitions owned (or
        just revoked, inside the grace window), and a recent poll."""
        with self._lock:
            phase = self._phase
            assignment = self._assignment
            last_poll = self._last_poll
            last_revoke = self._last_revoke
            now = self._clock()

        if phase != ConsumerPhase.CONSUMING:
            return False, f"phase={phase.value}"

        if last_poll is None:
            return False, "no poll yet"
        gap = now - last_poll
        if gap > self._ready_max_poll_gap:
            return False, f"no poll for {gap:.1f}s (limit {self._ready_max_poll_gap}s)"

        if not assignment and self._require_partitions:
            within_grace = (
                last_revoke is not None and (now - last_revoke) <= self._revoke_grace
            )
            if not within_grace:
                return False, "no partitions assigned"
            return True, "rebalancing (revoke grace)"

        return True, f"consuming {len(assignment)} partition(s)"


# The singleton the consumer writes and the probe server reads.
consumer_health = ConsumerHealth()
