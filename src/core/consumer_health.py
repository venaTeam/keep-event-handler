"""
Process-wide consumer health state, shared between the Kafka consume loop and
the health-check HTTP server used by the Kubernetes probes.

The health server used to answer 200 on every path, so readiness returned 200
before the consumer had joined the group (with `maxUnavailable: 0` Kubernetes
tore down an old pod before the new one consumed anything), and liveness only
proved the HTTP daemon thread was alive — a wedged consume loop was never
restarted.

This module holds the state both probes need (lifecycle phase, current
partition assignment, timestamp of the last successful poll) behind a lock, as a
module-level singleton so the health server can be started *before* the consumer
object exists.

Timestamps use `time.monotonic()` so clock changes can't make a stalled loop
look healthy; `snapshot()` also exposes wall-clock for humans reading the JSON.
"""

import threading
import time
from typing import Iterable, Optional

from src.config.consts import (
    KEEP_CONSUMER_LIVE_MAX_POLL_GAP_SECONDS,
    KEEP_CONSUMER_READY_MAX_POLL_GAP_SECONDS,
    KEEP_CONSUMER_REVOKE_GRACE_SECONDS,
)

# Lifecycle phases.
PHASE_STARTING = "starting"  # process booted, init_services / consumer not up yet
PHASE_CONSUMING = "consuming"  # consume loop is turning
PHASE_STOPPING = "stopping"  # SIGTERM received, draining
PHASE_STOPPED = "stopped"  # consume loop exited


class ConsumerHealth:
    """Thread-safe health state for a single Kafka consumer process."""

    def __init__(
        self,
        ready_max_poll_gap: int = KEEP_CONSUMER_READY_MAX_POLL_GAP_SECONDS,
        live_max_poll_gap: int = KEEP_CONSUMER_LIVE_MAX_POLL_GAP_SECONDS,
        revoke_grace: int = KEEP_CONSUMER_REVOKE_GRACE_SECONDS,
        clock=time.monotonic,
    ):
        self._lock = threading.Lock()
        self._clock = clock
        self._ready_max_poll_gap = ready_max_poll_gap
        self._live_max_poll_gap = live_max_poll_gap
        self._revoke_grace = revoke_grace

        self._phase = PHASE_STARTING
        self._phase_detail = "process starting"
        self._started_at = clock()
        self._consuming_since: Optional[float] = None
        self._last_poll: Optional[float] = None
        self._assigned: tuple = ()
        self._revoked_at: Optional[float] = None

    # ---------------------------------------------------------------- lifecycle

    def mark_starting(self, detail: str = "process starting"):
        with self._lock:
            self._phase = PHASE_STARTING
            self._phase_detail = detail

    def mark_consuming(self, detail: str = "consume loop running"):
        with self._lock:
            self._phase = PHASE_CONSUMING
            self._phase_detail = detail
            self._consuming_since = self._clock()

    def mark_stopping(self, detail: str = "shutdown signalled"):
        with self._lock:
            self._phase = PHASE_STOPPING
            self._phase_detail = detail

    def mark_stopped(self, detail: str = "consume loop exited"):
        with self._lock:
            self._phase = PHASE_STOPPED
            self._phase_detail = detail
            self._assigned = ()

    # ------------------------------------------------------------------- events

    def record_poll(self):
        """Called after every successful `consume()` return — including an empty
        one, because an empty poll still proves the loop is turning. This is the
        heartbeat both probes are built on."""
        with self._lock:
            self._last_poll = self._clock()

    def set_assignment(self, partitions: Iterable[int]):
        with self._lock:
            self._assigned = tuple(sorted(partitions))
            self._revoked_at = None

    def clear_assignment(self):
        """Partitions revoked (rebalance). Start the revoke grace window so a
        routine rebalance doesn't instantly flip the pod NotReady.

        The grace only applies to a consumer that actually *held* partitions: a
        pod that has never been assigned anything must not be reported ready.
        """
        with self._lock:
            had_assignment = bool(self._assigned)
            self._assigned = ()
            if had_assignment:
                self._revoked_at = self._clock()

    # -------------------------------------------------------------------- views

    def _poll_age(self, now: float) -> Optional[float]:
        if self._last_poll is None:
            return None
        return now - self._last_poll

    def snapshot(self) -> dict:
        with self._lock:
            now = self._clock()
            poll_age = self._poll_age(now)
            return {
                "phase": self._phase,
                "detail": self._phase_detail,
                "assigned_partitions": list(self._assigned),
                "uptime_seconds": round(now - self._started_at, 3),
                "consuming_for_seconds": (
                    None
                    if self._consuming_since is None
                    else round(now - self._consuming_since, 3)
                ),
                "last_poll_age_seconds": (
                    None if poll_age is None else round(poll_age, 3)
                ),
                "timestamp": time.time(),
            }

    def readiness(self) -> tuple:
        """Ready only when the consumer is genuinely consuming: the loop is
        running, partitions are assigned (or were revoked within the grace
        window), and the last poll is recent.

        Returns (ready: bool, payload: dict).
        """
        with self._lock:
            now = self._clock()
            poll_age = self._poll_age(now)
            phase = self._phase
            assigned = self._assigned
            revoked_at = self._revoked_at
            grace = self._revoke_grace
            max_gap = self._ready_max_poll_gap

        payload = self.snapshot()

        if phase != PHASE_CONSUMING:
            payload["reason"] = f"not consuming (phase={phase})"
            return False, payload

        if not assigned:
            if revoked_at is not None and (now - revoked_at) < grace:
                payload["reason"] = (
                    "partitions revoked, within rebalance grace "
                    f"({round(now - revoked_at, 1)}s < {grace}s)"
                )
                return True, payload
            payload["reason"] = "no partitions assigned"
            return False, payload

        if poll_age is None:
            payload["reason"] = "no successful poll yet"
            return False, payload

        if poll_age > max_gap:
            payload["reason"] = (
                f"last poll {round(poll_age, 1)}s ago exceeds {max_gap}s"
            )
            return False, payload

        payload["reason"] = "consuming"
        return True, payload

    def liveness(self) -> tuple:
        """Loop heartbeat: alive unless the consume loop has stopped polling for
        longer than the (deliberately generous) liveness gap.

        Startup and shutdown are always reported alive: killing a booting pod is
        what caused the CrashLoop, and killing a draining one just truncates the
        in-flight batch.

        Returns (alive: bool, payload: dict).
        """
        with self._lock:
            now = self._clock()
            poll_age = self._poll_age(now)
            phase = self._phase
            consuming_since = self._consuming_since
            max_gap = self._live_max_poll_gap

        payload = self.snapshot()

        if phase in (PHASE_STARTING, PHASE_STOPPING, PHASE_STOPPED):
            payload["reason"] = f"phase={phase} (liveness not evaluated)"
            return True, payload

        # Consuming but no poll recorded yet: measure from when the loop started,
        # so a loop that wedges before its first poll is still caught.
        age = poll_age if poll_age is not None else (now - (consuming_since or now))
        if age > max_gap:
            payload["reason"] = (
                f"consume loop stalled: no poll for {round(age, 1)}s "
                f"(threshold {max_gap}s)"
            )
            return False, payload

        payload["reason"] = "consume loop alive"
        return True, payload


# Process-wide singleton. The health server reads it; the consume loop writes it.
consumer_health = ConsumerHealth()
