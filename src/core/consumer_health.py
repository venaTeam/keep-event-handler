"""
Consumer health state shared between the consume loop (writer) and the probe
HTTP server (reader): lifecycle phase, current partition assignment, and the
time of the last successful poll.

A module-level singleton, so the probe server can start *before* the consumer
object exists — that ordering is what stops a slow boot being killed by the
liveness probe.

Timestamps are `time.monotonic()` so a clock change can't make a stalled loop
look healthy. `snapshot()` also reports wall-clock, for humans reading the JSON.
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

    def _snapshot_locked(self, now: float) -> dict:
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
            "last_poll_age_seconds": None if poll_age is None else round(poll_age, 3),
            "timestamp": time.time(),
        }

    def snapshot(self) -> dict:
        with self._lock:
            return self._snapshot_locked(self._clock())

    def _evaluate(self, check) -> tuple[bool, dict]:
        """Run a probe check and build its payload under one lock, from one
        clock reading — otherwise the reason can contradict the numbers beside
        it (the consume loop updates this state continuously)."""
        with self._lock:
            now = self._clock()
            ok, reason = check(now)
            payload = self._snapshot_locked(now)
        payload["reason"] = reason
        return ok, payload

    def _readiness_locked(self, now: float) -> tuple[bool, str]:
        if self._phase != PHASE_CONSUMING:
            return False, f"not consuming (phase={self._phase})"

        if not self._assigned:
            # A revoke that is still inside the grace window is an ordinary
            # rebalance, not a reason to fail the rollout.
            revoked_ago = (
                None if self._revoked_at is None else now - self._revoked_at
            )
            if revoked_ago is not None and revoked_ago < self._revoke_grace:
                return True, (
                    f"partitions revoked {revoked_ago:.1f}s ago, within "
                    f"{self._revoke_grace}s rebalance grace"
                )
            return False, "no partitions assigned"

        poll_age = self._poll_age(now)
        if poll_age is None:
            return False, "no successful poll yet"
        if poll_age > self._ready_max_poll_gap:
            return False, (
                f"last poll {poll_age:.1f}s ago exceeds "
                f"{self._ready_max_poll_gap}s"
            )
        return True, "consuming"

    def _liveness_locked(self, now: float) -> tuple[bool, str]:
        if self._phase in (PHASE_STARTING, PHASE_STOPPING, PHASE_STOPPED):
            return True, f"phase={self._phase} (liveness not evaluated)"

        # No poll yet? Measure from loop start, so a loop that wedges before its
        # first poll is still caught.
        poll_age = self._poll_age(now)
        age = (
            poll_age
            if poll_age is not None
            else now - (self._consuming_since or now)
        )
        if age > self._live_max_poll_gap:
            return False, (
                f"consume loop stalled: no poll for {age:.1f}s "
                f"(threshold {self._live_max_poll_gap}s)"
            )
        return True, "consume loop alive"

    def readiness(self) -> tuple[bool, dict]:
        """Ready only when genuinely consuming: loop running, partitions assigned
        (or revoked within the grace window), and the last poll recent."""
        return self._evaluate(self._readiness_locked)

    def liveness(self) -> tuple[bool, dict]:
        """Consume-loop heartbeat. Startup and shutdown always report alive:
        killing a booting pod is what caused the CrashLoop, and killing a
        draining one just truncates the in-flight batch."""
        return self._evaluate(self._liveness_locked)


# Process-wide singleton. The health server reads it; the consume loop writes it.
consumer_health = ConsumerHealth()
