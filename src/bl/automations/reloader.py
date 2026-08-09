"""Publishes the trigger index, and keeps it fresh.

Public surface, and the only thing B5/B6 import:

    from src.bl.automations.reloader import match
    match(tenant_id, alert) -> Sequence[AutomationMatch]

**The pre-readiness contract is pinned here, not left to discovery.** The
singleton exists at import holding an empty index; `match()` never raises, never
blocks, and returns an empty sequence when the index is not ready or when the
service was never started (a FastAPI worker, a unit test). A counter separates
"not ready" from "genuinely zero matches" so those are never confused in an
incident.

**Why the swap is safe without a lock on the read path.** One writer -- this
worker thread -- and one hot-path reader, the synchronous Kafka consumer thread.
A `TriggerIndex` is fully built before publication and never mutated after, so
publication is a single `STORE_ATTR` and a read is a single `LOAD_ATTR`. Under
CPython's GIL a bytecode boundary is the interleaving granularity, so the reader
sees either the whole old index or the whole new one. `match()` therefore takes
**exactly one** local reference for the entire probe: re-reading `self._index`
mid-probe could mix two generations and return a result set that never existed.
That is the one way to get this wrong, which is why it has a forced-interleave
test rather than a soak.
"""

import logging
import random
import threading
import time

from src.bl.automations import hydration, settings
from src.bl.automations.index import TriggerIndex
from src.core.metrics import (
    automation_index_enabled,
    automation_index_generation,
    automation_index_hydrate_rate_limited_total,
    automation_index_largest_posting_list,
    automation_index_last_successful_reload_timestamp,
    automation_index_matches_skipped_total,
    automation_index_ready,
    automation_match_duration_seconds,
    automation_index_reload_duration_seconds,
    automation_index_reloads_total,
    automation_index_rows_rejected_total,
    automation_index_size,
    automation_index_tenants,
    automation_index_worker_alive,
)

logger = logging.getLogger(__name__)

# How many consecutive failures are logged at ERROR before dropping to WARN.
# On a database that predates the gateway's migration a developer would
# otherwise get an ERROR every reload interval forever -- and training the one
# error that means "production index is dead" into noise is how a detection
# story dies.
_LOUD_FAILURES = 3


def _failure_kind(error: Exception) -> str:
    """Classify a hydrate failure.

    The spec requires a missing table or column to be distinguishable from a
    connection failure, because for this story they mean opposite things: the
    schema is behind (deploy ordering -- this service is specified to deploy
    BEFORE the gateway migration, so it is EXPECTED for a window), versus the
    database is gone (a real incident). Collapsing them into one counter is how
    an expected transient and an outage end up looking identical on a dashboard.
    """
    name = type(error).__name__
    text_form = f"{name}: {error}".lower()
    if "undefinedtable" in text_form or "undefinedcolumn" in text_form:
        return "schema_behind"
    if "does not exist" in text_form and ("relation" in text_form or "column" in text_form):
        return "schema_behind"
    if "operationalerror" in text_form or "could not connect" in text_form:
        return "unreachable"
    return "error"


def _failure_result(error: Exception) -> str:
    """The `result` label on reloads_total, so the two are separable in a query."""
    kind = _failure_kind(error)
    return "failed" if kind == "error" else f"failed_{kind}"


def next_action(
    now: float,
    last_attempt_at: float,
    signalled: bool,
    consecutive_failures: int,
    reload_seconds: float,
    min_hydrate_interval: float,
    boot_retry_seconds: float,
    jitter: float = 0.0,
) -> tuple[str, float]:
    """Pure scheduling policy: ("reload", 0.0) or ("wait", seconds).

    Extracted as a pure function because freezegun cannot drive
    `threading.Event.wait` -- a 1.5s wait under `freeze_time` burns 1.5s of real
    time while the frozen clock reports zero. So the policy is tested directly
    and the thread only has to honour it.

    **The clock is ATTEMPTS, not successes.** This is load-bearing and was a
    real bug: keying off the last *successful* hydrate means a failing hydrate
    never advances the clock, so `since` stays large, every guard passes, and
    the loop returns ("reload", 0.0) forever -- an unbounded tight loop issuing
    ~6 round trips per iteration against the connection pool alert ingestion is
    drawing from. A database blip would have been amplified into an ingestion
    outage, and it would have fired on the very first deploy, since this service
    is specified to deploy BEFORE the gateway migration that creates the table.

    `jitter` is passed in rather than drawn here so the function stays pure.
    """
    since = now - last_attempt_at

    # The floor applies to signals AND retries, not just the timer. Debounce
    # coalesces a burst; only this bounds a sustained publish rate, and the
    # `reload` channel is unauthenticated.
    if since < min_hydrate_interval:
        return "wait", max(0.0, min_hydrate_interval - since)

    if consecutive_failures:
        # Exponential from the boot-retry base, capped at the normal interval,
        # so a persistent failure settles into the ordinary cadence. Checked
        # BEFORE the signal branch: a publish storm must not be able to bypass
        # the failure backoff and reinstate the hot loop.
        backoff = min(
            reload_seconds, boot_retry_seconds * (2 ** (consecutive_failures - 1))
        )
        if since >= backoff:
            return "reload", 0.0
        return "wait", backoff - since

    if signalled:
        return "reload", 0.0

    due_in = reload_seconds + jitter - since
    if due_in <= 0:
        return "reload", 0.0
    return "wait", due_in


class TriggerIndexService:
    """Holds the published index and owns the only thread that replaces it."""

    def __init__(self, reload_seconds=None, wait_fn=None, hydrate_fn=None):
        # The deployment gate, resolved once. Read here and not per call: match()
        # runs per alert against a 1ms p99 budget, and an os.environ lookup on
        # that path would cost more than the probe it guards. A deploy gate does
        # not need to be flippable without a restart.
        self._enabled = settings.read_index_enabled()
        # Published at construction so match() is legal before start().
        self._index = TriggerIndex.empty()
        self._ready = False
        self._digest = None
        # Two clocks, deliberately. `_last_attempt_at` drives scheduling and is
        # advanced on EVERY attempt including failures -- without that a failing
        # hydrate never moves the clock and the worker spins. `_last_hydrate_at`
        # records the last SUCCESS and is what the staleness alert reads, so a
        # failing service must not be able to refresh it.
        self._last_attempt_at = 0.0
        self._last_hydrate_at = 0.0
        self._consecutive_failures = 0

        self._reload_seconds = (
            reload_seconds
            if reload_seconds is not None
            else settings.read_reload_seconds()
        )
        self._wait_fn = wait_fn
        self._hydrate_fn = hydrate_fn or hydration.fetch_rows

        self._signal = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        # Writer-side only. Never acquired by match(); putting a lock on the
        # read path would couple ingestion to the reload thread.
        self._writer_lock = threading.Lock()

    # -- read path ---------------------------------------------------------

    @property
    def index(self) -> TriggerIndex:
        return self._index

    @property
    def ready(self) -> bool:
        return self._ready

    def match(self, tenant_id: str, alert):
        """Never raises, never blocks. Empty when disabled or not ready."""
        # Checked here, not only at startup: this is the boundary every caller
        # goes through, so a future call site (B5/B6) cannot switch the feature
        # on by forgetting to ask whether it is enabled. With the gate off no
        # index is ever published, so this is belt-and-braces -- which is the
        # point, since the failure it prevents is an automation running in an
        # environment where the feature was declared off.
        if not self._enabled:
            automation_index_matches_skipped_total.labels(reason="disabled").inc()
            return ()
        index = self._index  # exactly one read, for the whole probe
        if not self._ready:
            automation_index_matches_skipped_total.labels(reason="not_ready").inc()
            return ()
        started = time.perf_counter()
        try:
            return index.match(tenant_id, alert)
        finally:
            # Bare observe, not the .time() context manager: that allocates
            # a Timer object per call. Measured, this instrument still costs
            # ~1.5us (MutexValue) to ~2.9us (multiprocess) against a realistic
            # probe of ~0.3-0.7us -- i.e. it costs MORE than what it measures,
            # and the histogram's lowest bucket (50us) means it can only ever
            # distinguish a degenerate posting list from a healthy one. That is
            # the intended resolution; do not read it as a microbenchmark.
            automation_match_duration_seconds.observe(time.perf_counter() - started)

    # -- write path --------------------------------------------------------

    def reload_now(self, trigger: str) -> bool:
        """Hydrate, compile, swap. Total: never raises to the caller."""
        with self._writer_lock:
            started = time.perf_counter()
            # Stamped before anything can fail, so the scheduler's backoff is
            # honoured no matter which branch below is taken.
            self._last_attempt_at = time.time()
            try:
                rows = self._hydrate_fn()
                digest = hydration.rows_digest(rows)
                if self._ready and digest == self._digest:
                    # Nothing changed: skip compile and the swap, but still
                    # refresh the timestamp so the staleness alert stays valid.
                    self._last_hydrate_at = time.time()
                    self._consecutive_failures = 0
                    automation_index_last_successful_reload_timestamp.set(time.time())
                    automation_index_reload_duration_seconds.observe(
                        time.perf_counter() - started
                    )
                    automation_index_reloads_total.labels(
                        trigger=trigger, result="skipped"
                    ).inc()
                    return True
                definitions = hydration.rows_to_definitions(rows)
                new_index = TriggerIndex.compile(definitions)
            except hydration.HydrationRejected as rejected:
                automation_index_rows_rejected_total.labels(
                    reason=rejected.reason
                ).inc()
                self._record_failure(trigger, rejected)
                return False
            except Exception as error:  # noqa: BLE001 - fail-open is the point
                self._record_failure(trigger, error)
                return False

            # The swap. One STORE_ATTR; the object is complete before this line.
            self._index = new_index
            self._digest = digest
            self._ready = True
            self._last_hydrate_at = time.time()
            self._consecutive_failures = 0

            automation_index_size.set(new_index.size)
            automation_index_tenants.set(new_index.tenants)
            automation_index_generation.set(new_index.generation)
            automation_index_largest_posting_list.set(new_index.largest_posting_list)
            automation_index_ready.set(1)
            automation_index_last_successful_reload_timestamp.set(time.time())
            automation_index_reload_duration_seconds.observe(
                time.perf_counter() - started
            )
            automation_index_reloads_total.labels(
                trigger=trigger, result="applied"
            ).inc()
            logger.debug(
                "automations: index applied (trigger=%s, size=%d, tenants=%d)",
                trigger,
                new_index.size,
                new_index.tenants,
            )
            return True

    def _record_failure(self, trigger: str, error: Exception) -> None:
        """A failed hydrate never replaces a good index.

        Note the contrast with tenant_configuration.py's empty-guard: a
        SUCCESSFUL hydrate returning zero rows DOES swap, because disabling the
        last automation has to take effect. Only a failure keeps last-good.
        """
        self._consecutive_failures += 1
        automation_index_reloads_total.labels(
            trigger=trigger, result=_failure_result(error)
        ).inc()
        message = (
            "automations: index reload failed (trigger=%s, consecutive=%d, kind=%s): %s"
        )
        args = (
            trigger,
            self._consecutive_failures,
            _failure_kind(error),
            settings.redact_url(str(error)),
        )
        if self._consecutive_failures <= _LOUD_FAILURES:
            logger.error(message, *args)
        elif self._consecutive_failures % 20 == 0:
            logger.warning(message + " [suppressing; still failing]", *args)
        else:
            logger.debug(message, *args)

    # -- lifecycle ---------------------------------------------------------

    def signal(self) -> None:
        self._signal.set()

    def start(self) -> None:
        if not self._enabled:
            # No worker, so no hydrate query and no connection taken from the
            # pool alert ingestion shares.
            return
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="automation-index-reloader", daemon=True
        )
        self._thread.start()

    def stop(self, deadline: float | None = None) -> None:
        self._stop.set()
        self._signal.set()
        if self._thread is not None:
            self._thread.join(timeout=deadline)
            self._thread = None
        automation_index_worker_alive.set(0)

    def _wait(self, seconds: float) -> bool:
        if self._wait_fn is not None:
            return self._wait_fn(seconds)
        return self._signal.wait(timeout=seconds)

    def _run(self) -> None:
        automation_index_worker_alive.set(1)
        while not self._stop.is_set():
            # The ENTIRE body is guarded, not just the hydrate. Scheduling,
            # metric emission and bookkeeping all sit inside this try for a
            # reason: an exception escaping here unwinds the loop and the daemon
            # thread exits permanently, fleet-wide, while index_ready still
            # reports 1 and pub/sub signals a corpse. Both convergence paths
            # would die from one transient blip and stay dead until deploy.
            try:
                automation_index_worker_alive.set(1)
                signalled = self._signal.is_set()
                self._signal.clear()

                action, seconds = next_action(
                    now=time.time(),
                    last_attempt_at=self._last_attempt_at,
                    signalled=signalled,
                    consecutive_failures=self._consecutive_failures,
                    reload_seconds=self._reload_seconds,
                    min_hydrate_interval=settings.read_min_hydrate_interval_seconds(),
                    boot_retry_seconds=settings.read_boot_retry_seconds(),
                    jitter=self._jitter(),
                )

                if action == "reload":
                    if signalled:
                        # Spread a fleet-wide publish so N replicas do not
                        # hydrate the shared pool in lockstep.
                        debounce = settings.read_debounce_seconds()
                        if debounce:
                            self._stop.wait(random.uniform(0, debounce))
                            self._signal.clear()
                    self.reload_now(trigger="pubsub" if signalled else "periodic")
                    continue

                if signalled:
                    # A signal arrived inside the floor: dropped, and counted --
                    # this is what degrades a publish storm to the periodic
                    # cadence instead of amplifying it onto the shared database.
                    automation_index_hydrate_rate_limited_total.inc()
                    # Wait on the STOP event, not the signal event. Waiting on
                    # the signal would let the next publish wake the loop
                    # immediately, so a flood on the unauthenticated `reload`
                    # channel would spin this thread at the attacker's publish
                    # rate -- no database traffic, but real GIL contention with
                    # the single synchronous consumer thread. Sleeping out the
                    # floor is the point of having one.
                    self._stop.wait(seconds)
                else:
                    self._wait(seconds)
            except Exception as error:  # noqa: BLE001 - the loop must never die
                logger.error(
                    "automations: reload worker iteration failed: %s",
                    settings.redact_url(str(error)),
                    exc_info=False,
                )
                self._stop.wait(settings.read_boot_retry_seconds())

    def _jitter(self) -> float:
        fraction = settings.read_jitter_fraction()
        if not fraction:
            return 0.0
        return random.uniform(-fraction, fraction) * self._reload_seconds


# Module-level singleton, constructed at import. This is what makes match()
# legal in a process that never started the service.
_service = TriggerIndexService()
_subscriber = None


def get_service() -> TriggerIndexService:
    return _service


def match(tenant_id: str, alert):
    """The public entry point B5 and B6 consume."""
    return _service.match(tenant_id, alert)


def start_trigger_index() -> bool:
    """Start the reload worker, and the `reload` subscriber if configured.

    Returns whether anything was started, so the caller can log the truth
    rather than announcing a component that is switched off.

    Non-blocking: it kicks the worker and returns rather than waiting for the
    first hydrate, so a slow database cannot add a second to ingestion startup.
    `index_ready` makes the warm-up window observable instead.
    """
    global _subscriber
    # Always reported, both ways: this gauge is what keeps "off on purpose"
    # separable from "should be running but isn't".
    enabled = settings.read_index_enabled()
    automation_index_enabled.set(1 if enabled else 0)
    if not enabled:
        logger.info(
            "automations: AUTOMATION_INDEX_ENABLED is off -- no trigger index, "
            "no reload subscriber, and match() returns no matches"
        )
        return False
    _service.start()
    # Imported here, not at module scope: this pulls in redis, and an import
    # error must not be able to take down the consumer (see the wrapped import
    # in consumer_main).
    from src.bl.automations.pubsub import ReloadSubscriber

    if _subscriber is None:
        _subscriber = ReloadSubscriber(_service)
    _subscriber.start()
    return True


def stop_trigger_index() -> None:
    """Bounded stop, one shared deadline across both threads.

    Both threads are daemons, so a wedged join can never block process exit --
    but this runs BEFORE the unbounded SSE pool flush in consumer_main, so the
    bounded half completes inside the Kubernetes grace period regardless.
    """
    global _subscriber
    deadline = settings.read_shutdown_timeout_seconds()
    started = time.monotonic()
    if _subscriber is not None:
        _subscriber.stop(deadline=deadline)
        _subscriber = None
    remaining = max(0.5, deadline - (time.monotonic() - started))
    _service.stop(deadline=remaining)
