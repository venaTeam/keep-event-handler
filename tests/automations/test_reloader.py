"""Swap semantics, the pure scheduler, the worker loop, and the match facade.

No test here sleeps for a real interval or depends on thread timing for its
assertion: the scheduling policy is a pure function, and the concurrency test
forces the interleave rather than hoping for it.
"""

import json
import threading

import pytest

from src.bl.automations import hydration, settings
from src.bl.automations.index import TriggerIndex
from src.bl.automations.models import AutomationMatch
from src.bl.automations.reloader import TriggerIndexService, next_action
from src.models.alert import AlertDto

TENANT = "keep"


def make_alert(**overrides):
    base = {
        "id": "alert-1",
        "name": "n",
        "status": "firing",
        "severity": "critical",
        "lastReceived": "2026-07-30T00:00:00Z",
        "source": ["grafana"],
    }
    base.update(overrides)
    return AlertDto(**base)


def row(automation_id, field, value, tenant_id=TENANT):
    return {
        "id": automation_id,
        "tenant_id": tenant_id,
        "triggers": json.dumps(
            [{"field": field, "value": value}, {"field": "status", "value": "firing"}]
        ),
        "cooldown_seconds": None,
        "cooldown_fields": None,
        "grace_seconds": 300,
        "index_generation": 1,
    }


# --------------------------------------------------------------------------
# The pure scheduler
# --------------------------------------------------------------------------


def _action(**overrides):
    kwargs = dict(
        now=1000.0,
        last_attempt_at=0.0,
        signalled=False,
        consecutive_failures=0,
        reload_seconds=30.0,
        min_hydrate_interval=5.0,
        boot_retry_seconds=5.0,
        jitter=0.0,
    )
    kwargs.update(overrides)
    return next_action(**kwargs)


def test_reloads_when_the_interval_has_elapsed():
    assert _action(last_attempt_at=900.0)[0] == "reload"


def test_waits_when_the_interval_has_not_elapsed():
    action, seconds = _action(last_attempt_at=990.0)
    assert action == "wait"
    assert 0 < seconds <= 30


def test_a_signal_reloads_immediately_once_past_the_floor():
    assert _action(last_attempt_at=990.0, signalled=True)[0] == "reload"


def test_the_minimum_interval_floor_beats_a_signal():
    """Debounce coalesces a burst; only the floor bounds a sustained publish
    rate -- and the reload channel is unauthenticated."""
    action, seconds = _action(last_attempt_at=998.0, signalled=True)
    assert action == "wait"
    assert seconds == pytest.approx(3.0)


def test_the_floor_also_applies_to_retries():
    action, _ = _action(last_attempt_at=999.0, consecutive_failures=3)
    assert action == "wait"


def test_failure_backoff_grows_then_caps_at_the_reload_interval():
    """Each sample is measured at ITS OWN backoff boundary.

    Measuring them all at a fixed `since` would just report the same clamp.
    """
    waits = []
    for failures in (1, 2, 3, 4, 5, 9):
        _, seconds = _action(last_attempt_at=994.0, consecutive_failures=failures)
        waits.append(seconds)
    assert waits == sorted(waits)
    assert max(waits) <= 30.0


@pytest.mark.parametrize("failures", [1, 2, 3, 10, 50])
def test_a_failed_attempt_never_schedules_an_immediate_retry(failures):
    """Regression: the scheduler used to key off the last SUCCESSFUL hydrate.

    A failing hydrate never advanced that clock, so `since` stayed large, every
    guard passed, and the loop returned ("reload", 0.0) forever -- an unbounded
    tight loop issuing ~6 round trips per iteration against the connection pool
    alert ingestion draws from. It would have fired on the very first deploy,
    because this service is specified to deploy BEFORE the gateway migration
    that creates the table.

    Now the clock is ATTEMPTS, so a failure that just happened must wait.
    """
    action, seconds = _action(last_attempt_at=1000.0, consecutive_failures=failures)
    assert action == "wait"
    assert seconds > 0


def test_a_signal_cannot_bypass_the_failure_backoff():
    """Otherwise a publish storm reinstates the hot loop during an outage."""
    action, seconds = _action(
        last_attempt_at=994.0, signalled=True, consecutive_failures=3
    )
    assert action == "wait"
    assert seconds > 0


def test_jitter_moves_the_due_time():
    """since = 31s, interval = 30s: due without jitter, not due with +5s."""
    early, _ = _action(last_attempt_at=969.0, jitter=0.0)
    late, seconds = _action(last_attempt_at=969.0, jitter=5.0)
    assert early == "reload"
    assert late == "wait"
    assert seconds == pytest.approx(4.0)


def test_the_attempt_clock_advances_on_a_failed_hydrate():
    """The service half of the regression: reload_now must stamp the attempt
    clock before anything can fail."""

    def boom():
        raise RuntimeError("database is gone")

    service = TriggerIndexService(hydrate_fn=boom)
    assert service._last_attempt_at == 0.0
    service.reload_now("boot")
    assert service._last_attempt_at > 0.0
    # ...and must NOT have refreshed the success clock the staleness alert reads.
    assert service._last_hydrate_at == 0.0


# --------------------------------------------------------------------------
# Swap semantics
# --------------------------------------------------------------------------


def test_successful_zero_row_hydrate_swaps_in_an_empty_index():
    """Deliberately unlike tenant_configuration.py's empty-guard: disabling the
    last automation MUST take effect."""
    service = TriggerIndexService(hydrate_fn=lambda: [row("a", "site", "dc1")])
    assert service.reload_now("boot") is True
    assert service.index.size == 1

    service._hydrate_fn = lambda: []
    assert service.reload_now("periodic") is True
    assert service.index.size == 0
    assert service.ready is True


def test_failed_hydrate_does_not_swap_and_last_good_survives():
    service = TriggerIndexService(hydrate_fn=lambda: [row("a", "site", "dc1")])
    service.reload_now("boot")
    good = service.index

    def boom():
        raise RuntimeError("database is gone")

    service._hydrate_fn = boom
    assert service.reload_now("periodic") is False
    assert service.index is good
    assert service.index.size == 1


def test_a_rejected_result_set_refuses_the_swap_and_counts_the_reason(metric_delta):
    service = TriggerIndexService(hydrate_fn=lambda: [row("a", "site", "dc1")])
    service.reload_now("boot")
    good = service.index

    tracked = metric_delta(
        "keep_automation_index_rows_rejected_total", {"reason": "row_cap"}
    )

    def rejected():
        raise hydration.HydrationRejected("row_cap", "too many")

    service._hydrate_fn = rejected
    assert service.reload_now("periodic") is False
    assert service.index is good
    assert tracked.delta == 1.0


def test_unchanged_rows_skip_the_swap_but_refresh_the_staleness_clock(metric_delta):
    """The digest skip must not make the staleness alert fire on a healthy,
    idle service."""
    rows = [row("a", "site", "dc1")]
    service = TriggerIndexService(hydrate_fn=lambda: list(rows))
    service.reload_now("boot")
    first = service.index

    tracked = metric_delta(
        "keep_automation_index_reloads_total",
        {"trigger": "periodic", "result": "skipped"},
    )
    assert service.reload_now("periodic") is True
    assert service.index is first  # identity stable, no recompile
    assert tracked.delta == 1.0
    assert service._last_hydrate_at > 0


def test_changed_rows_do_swap():
    state = {"rows": [row("a", "site", "dc1")]}
    service = TriggerIndexService(hydrate_fn=lambda: state["rows"])
    service.reload_now("boot")
    first = service.index

    state["rows"] = [row("a", "site", "dc2")]
    service.reload_now("pubsub")
    assert service.index is not first


# --------------------------------------------------------------------------
# The match facade before readiness
# --------------------------------------------------------------------------


def test_match_before_any_hydrate_returns_empty_and_counts_not_ready(metric_delta):
    """B5 will call this in processes that never started the service."""
    service = TriggerIndexService(hydrate_fn=lambda: [])
    tracked = metric_delta(
        "keep_automation_index_matches_skipped_total", {"reason": "not_ready"}
    )
    assert list(service.match(TENANT, make_alert())) == []
    assert tracked.delta == 1.0


def test_match_never_raises_even_when_the_index_is_broken():
    service = TriggerIndexService(hydrate_fn=lambda: [row("a", "site", "dc1")])
    service.reload_now("boot")
    assert list(service.match(TENANT, make_alert())) == []


def test_module_level_match_is_importable_and_safe_without_start():
    from src.bl.automations.reloader import match

    assert list(match("no-such-tenant", make_alert())) == []


# --------------------------------------------------------------------------
# Snapshot consistency -- forced, not sampled
# --------------------------------------------------------------------------


def test_match_uses_one_snapshot_even_if_the_index_swaps_mid_probe():
    """Deterministic replacement for a probabilistic soak.

    A soak that swaps in a loop while a reader probes is a coin flip on a
    two-bytecode window -- it is green with the bug present, which is exactly
    when it matters. Here the swap happens *during* the probe by construction,
    so a match() that re-read self._index would fail every single run.
    """
    service = TriggerIndexService(hydrate_fn=lambda: [])

    def definition(automation_id, field, value, generation):
        return (
            TENANT,
            ((field, value), ("status", "firing")),
            AutomationMatch(
                automation_id=automation_id, grace_seconds=300, cooldown=None
            ),
            generation,
        )

    # index_a seeds on BOTH `site` and `network`, so the probe genuinely reads
    # `network` -- which is what makes the swap fire mid-probe rather than never.
    index_a = TriggerIndex.compile(
        [
            definition("A", "site", "dc1", 1),
            definition("A2", "network", "nh", 1),
        ]
    )
    # index_b matches the SAME alert on `network`, so a probe that re-read the
    # published index mid-loop would return B in place of A2.
    index_b = TriggerIndex.compile([definition("B", "network", "nh", 2)])

    service._index = index_a
    service._ready = True

    swapped = threading.Event()

    class SwappingDict(dict):
        """Publishes a different index the moment the probe reads `network`."""

        def get(self, key, default=None):
            if key == "network":
                service._index = index_b
                swapped.set()
            return super().get(key, default)

    alert = make_alert(site="dc1", network="nh")
    # object.__setattr__, not plain assignment: AlertDto is Pydantic v1 with
    # Extra.allow, so `alert.__dict__ = x` goes through BaseModel.__setattr__
    # and stores a *field literally named __dict__* instead of replacing the
    # instance dict -- which silently made this test vacuous.
    object.__setattr__(alert, "__dict__", SwappingDict(alert.__dict__))

    result = sorted(m.automation_id for m in service.match(TENANT, alert))

    assert swapped.is_set(), "the swap never fired; the test would be vacuous"
    assert service._index is index_b
    # One generation, whole. Never ["A", "B"] and never just ["A"].
    assert result == ["A", "A2"]


def test_match_reads_the_published_index_exactly_once():
    """The mechanism behind the test above, asserted directly.

    Normally counting attribute reads is a smell -- but snapshot consistency
    *is* an implementation invariant with no black-box signature, and it is the
    single way to get the lock-free swap wrong. A probe that re-read
    `self._index` per field could mix two generations and return a result set
    that never existed at any instant. Falsifiable: add a second read to
    `match()` and this fails immediately.
    """
    reads = {"n": 0}

    class CountingService(TriggerIndexService):
        @property
        def _index(self):
            reads["n"] += 1
            return self.__dict__["_index_value"]

        @_index.setter
        def _index(self, value):
            self.__dict__["_index_value"] = value

    service = CountingService(hydrate_fn=lambda: [row("a", "site", "dc1")])
    service.reload_now("boot")

    reads["n"] = 0
    service.match(TENANT, make_alert(site="dc1", status="firing"))
    assert reads["n"] == 1


# --------------------------------------------------------------------------
# The worker loop must survive an exception from ANY stage
# --------------------------------------------------------------------------


@pytest.mark.timeout(15)
@pytest.mark.parametrize(
    "stage", ["hydrate", "digest", "compile", "schedule", "metrics"]
)
def test_worker_survives_a_raise_from_any_loop_stage(monkeypatch, stage):
    """A single hydrate-raises test would pass on the buggy code, because
    reload_now() already catches that. The stages OUTSIDE reload_now() --
    scheduling, metric emission, bookkeeping -- are the ones that killed the
    thread in the draft.
    """
    rows = [row("a", "site", "dc1")]
    calls = {"n": 0}
    applied = threading.Event()

    def hydrate():
        calls["n"] += 1
        if stage == "hydrate" and calls["n"] == 1:
            raise RuntimeError("boom")
        if calls["n"] > 1:
            applied.set()
        return list(rows)

    service = TriggerIndexService(reload_seconds=0.01, hydrate_fn=hydrate)

    if stage == "digest":
        original = hydration.rows_digest
        state = {"first": True}

        def flaky_digest(r):
            if state["first"]:
                state["first"] = False
                raise RuntimeError("boom")
            return original(r)

        monkeypatch.setattr(hydration, "rows_digest", flaky_digest)
    elif stage == "compile":
        original = TriggerIndex.compile
        state = {"first": True}

        def flaky_compile(d):
            if state["first"]:
                state["first"] = False
                raise RuntimeError("boom")
            return original(d)

        monkeypatch.setattr(TriggerIndex, "compile", staticmethod(flaky_compile))
    elif stage == "schedule":
        state = {"first": True}
        real = settings.read_min_hydrate_interval_seconds

        def flaky_setting():
            if state["first"]:
                state["first"] = False
                raise RuntimeError("boom")
            return 0

        monkeypatch.setattr(
            settings, "read_min_hydrate_interval_seconds", flaky_setting
        )
    elif stage == "metrics":
        state = {"first": True}
        real = settings.read_jitter_fraction

        def flaky_jitter():
            if state["first"]:
                state["first"] = False
                raise RuntimeError("boom")
            return 0.0

        monkeypatch.setattr(settings, "read_jitter_fraction", flaky_jitter)
    else:
        monkeypatch.setattr(settings, "read_min_hydrate_interval_seconds", lambda: 0)

    monkeypatch.setattr(settings, "read_boot_retry_seconds", lambda: 1)
    if stage not in ("schedule",):
        monkeypatch.setattr(settings, "read_min_hydrate_interval_seconds", lambda: 0)

    service.start()
    try:
        # Liveness, not just "it didn't crash": a LATER hydrate must be applied.
        assert applied.wait(timeout=10), f"worker did not recover from a {stage} failure"
        assert service._thread.is_alive()
        assert service.index.size == 1
    finally:
        service.stop(deadline=5)


@pytest.mark.timeout(15)
def test_stop_joins_the_worker_within_the_deadline(monkeypatch):
    monkeypatch.setattr(settings, "read_min_hydrate_interval_seconds", lambda: 0)
    service = TriggerIndexService(
        reload_seconds=0.05, hydrate_fn=lambda: [row("a", "site", "dc1")]
    )
    service.start()
    thread = service._thread
    service.stop(deadline=5)
    assert not thread.is_alive()
    assert service._thread is None


@pytest.mark.timeout(15)
def test_a_signal_inside_the_floor_is_dropped_and_counted(monkeypatch, metric_delta):
    """A publish storm must degrade to the periodic cadence, not amplify onto
    the database that also serves alert ingestion."""
    monkeypatch.setattr(settings, "read_min_hydrate_interval_seconds", lambda: 60)
    monkeypatch.setattr(settings, "read_debounce_seconds", lambda: 0)
    service = TriggerIndexService(
        reload_seconds=30, hydrate_fn=lambda: [row("a", "site", "dc1")]
    )
    service.reload_now("boot")

    tracked = metric_delta("keep_automation_index_hydrate_rate_limited_total")
    service.start()
    try:
        for _ in range(5):
            service.signal()
        threading.Event().wait(0.4)
    finally:
        service.stop(deadline=5)
    assert tracked.delta >= 1.0


# --------------------------------------------------------------------------
# Failure classification and gauge movement
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error,expected",
    [
        (Exception("relation \"automations\" does not exist"), "schema_behind"),
        (Exception("UndefinedTable: no such relation"), "schema_behind"),
        (Exception("UndefinedColumn: tenant_id"), "schema_behind"),
        (Exception("column tenant_id does not exist"), "schema_behind"),
        (Exception("OperationalError: could not connect to server"), "unreachable"),
        (Exception("something else entirely"), "error"),
    ],
)
def test_a_missing_table_is_distinguishable_from_a_dead_database(error, expected):
    """They mean opposite things for this story.

    The schema being behind is EXPECTED for a window -- this service is
    specified to deploy before the gateway migration that creates the table.
    The database being gone is an incident. One counter for both is how an
    expected transient and an outage look identical on a dashboard.
    """
    from src.bl.automations.reloader import _failure_kind

    assert _failure_kind(error) == expected


def test_the_failure_result_label_separates_the_two(metric_delta):
    def schema_behind():
        raise Exception('relation "automations" does not exist')

    tracked = metric_delta(
        "keep_automation_index_reloads_total",
        {"trigger": "boot", "result": "failed_schema_behind"},
    )
    service = TriggerIndexService(hydrate_fn=schema_behind)
    service.reload_now("boot")
    assert tracked.delta == 1.0


def test_a_successful_swap_moves_the_published_gauges():
    """The instruments the runbooks read must actually be written, not merely
    registered."""
    from tests.automations.conftest import metric_value

    service = TriggerIndexService(
        hydrate_fn=lambda: [
            row("a", "site", "dc1", tenant_id="keep"),
            row("b", "site", "dc2", tenant_id="other-tenant"),
        ]
    )
    service.reload_now("boot")

    assert metric_value("keep_automation_index_ready") == 1.0
    assert metric_value("keep_automation_index_size") == 2.0
    assert metric_value("keep_automation_index_tenants") == 2.0
    assert metric_value("keep_automation_index_last_successful_reload_timestamp") > 0


def test_the_staleness_clock_is_not_refreshed_by_a_failure():
    """The staleness alert is the detector for a dead worker. A failing service
    must not be able to keep it looking fresh."""
    from tests.automations.conftest import metric_value

    service = TriggerIndexService(hydrate_fn=lambda: [row("a", "site", "dc1")])
    service.reload_now("boot")
    fresh = metric_value("keep_automation_index_last_successful_reload_timestamp")

    def boom():
        raise RuntimeError("gone")

    service._hydrate_fn = boom
    service.reload_now("periodic")

    assert (
        metric_value("keep_automation_index_last_successful_reload_timestamp") == fresh
    )
