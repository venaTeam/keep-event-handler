"""AUTOMATION_INDEX_ENABLED — the deployment gate for this whole surface.

The automations feature spans several stories and repos, so the code has to be
mergeable and deployable while the feature is not ready to run. Off must mean
genuinely nothing: no worker thread, no `reload` subscriber, no hydrate query
against the pool alert ingestion shares, and no matches returned to any caller.

The `automations_enabled` autouse fixture in conftest turns the gate ON for
every other test in this package; these tests turn it back off.
"""
import pytest

from src.bl.automations import settings
from src.bl.automations.reloader import TriggerIndexService, start_trigger_index
from tests.automations.conftest import metric_value


@pytest.fixture
def gate_off(monkeypatch):
    monkeypatch.setattr(settings, "AUTOMATION_INDEX_ENABLED", False)


@pytest.fixture
def gate_on(monkeypatch):
    monkeypatch.setattr(settings, "AUTOMATION_INDEX_ENABLED", True)


# -- the setting itself ----------------------------------------------------


def test_default_is_off():
    """Unset must mean off — the safe side of a deployment gate."""
    from src.config import consts

    assert consts.AUTOMATION_INDEX_ENABLED is False


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("true", True),
        ("True", True),
        ("1", True),
        ("yes", True),
        # The trap this pins: a naive `bool("false")` is True, which would turn
        # an explicit opt-OUT into an opt-in.
        ("false", False),
        ("False", False),
        ("0", False),
        ("", False),
        ("no", False),
        ("banana", False),
    ],
)
def test_environment_values_parse_to_the_safe_side(raw, expected, monkeypatch):
    from src.config.config import config

    monkeypatch.setenv("AUTOMATION_INDEX_ENABLED", raw)
    assert config("AUTOMATION_INDEX_ENABLED", default=False, cast=bool) is expected


# -- off means nothing runs -------------------------------------------------


def test_service_start_does_not_spawn_a_worker(gate_off):
    service = TriggerIndexService()
    service.start()
    assert service._thread is None, "a worker thread started while gated off"


def test_no_hydrate_query_is_issued(gate_off):
    """The hydrate borrows a connection from the pool alert ingestion uses."""
    calls = []

    def exploding_hydrate(*args, **kwargs):
        calls.append(args)
        raise AssertionError("hydrated while gated off")

    service = TriggerIndexService(hydrate_fn=exploding_hydrate)
    service.start()
    service.stop(deadline=1)
    assert calls == []


def test_match_returns_no_matches_even_with_an_index_published(gate_off):
    """The gate is checked at the boundary, not merely implied by emptiness.

    A future call site (B5/B6) must not be able to switch the feature on by
    forgetting to ask whether it is enabled, so this forces the service into
    the state it would be in if a hydrate HAD succeeded and still expects
    nothing back.
    """
    service = TriggerIndexService()
    service._ready = True  # pretend a hydrate succeeded

    class AnyAlert:
        pass

    assert service.match("keep", AnyAlert()) == ()


def test_a_disabled_match_is_counted_distinctly(gate_off, metric_delta):
    """Separate reason from "not_ready": one is a choice, the other a problem."""
    service = TriggerIndexService()
    service._ready = True
    counted = metric_delta(
        "keep_automation_index_matches_skipped_total", {"reason": "disabled"}
    )

    class AnyAlert:
        pass

    service.match("keep", AnyAlert())

    assert counted.delta == 1.0


def test_start_trigger_index_reports_that_it_started_nothing(gate_off, caplog):
    with caplog.at_level("INFO", logger="src.bl.automations.reloader"):
        started = start_trigger_index()

    assert started is False
    # consumer_main keys off this return value; announcing a component that is
    # switched off is how an operator concludes it is running.
    assert any("switched off" in r.message or "is off" in r.message for r in caplog.records)


# -- the gauge that keeps "off" separable from "broken" ---------------------


def test_gauge_reports_zero_when_off(gate_off):
    start_trigger_index()
    assert metric_value("keep_automation_index_enabled", {}) == 0.0


def test_gauge_reports_one_when_on(gate_on):
    """Otherwise every automations alert has to be written as `absent(...)`.

    With the gauge, a dead worker is `index_enabled == 1 and
    index_worker_alive == 0`; without it, that alert fires on every correctly
    switched-off pod and gets muted.
    """
    try:
        start_trigger_index()
        assert metric_value("keep_automation_index_enabled", {}) == 1.0
    finally:
        from src.bl.automations.reloader import stop_trigger_index

        stop_trigger_index()


# -- on still behaves exactly as before -------------------------------------


def test_service_starts_a_worker_when_enabled(gate_on):
    service = TriggerIndexService(hydrate_fn=lambda *a, **kw: [])
    try:
        service.start()
        assert service._thread is not None
    finally:
        service.stop(deadline=2)
