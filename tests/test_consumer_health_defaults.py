"""The liveness threshold is derived from max.poll.interval.ms, so a chart
cannot configure liveness into killing pods that are retrying as designed.
"""
import importlib
from unittest.mock import patch

import pytest


def reload_health(env: dict):
    """Module-level constants are resolved at import, so the env has to be in
    place before the reload."""
    with patch.dict("os.environ", env, clear=False):
        import src.core.consumer_health as ch

        return importlib.reload(ch)


@pytest.fixture(autouse=True)
def restore_module():
    yield
    reload_health({})  # leave the singleton back on plain defaults


def test_default_live_gap_covers_the_retry_budget_at_production_settings():
    """6000000ms x 0.8 = 4800s of legitimate non-polling. A fixed 300s
    liveness would kill that pod at ~8 minutes."""
    ch = reload_health({"KAFKA_MAX_POLL_INTERVAL_MS": "6000000"})

    assert ch.RETRY_BUDGET_SECONDS == 4800
    assert ch.LIVE_MAX_POLL_GAP_SECONDS == 4860  # budget + margin


def test_default_live_gap_holds_the_floor_at_small_poll_intervals():
    ch = reload_health({"KAFKA_MAX_POLL_INTERVAL_MS": "60000"})

    assert ch.LIVE_MAX_POLL_GAP_SECONDS == 300  # floor, not 48+60


def test_lowering_the_poll_interval_tightens_liveness_automatically():
    """The correct order of operations: tighten max.poll.interval.ms first,
    and liveness follows on its own."""
    loose = reload_health({"KAFKA_MAX_POLL_INTERVAL_MS": "6000000"})
    loose_gap = loose.LIVE_MAX_POLL_GAP_SECONDS

    tight = reload_health({"KAFKA_MAX_POLL_INTERVAL_MS": "600000"})

    assert tight.LIVE_MAX_POLL_GAP_SECONDS == 540
    assert tight.LIVE_MAX_POLL_GAP_SECONDS < loose_gap


def test_explicit_override_still_wins():
    ch = reload_health(
        {
            "KAFKA_MAX_POLL_INTERVAL_MS": "6000000",
            "KEEP_CONSUMER_LIVE_MAX_POLL_GAP_SECONDS": "900",
        }
    )

    assert ch.LIVE_MAX_POLL_GAP_SECONDS == 900


def test_an_override_below_the_budget_is_warned_about(caplog):
    """Honoured, but never silently: this is exactly the misconfiguration the
    derivation exists to prevent."""
    with caplog.at_level("WARNING"):
        reload_health(
            {
                "KAFKA_MAX_POLL_INTERVAL_MS": "6000000",
                "KEEP_CONSUMER_LIVE_MAX_POLL_GAP_SECONDS": "300",
            }
        )

    assert "below the retry budget" in caplog.text


def test_a_sane_override_is_not_warned_about(caplog):
    with caplog.at_level("WARNING"):
        reload_health(
            {
                "KAFKA_MAX_POLL_INTERVAL_MS": "300000",
                "KEEP_CONSUMER_LIVE_MAX_POLL_GAP_SECONDS": "600",
            }
        )

    assert "below the retry budget" not in caplog.text


def test_env_reaches_the_singleton_not_just_the_constants():
    """The knobs are read at module scope and passed as constructor defaults —
    a swapped default would leave every explicit-kwarg test green."""
    ch = reload_health(
        {
            "KEEP_CONSUMER_READY_MAX_POLL_GAP_SECONDS": "11",
            "KEEP_CONSUMER_REVOKE_GRACE_SECONDS": "22",
        }
    )

    assert ch.consumer_health._ready_max_poll_gap == 11
    assert ch.consumer_health._revoke_grace == 22
    assert ch.consumer_health._live_max_poll_gap == ch.LIVE_MAX_POLL_GAP_SECONDS


def test_require_partitions_lever_reaches_the_singleton():
    """Its failure mode is 'every rolling update hangs forever', so the wiring
    matters as much as the logic."""
    ch = reload_health({"KEEP_CONSUMER_READY_REQUIRE_PARTITIONS": "false"})
    ch.consumer_health.set_phase(ch.ConsumerPhase.CONSUMING)
    ch.consumer_health.mark_poll()

    assert ch.consumer_health._require_partitions is False
    assert ch.consumer_health.is_ready()[0] is True  # zero partitions, still ready


def test_readiness_gap_is_unaffected():
    """Readiness stays tight on purpose -- a pod deep in retries is genuinely
    not consuming, and going NotReady costs nothing but rollout credit."""
    ch = reload_health({"KAFKA_MAX_POLL_INTERVAL_MS": "6000000"})

    assert ch.READY_MAX_POLL_GAP_SECONDS == 90
