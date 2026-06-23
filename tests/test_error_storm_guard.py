"""
Unit tests for the error-storm guard that bounds AlertRaw(error=True) writes.

freezegun drives the TTL window. The guard's default clock is time.monotonic,
which freezegun does NOT control, so we inject a wall-clock-based clock so
frozen time advances the window.
"""
import time
from unittest.mock import MagicMock, patch

from freezegun import freeze_time

from src.event_management.error_storm_guard import ErrorStormGuard


def _wallclock():
    return time.time()


def _make_guard(window=60, max_per_key=1, max_entries=10000):
    return ErrorStormGuard(
        window_seconds=window,
        max_per_key=max_per_key,
        max_entries=max_entries,
        clock=_wallclock,
    )


def test_first_write_allowed():
    guard = _make_guard()
    key = guard.build_key("t1", "grafana", "ValueError", "boom 42")
    assert guard.should_record(key) is True


def test_duplicate_within_ttl_suppressed():
    guard = _make_guard(window=60, max_per_key=1)
    with freeze_time("2026-06-21 00:00:00"):
        key = guard.build_key("t1", "grafana", "ValueError", "boom 42")
        assert guard.should_record(key) is True
        # Same key again inside the window -> suppressed.
        assert guard.should_record(key) is False
        assert guard.should_record(key) is False


def test_resumes_after_ttl():
    guard = _make_guard(window=60, max_per_key=1)
    key = None
    with freeze_time("2026-06-21 00:00:00") as frozen:
        key = guard.build_key("t1", "grafana", "ValueError", "boom 42")
        assert guard.should_record(key) is True
        assert guard.should_record(key) is False
        # Advance past the TTL window.
        frozen.tick(delta=61)
        assert guard.should_record(key) is True


def test_max_per_key_greater_than_one():
    guard = _make_guard(window=60, max_per_key=3)
    with freeze_time("2026-06-21 00:00:00"):
        key = guard.build_key("t1", "grafana", "ValueError", "boom")
        assert guard.should_record(key) is True
        assert guard.should_record(key) is True
        assert guard.should_record(key) is True
        # Fourth within window -> suppressed.
        assert guard.should_record(key) is False


def test_lru_eviction_does_not_falsely_suppress_evicted_key():
    # Cap of 2 entries. Seed key A, then push 2 more distinct keys so A is
    # evicted (LRU). A re-seen A must be allowed again (fail-open), not
    # suppressed.
    guard = _make_guard(window=600, max_per_key=1, max_entries=2)
    with freeze_time("2026-06-21 00:00:00"):
        key_a = guard.build_key("t1", "grafana", "ErrA", "a")
        key_b = guard.build_key("t1", "grafana", "ErrB", "b")
        key_c = guard.build_key("t1", "grafana", "ErrC", "c")

        assert guard.should_record(key_a) is True  # A in map
        assert guard.should_record(key_b) is True  # B in map (A,B)
        assert guard.should_record(key_c) is True  # inserts C, evicts A -> (B,C)

        # A was evicted; even though we're still inside its window, the guard
        # has no record of it, so it must be allowed (not falsely suppressed).
        assert guard.should_record(key_a) is True


def test_distinct_keys_independent():
    guard = _make_guard(window=60, max_per_key=1)
    with freeze_time("2026-06-21 00:00:00"):
        k_tenant1 = guard.build_key("t1", "grafana", "ValueError", "boom")
        k_tenant2 = guard.build_key("t2", "grafana", "ValueError", "boom")
        k_provider = guard.build_key("t1", "datadog", "ValueError", "boom")
        assert guard.should_record(k_tenant1) is True
        assert guard.should_record(k_tenant2) is True  # different tenant
        assert guard.should_record(k_provider) is True  # different provider
        # All three now suppressed on repeat.
        assert guard.should_record(k_tenant1) is False
        assert guard.should_record(k_tenant2) is False
        assert guard.should_record(k_provider) is False


def test_digit_normalization_collapses_same_storm():
    guard = _make_guard(window=60, max_per_key=1)
    with freeze_time("2026-06-21 00:00:00"):
        # Same error shape, different ids -> same key -> second suppressed.
        k1 = guard.build_key("t1", "grafana", "KeyError", "missing id=123")
        k2 = guard.build_key("t1", "grafana", "KeyError", "missing id=999")
        assert k1 == k2
        assert guard.should_record(k1) is True
        assert guard.should_record(k2) is False


def test_error_write_suppressed_skips_db_session():
    """When the guard suppresses, __save_error_alerts must not open a DB
    session at all (the write is fully skipped, not just rolled back)."""
    import src.event_management.process_event_task as pet

    save_error = pet.__dict__["__save_error_alerts"]

    with patch(
        "src.event_management.process_event_task.should_record_error",
        return_value=False,
    ) as mock_guard:
        with patch.object(pet, "get_session_sync") as mock_session:
            save_error("t1", "grafana", [{"a": 1}], "boom")
            mock_guard.assert_called_once()
            # Suppressed -> no DB session opened.
            mock_session.assert_not_called()


def test_error_write_allowed_opens_db_session():
    """When the guard allows, __save_error_alerts proceeds to write."""
    import src.event_management.process_event_task as pet

    save_error = pet.__dict__["__save_error_alerts"]

    with patch(
        "src.event_management.process_event_task.should_record_error",
        return_value=True,
    ) as mock_guard:
        fake_session = MagicMock()
        with patch.object(pet, "get_session_sync", return_value=fake_session):
            save_error("t1", "grafana", [{"a": 1}], "boom")
            mock_guard.assert_called_once()
            # Allowed -> session opened and committed.
            fake_session.add.assert_called_once()
            fake_session.commit.assert_called_once()
