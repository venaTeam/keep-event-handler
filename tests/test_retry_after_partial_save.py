"""Kafka mode re-raises a processing failure so the consumer retries it. When
the failure comes after the Alert row was committed, the retry must still
bring LastAlert (the feed) to the new occurrence."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from src.core.db.db import get_last_alert_by_fingerprint
from src.core.dependencies import SINGLE_TENANT_UUID
from src.event_management import process_event_task
from src.event_management.process_event_task import process_event
from src.models.alert import AlertStatus
from src.models.db.alert import Alert
from sqlmodel import select

T_FIRING = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
T_RESOLVED = datetime(2026, 8, 30, 12, 2, tzinfo=timezone.utc)


def _send(fingerprint, status, last_received):
    with patch.object(process_event_task, "_notify_client"):
        process_event(
            ctx={},  # Kafka mode
            trace_id="test",
            tenant_id=SINGLE_TENANT_UUID,
            provider_id="test",
            provider_type=None,
            fingerprint=fingerprint,
            api_key_name="test",
            event={
                "name": f"test-{fingerprint}",
                "fingerprint": fingerprint,
                "status": status,
                "lastReceived": last_received.isoformat(),
            },
        )


def _fail_once(real):
    calls = {"n": 0}

    def wrapper(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("db write failed")
        return real(*args, **kwargs)

    return wrapper


def _shown(db_session, fingerprint):
    last_alert = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, fingerprint)
    alert = db_session.exec(select(Alert).where(Alert.id == last_alert.alert_id)).one()
    return alert.status, last_alert.last_received.replace(tzinfo=timezone.utc)


def _history(db_session, fingerprint):
    return db_session.exec(select(Alert).where(Alert.fingerprint == fingerprint)).all()


def test_retry_updates_feed_after_partial_save(db_session):
    _send("fp-partial", AlertStatus.FIRING.value, T_FIRING)

    real = process_event_task.set_last_alert
    with patch.object(process_event_task, "set_last_alert", _fail_once(real)):
        with pytest.raises(RuntimeError):
            _send("fp-partial", AlertStatus.RESOLVED.value, T_RESOLVED)
        _send("fp-partial", AlertStatus.RESOLVED.value, T_RESOLVED)  # the retry

    assert _shown(db_session, "fp-partial") == (AlertStatus.RESOLVED.value, T_RESOLVED)
    # The failed attempt's row was already committed, so history holds the
    # resolve twice.
    statuses = sorted(a.status for a in _history(db_session, "fp-partial"))
    assert statuses == ["firing", "resolved", "resolved"]


def test_retry_creates_feed_entry_for_first_occurrence(db_session):
    real = process_event_task.set_last_alert
    with patch.object(process_event_task, "set_last_alert", _fail_once(real)):
        with pytest.raises(RuntimeError):
            _send("fp-first", AlertStatus.FIRING.value, T_FIRING)
        _send("fp-first", AlertStatus.FIRING.value, T_FIRING)

    assert _shown(db_session, "fp-first") == (AlertStatus.FIRING.value, T_FIRING)
