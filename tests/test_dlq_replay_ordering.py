"""A late occurrence (e.g. a DLQ replay of a firing that failed while its
resolve went through) is kept in the history at its event time, but the
current state stays with the newest occurrence by event time.
"""

from datetime import datetime, timezone
from unittest.mock import patch

from sqlmodel import select

from src.core.db.db import get_last_alert_by_fingerprint
from src.core.dependencies import SINGLE_TENANT_UUID
from src.event_management import process_event_task
from src.event_management.process_event_task import process_event
from src.models.alert import AlertStatus
from src.models.db.alert import Alert, AlertAudit

FIRING = AlertStatus.FIRING.value
RESOLVED = AlertStatus.RESOLVED.value

T_FIRING = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
T_RESOLVED = datetime(2026, 8, 30, 12, 2, tzinfo=timezone.utc)


def _send(fingerprint: str, status: str, last_received: datetime) -> list[dict]:
    """Process one occurrence; returns the events that went on past the save
    (Elasticsearch, rules engine, UI notification)."""
    with patch.object(process_event_task, "_notify_client") as notify:
        process_event(
            ctx={"job_try": 1},
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
    return notify.call_args.args[2] if notify.called else []


def _history(db_session, fingerprint):
    return db_session.exec(
        select(Alert)
        .where(Alert.fingerprint == fingerprint)
        .order_by(Alert.timestamp.desc())
    ).all()


def _current_status(db_session, fingerprint) -> str:
    """The provider status of the occurrence LastAlert points at."""
    last_alert = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, fingerprint)
    return db_session.exec(select(Alert).where(Alert.id == last_alert.alert_id)).one().status


def _naive(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def test_late_firing_stays_in_history_but_not_current(db_session):
    _send("fp-late", RESOLVED, T_RESOLVED)
    replayed = _send("fp-late", FIRING, T_FIRING)

    assert _current_status(db_session, "fp-late") == RESOLVED
    last_alert = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-late")
    assert _as_utc(last_alert.last_received) == T_RESOLVED

    # Both occurrences in the history, newest event first.
    history = _history(db_session, "fp-late")
    assert [a.status for a in history] == [RESOLVED, FIRING]
    assert history[1].timestamp == _naive(T_FIRING)

    # The late firing doesn't go on to Elasticsearch / rules / notifications.
    assert replayed == []


def test_late_firing_audit_sorted_by_event_time(db_session):
    _send("fp-audit", RESOLVED, T_RESOLVED)
    _send("fp-audit", FIRING, T_FIRING)

    audits = db_session.exec(
        select(AlertAudit)
        .where(AlertAudit.fingerprint == "fp-audit")
        .order_by(AlertAudit.timestamp.desc())
    ).all()
    assert audits[0].description.endswith(RESOLVED)
    assert audits[-1].timestamp == _naive(T_FIRING)


def test_late_resolve_does_not_resolve_a_newer_firing(db_session):
    _send("fp-rev", FIRING, T_RESOLVED)
    _send("fp-rev", RESOLVED, T_FIRING)

    assert _current_status(db_session, "fp-rev") == FIRING
    assert [a.status for a in _history(db_session, "fp-rev")] == [FIRING, RESOLVED]


def test_in_order_occurrences_still_apply(db_session):
    _send("fp-order", FIRING, T_FIRING)
    applied = _send("fp-order", RESOLVED, T_RESOLVED)

    assert _current_status(db_session, "fp-order") == RESOLVED
    assert [a["status"] for a in applied] == [RESOLVED]


def test_resolve_with_same_time_as_firing_still_applies(db_session):
    _send("fp-same", FIRING, T_FIRING)
    _send("fp-same", RESOLVED, T_FIRING)

    assert _current_status(db_session, "fp-same") == RESOLVED
