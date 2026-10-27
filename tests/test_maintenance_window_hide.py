"""Alerts matched by a "Hide From Feed" maintenance window are stored, not dropped.

The event-handler tags the LastAlert row with the hiding window's id; the
gateway's feed query hides the row while that window is active. An alert
already on screen is frozen instead: the row keeps its pre-window occurrence
and holds the latest one back until the window ends. Hidden and frozen
occurrences stay out of correlation and client notifications.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlmodel import select

from src.bl.maintenance_windows_bl import MaintenanceWindowsBl
from src.core.db.db import get_last_alert_by_fingerprint
from src.core.dependencies import SINGLE_TENANT_UUID
from src.event_management.process_event_task import process_event
from src.models.action_type import ActionType
from src.models.alert import AlertDto, AlertStatus
from src.models.db.alert import Alert, AlertAudit
from src.models.db.maintenance_window import MaintenanceWindowRule

SOURCE = "test-source"


def _window(db_session, suppress=False, ignore_statuses=None, tenant_id=SINGLE_TENANT_UUID):
    window = MaintenanceWindowRule(
        tenant_id=tenant_id,
        name="DB upgrade",
        description="",
        start_time=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1),
        end_time=datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1),
        created_by="test_user",
        cel_query=f'source == "{SOURCE}"',
        enabled=True,
        suppress=suppress,
        ignore_statuses=(
            [AlertStatus.RESOLVED.value, AlertStatus.ACKNOWLEDGED.value]
            if ignore_statuses is None
            else ignore_statuses
        ),
    )
    db_session.add(window)
    db_session.commit()
    db_session.refresh(window)
    return window


def _send(fingerprint, status, minutes, source=SOURCE, notify_client=False, severity="high"):
    ts = datetime.now(UTC) - timedelta(minutes=30) + timedelta(minutes=minutes)
    return process_event(
        ctx={"job_try": 1},
        trace_id="test",
        tenant_id=SINGLE_TENANT_UUID,
        provider_id="test",
        provider_type=source,
        fingerprint=fingerprint,
        api_key_name="test",
        event={
            "name": f"test-{fingerprint}",
            "last_received": ts.isoformat(),
            "status": status.value,
            "severity": severity,
            "source": [source],
            "fingerprint": fingerprint,
        },
        notify_client=notify_client,
        timestamp_forced=ts,
    )


def _last_alert(db_session, fingerprint):
    db_session.expire_all()
    return get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, fingerprint, session=db_session)


def _alerts(db_session, fingerprint):
    return db_session.exec(select(Alert).where(Alert.fingerprint == fingerprint)).all()


def test_hidden_alert_is_stored_and_tagged(db_session):
    window = _window(db_session)

    _send("fp-hidden", AlertStatus.FIRING, 0)

    assert len(_alerts(db_session, "fp-hidden")) == 1
    last_alert = _last_alert(db_session, "fp-hidden")
    assert last_alert.maintenance_window_id == window.id
    audits = db_session.exec(
        select(AlertAudit).where(
            AlertAudit.fingerprint == "fp-hidden",
            AlertAudit.action == ActionType.MAINTENANCE.value,
        )
    ).all()
    assert [a.description for a in audits] == ["Alert in maintenance due to rule `DB upgrade`"]


def test_non_matching_occurrence_clears_the_window(db_session):
    _window(db_session)

    _send("fp-resolve", AlertStatus.FIRING, 0)
    _send("fp-resolve", AlertStatus.RESOLVED, 1)  # resolved is an ignored status

    assert len(_alerts(db_session, "fp-resolve")) == 2
    last_alert = _last_alert(db_session, "fp-resolve")
    assert last_alert.maintenance_window_id is None


def test_alert_outside_the_filter_is_not_tagged(db_session):
    _window(db_session)

    _send("fp-other", AlertStatus.FIRING, 0, source="other-source")

    assert _last_alert(db_session, "fp-other").maintenance_window_id is None


def _alert_by_id(db_session, alert_id):
    return db_session.exec(select(Alert).where(Alert.id == alert_id)).one()


def _latest_alert(db_session, fingerprint):
    return max(_alerts(db_session, fingerprint), key=lambda a: a.timestamp)


def test_alert_already_firing_stays_visible_but_frozen_when_re_sent(db_session):
    _send("fp-firing", AlertStatus.FIRING, 0)
    before = _last_alert(db_session, "fp-firing")
    assert before.maintenance_window_id is None
    shown_alert_id = before.alert_id

    window = _window(db_session)
    with patch(
        "src.event_management.process_event_task.RulesEngine"
    ) as rules_engine, patch(
        "src.event_management.process_event_task._notify_client"
    ) as notify:
        rules_engine.return_value.run_rules.return_value = []
        _send("fp-firing", AlertStatus.FIRING, 1, severity="critical", notify_client=True)
        _send("fp-firing", AlertStatus.FIRING, 2, severity="low", notify_client=True)

    assert len(_alerts(db_session, "fp-firing")) == 3
    last_alert = _last_alert(db_session, "fp-firing")
    # Still visible, still showing the occurrence from before the window.
    assert last_alert.maintenance_window_id is None
    assert last_alert.alert_id == shown_alert_id
    assert _alert_by_id(db_session, last_alert.alert_id).severity == "high"
    assert last_alert.firing_counter == 1
    # The latest occurrence is held back for when the window ends.
    assert last_alert.maintenance_frozen_window_id == window.id
    assert last_alert.maintenance_pending_firing_count == 2
    latest = _latest_alert(db_session, "fp-firing")
    assert latest.severity == "low"
    assert last_alert.maintenance_pending_alert_id == latest.id
    # Frozen occurrences are not correlated or pushed to open feeds.
    for call in rules_engine.return_value.run_rules.call_args_list:
        assert call.args[0] == []
    notify.assert_not_called()


def test_duplicate_of_a_held_back_occurrence_only_moves_last_received(db_session):
    _send("fp-dup", AlertStatus.FIRING, 0)
    _window(db_session)
    _send("fp-dup", AlertStatus.FIRING, 1, severity="critical")
    _send("fp-dup", AlertStatus.FIRING, 2, severity="critical")  # same as the held one

    assert len(_alerts(db_session, "fp-dup")) == 2
    last_alert = _last_alert(db_session, "fp-dup")
    assert last_alert.maintenance_pending_firing_count == 1
    held = last_alert.maintenance_pending_last_received.replace(tzinfo=UTC)
    assert held > _latest_alert(db_session, "fp-dup").timestamp.replace(tzinfo=UTC)


def test_catch_up_applies_every_held_back_occurrence(db_session):
    from src.core.db.db import fold_held_back_occurrence

    _send("fp-fold", AlertStatus.FIRING, 0)
    _window(db_session)
    for minute, severity in [(1, "critical"), (2, "low"), (3, "info")]:
        _send("fp-fold", AlertStatus.FIRING, minute, severity=severity)

    last_alert = get_last_alert_by_fingerprint(
        SINGLE_TENANT_UUID, "fp-fold", session=db_session, for_update=True
    )
    held_received = last_alert.maintenance_pending_last_received
    assert fold_held_back_occurrence(last_alert, db_session) is True
    db_session.commit()

    last_alert = _last_alert(db_session, "fp-fold")
    latest = _latest_alert(db_session, "fp-fold")
    assert last_alert.alert_id == latest.id
    assert latest.severity == "info"
    assert last_alert.firing_counter == 4
    assert last_alert.unresolved_counter == 4
    assert last_alert.last_received == held_received
    assert last_alert.maintenance_frozen_window_id is None
    assert last_alert.maintenance_pending_alert_id is None
    assert last_alert.maintenance_pending_last_received is None
    assert last_alert.maintenance_pending_firing_count is None
    assert fold_held_back_occurrence(last_alert, db_session) is False


def test_occurrence_after_the_window_catches_up_first(db_session):
    _send("fp-after", AlertStatus.FIRING, 0)
    window = _window(db_session)
    _send("fp-after", AlertStatus.FIRING, 1, severity="critical")
    _send("fp-after", AlertStatus.FIRING, 2, severity="low")

    window.enabled = False
    db_session.add(window)
    db_session.commit()
    _send("fp-after", AlertStatus.FIRING, 3, severity="info")

    last_alert = _last_alert(db_session, "fp-after")
    assert last_alert.alert_id == _latest_alert(db_session, "fp-after").id
    assert last_alert.firing_counter == 4
    assert last_alert.maintenance_pending_firing_count is None
    assert last_alert.maintenance_frozen_window_id is None


def test_resolve_during_the_window_is_shown_at_once(db_session):
    _send("fp-res", AlertStatus.FIRING, 0)
    _window(db_session)
    _send("fp-res", AlertStatus.FIRING, 1, severity="critical")
    _send("fp-res", AlertStatus.RESOLVED, 2)  # resolved is an ignored status

    last_alert = _last_alert(db_session, "fp-res")
    shown = _alert_by_id(db_session, last_alert.alert_id)
    assert shown.status == AlertStatus.RESOLVED.value
    assert last_alert.firing_counter == 3
    assert last_alert.unresolved_counter == 0
    assert last_alert.maintenance_pending_firing_count is None
    assert last_alert.maintenance_window_id is None


def test_resolved_alert_firing_again_is_hidden_and_feeds_refetch(db_session):
    _send("fp-refire", AlertStatus.FIRING, 0)
    _send("fp-refire", AlertStatus.RESOLVED, 1)
    window = _window(db_session)

    with patch("src.event_management.process_event_task._notify_client") as notify:
        _send("fp-refire", AlertStatus.FIRING, 2, notify_client=True)

    assert _last_alert(db_session, "fp-refire").maintenance_window_id == window.id
    notify.assert_called_once()
    assert notify.call_args.kwargs["refetch"] is True


def test_hidden_alert_re_sent_stays_hidden(db_session):
    window = _window(db_session)
    _send("fp-repeat", AlertStatus.FIRING, 0)

    with patch("src.event_management.process_event_task._notify_client") as notify:
        _send("fp-repeat", AlertStatus.FIRING, 1, notify_client=True, severity="critical")

    assert len(_alerts(db_session, "fp-repeat")) == 2
    assert _last_alert(db_session, "fp-repeat").maintenance_window_id == window.id
    notify.assert_not_called()


def test_suppress_window_is_unchanged(db_session):
    _window(db_session, suppress=True)

    _send("fp-suppressed", AlertStatus.FIRING, 0)

    alerts = _alerts(db_session, "fp-suppressed")
    assert [a.status for a in alerts] == [AlertStatus.SUPPRESSED.value]
    assert _last_alert(db_session, "fp-suppressed").maintenance_window_id is None


def test_window_of_another_tenant_does_not_hide(db_session):
    from src.models.db.tenant import Tenant

    db_session.add(Tenant(id="other-tenant", name="other-tenant"))
    db_session.commit()
    _window(db_session, tenant_id="other-tenant")

    _send("fp-tenant", AlertStatus.FIRING, 0)

    assert _last_alert(db_session, "fp-tenant").maintenance_window_id is None


def test_hidden_alerts_are_not_correlated_or_notified(db_session):
    _window(db_session)

    with patch(
        "src.event_management.process_event_task.RulesEngine"
    ) as rules_engine, patch(
        "src.event_management.process_event_task._notify_client"
    ) as notify:
        rules_engine.return_value.run_rules.return_value = []
        _send("fp-silent", AlertStatus.FIRING, 0, notify_client=True)

    rules_engine.return_value.run_rules.assert_called_once()
    assert rules_engine.return_value.run_rules.call_args.args[0] == []
    notify.assert_not_called()


def test_mixed_batch_of_one_fingerprint(db_session):
    """One batch holding a hidden and a visible occurrence of the same
    fingerprint: the reason the hidden set is keyed by id(event)."""
    _window(db_session)
    now = datetime.now(UTC)
    batch = [
        AlertDto(
            id=f"mixed-{status}",
            name="mixed",
            status=status,
            severity="high",
            lastReceived=(now + timedelta(seconds=offset)).isoformat(),
            source=[SOURCE],
            fingerprint="fp-mixed",
            labels={},
        )
        for offset, status in [(0, AlertStatus.FIRING), (1, AlertStatus.RESOLVED)]
    ]

    with patch("src.event_management.process_event_task._notify_client") as notify:
        process_event(
            ctx={"job_try": 1},
            trace_id="test",
            tenant_id=SINGLE_TENANT_UUID,
            provider_id="test",
            provider_type=SOURCE,
            fingerprint=None,
            api_key_name="test",
            event=batch,
            notify_client=True,
        )

    alerts = _alerts(db_session, "fp-mixed")
    assert sorted(a.status for a in alerts) == ["firing", "resolved"]
    # The resolved occurrence is the latest and no window matches it.
    assert _last_alert(db_session, "fp-mixed").maintenance_window_id is None
    pushed = notify.call_args.args[2]
    assert [(a["fingerprint"], a["status"]) for a in pushed] == [("fp-mixed", "resolved")]


def test_refetch_signal_survives_coalescing():
    import src.event_management.process_event_task as pet

    merged = pet._merge_coalesced_data({"alerts": [{"fingerprint": "a"}]}, {})
    assert merged == {}
    merged = pet._merge_coalesced_data({}, {"alerts": [{"fingerprint": "b"}]})
    assert merged == {}


@pytest.fixture
def mock_session():
    return MagicMock()


def _bl_with(mock_session, window):
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        window
    ]
    return MaintenanceWindowsBl(tenant_id="test-tenant", session=mock_session)


def _dto(status=AlertStatus.FIRING):
    return AlertDto(
        id="1",
        name="n",
        status=status,
        severity="high",
        last_received=datetime.now(UTC).isoformat(),
        source=[SOURCE],
        fingerprint="fp",
        labels={},
    )


def _rule(suppress):
    return MaintenanceWindowRule(
        id=7,
        name="w",
        tenant_id="test-tenant",
        cel_query=f'source == "{SOURCE}"',
        start_time=datetime.utcnow() - timedelta(hours=1),
        end_time=datetime.utcnow() + timedelta(hours=1),
        enabled=True,
        suppress=suppress,
        ignore_statuses=[AlertStatus.RESOLVED.value],
    )


def test_bl_returns_the_hiding_window_id(mock_session):
    bl = _bl_with(mock_session, _rule(suppress=False))
    assert bl.get_hiding_window_id(_dto()) == 7
    assert bl.check_if_alert_in_maintenance_windows(_dto()) is True


def test_bl_returns_none_for_a_suppress_window(mock_session):
    bl = _bl_with(mock_session, _rule(suppress=True))
    alert = _dto()
    assert bl.get_hiding_window_id(alert) is None
    assert alert.status == AlertStatus.SUPPRESSED.value


def test_bl_returns_none_for_an_ignored_status(mock_session):
    bl = _bl_with(mock_session, _rule(suppress=False))
    assert bl.get_hiding_window_id(_dto(AlertStatus.RESOLVED)) is None
