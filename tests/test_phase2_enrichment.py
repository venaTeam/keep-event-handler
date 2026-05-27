"""Phase 2 (alertenrichment removal) shared-logic tests.

These exercise the typed-column enrichment model on LastAlert directly against
the in-memory sqlite db_session fixture (no elastic / arq / API gateway needed):

- dismissed <-> dismiss_mode translation
- note-guard (empty incoming note never erases an existing note)
- status_disposable clears on non-resolved re-fire (TRUE) / persists (FALSE)
- dismiss survive-resolve (permanent + dismiss_until survive; until_resolved clears)
- D1 enrich-before-first-alert: no column write, AlertAudit still created
- unknown enrichment key rejected (strict) / discarded (non-strict)
"""

import uuid
from datetime import datetime, timezone

import pytest

from core.db.db import (
    enrich_entity,
    get_last_alert_by_fingerprint,
    normalize_enrichments,
    set_last_alert,
)
from core.dependencies import SINGLE_TENANT_UUID
from models.action_type import ActionType
from models.alert import AlertStatus
from models.db.alert import Alert, AlertAudit, LastAlert


def _make_alert(fingerprint, status, ts=None):
    ts = ts or datetime.now(tz=timezone.utc)
    return Alert(
        id=uuid.uuid4(),
        tenant_id=SINGLE_TENANT_UUID,
        timestamp=ts,
        provider_type="test",
        provider_id="test",
        status=status,
        fingerprint=fingerprint,
        alert_hash="hash-" + fingerprint,
    )


def _insert_alert_and_lastalert(db_session, fingerprint, status, ts=None, tracking=None):
    alert = _make_alert(fingerprint, status, ts)
    db_session.add(alert)
    db_session.commit()
    set_last_alert(SINGLE_TENANT_UUID, alert, session=db_session, tracking=tracking)
    return alert


# --------------------------------------------------------------------------- #
# Translation
# --------------------------------------------------------------------------- #
def test_translate_dismissed_true_permanent():
    out = normalize_enrichments({"dismissed": True})
    assert out["status"] == "suppressed"
    assert out["dismiss_mode"] == "permanent"
    assert "dismissed" not in out


def test_translate_dismissed_true_with_timestamp_is_dismiss_until():
    out = normalize_enrichments({"dismissed": True, "dismiss_until": "2026-06-01T00:00:00Z"})
    assert out["status"] == "suppressed"
    assert out["dismiss_mode"] == "dismiss_until"
    assert out["dismissed_until"] == "2026-06-01T00:00:00Z"


def test_translate_dismissed_false_clears():
    out = normalize_enrichments({"dismissed": False})
    assert out["status"] is None
    assert out["dismiss_mode"] is None
    assert out["dismissed_until"] is None


def test_dismiss_mode_forwarded_directly():
    out = normalize_enrichments({"status": "suppressed", "dismiss_mode": "until_resolved"})
    assert out["dismiss_mode"] == "until_resolved"
    assert out["status"] == "suppressed"


def test_unknown_key_rejected_strict():
    with pytest.raises(ValueError):
        normalize_enrichments({"ticket_url": "https://x"})


def test_unknown_key_discarded_non_strict():
    out = normalize_enrichments({"status": "acknowledged", "ticket_url": "x"}, strict=False)
    assert out == {"status": "acknowledged"}


# --------------------------------------------------------------------------- #
# Enrich write -> typed columns
# --------------------------------------------------------------------------- #
def test_enrich_writes_typed_columns(db_session):
    _insert_alert_and_lastalert(db_session, "fp-write", AlertStatus.FIRING.value)
    enrich_entity(
        SINGLE_TENANT_UUID,
        "fp-write",
        {"status": "acknowledged", "assignee": "bob", "note": "hello"},
        action_type=ActionType.GENERIC_ENRICH,
        action_callee="bob",
        action_description="test",
        session=db_session,
    )
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-write", session=db_session)
    assert la.status == "acknowledged"
    assert la.assignee == "bob"
    assert la.note == "hello"


def test_enrich_dismissed_true_sets_suppressed_permanent(db_session):
    _insert_alert_and_lastalert(db_session, "fp-dismiss", AlertStatus.FIRING.value)
    enrich_entity(
        SINGLE_TENANT_UUID,
        "fp-dismiss",
        {"dismissed": True},
        action_type=ActionType.GENERIC_ENRICH,
        action_callee="bob",
        action_description="test",
        session=db_session,
    )
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-dismiss", session=db_session)
    assert la.status == "suppressed"
    assert la.dismiss_mode == "permanent"


def test_note_guard_does_not_erase(db_session):
    _insert_alert_and_lastalert(db_session, "fp-note", AlertStatus.FIRING.value)
    # set a note
    enrich_entity(
        SINGLE_TENANT_UUID, "fp-note", {"note": "keep me"},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session,
    )
    # an automated write with empty note must NOT erase it
    enrich_entity(
        SINGLE_TENANT_UUID, "fp-note", {"note": "", "assignee": "alice"},
        action_type=ActionType.GENERIC_ENRICH, action_callee="system",
        action_description="t", session=db_session,
    )
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-note", session=db_session)
    assert la.note == "keep me"
    assert la.assignee == "alice"


def test_note_force_clear(db_session):
    _insert_alert_and_lastalert(db_session, "fp-note2", AlertStatus.FIRING.value)
    enrich_entity(
        SINGLE_TENANT_UUID, "fp-note2", {"note": "keep me"},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session,
    )
    # explicit clear with force=True
    enrich_entity(
        SINGLE_TENANT_UUID, "fp-note2", {"note": None},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session, force=True,
    )
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-note2", session=db_session)
    assert la.note is None


# --------------------------------------------------------------------------- #
# D1: enrich-before-first-alert
# --------------------------------------------------------------------------- #
def test_d1_enrich_before_first_alert_no_write_but_audit(db_session):
    # no LastAlert row exists for this fingerprint
    enrich_entity(
        SINGLE_TENANT_UUID, "fp-ghost", {"status": "acknowledged"},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session,
    )
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-ghost", session=db_session)
    assert la is None
    audits = (
        db_session.query(AlertAudit)
        .filter(AlertAudit.fingerprint == "fp-ghost")
        .all()
    )
    assert len(audits) == 1


# --------------------------------------------------------------------------- #
# status_disposable clearing on re-fire
# --------------------------------------------------------------------------- #
def test_status_disposable_clears_on_non_resolved_refire(db_session):
    _insert_alert_and_lastalert(db_session, "fp-disp", AlertStatus.FIRING.value)
    enrich_entity(
        SINGLE_TENANT_UUID, "fp-disp",
        {"status": "acknowledged", "status_disposable": True},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session,
    )
    # a new firing occurrence re-fires
    refire = _make_alert("fp-disp", AlertStatus.FIRING.value,
                         ts=datetime.now(tz=timezone.utc))
    db_session.add(refire)
    db_session.commit()
    set_last_alert(SINGLE_TENANT_UUID, refire, session=db_session, tracking={})
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-disp", session=db_session)
    assert la.status is None
    assert la.status_disposable is False


def test_status_persists_when_not_disposable(db_session):
    _insert_alert_and_lastalert(db_session, "fp-keep", AlertStatus.FIRING.value)
    enrich_entity(
        SINGLE_TENANT_UUID, "fp-keep", {"status": "acknowledged"},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session,
    )
    refire = _make_alert("fp-keep", AlertStatus.FIRING.value,
                         ts=datetime.now(tz=timezone.utc))
    db_session.add(refire)
    db_session.commit()
    set_last_alert(SINGLE_TENANT_UUID, refire, session=db_session, tracking={})
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-keep", session=db_session)
    assert la.status == "acknowledged"


# --------------------------------------------------------------------------- #
# dismiss survive-resolve
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "mode,survives",
    [
        ("permanent", True),
        ("dismiss_until", True),
        ("until_resolved", False),
    ],
)
def test_dismiss_survive_resolve(db_session, mode, survives):
    fp = f"fp-resolve-{mode}"
    _insert_alert_and_lastalert(db_session, fp, AlertStatus.FIRING.value)
    enrich_entity(
        SINGLE_TENANT_UUID, fp,
        {"status": "suppressed", "dismiss_mode": mode},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session,
    )
    resolved = _make_alert(fp, AlertStatus.RESOLVED.value,
                           ts=datetime.now(tz=timezone.utc))
    db_session.add(resolved)
    db_session.commit()
    set_last_alert(SINGLE_TENANT_UUID, resolved, session=db_session, tracking={})
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, fp, session=db_session)
    if survives:
        assert la.status == "suppressed"
        assert la.dismiss_mode == mode
    else:
        assert la.status is None
        assert la.dismiss_mode is None
        assert la.dismissed_until is None


# --------------------------------------------------------------------------- #
# tracking columns written by set_last_alert
# --------------------------------------------------------------------------- #
def test_tracking_columns_written(db_session):
    now = datetime.now(tz=timezone.utc)
    _insert_alert_and_lastalert(
        db_session, "fp-track", AlertStatus.FIRING.value,
        tracking={
            "last_received": now,
            "firing_counter": 3,
            "unresolved_counter": 2,
            "started_at": "2026-01-01T00:00:00Z",
            "firing_start_time": "2026-01-01T00:00:00Z",
            "firing_start_time_since_last_resolved": "2026-01-01T00:00:00Z",
        },
    )
    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-track", session=db_session)
    assert la.firing_counter == 3
    assert la.unresolved_counter == 2
    assert la.started_at == "2026-01-01T00:00:00Z"
    assert la.last_received is not None
