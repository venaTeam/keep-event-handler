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

import re
import uuid
from datetime import datetime, timezone

import pytest

from core.db.db import (
    LASTALERT_ENRICHMENT_COLUMNS,
    batch_enrich,
    enrich_entity,
    get_enrichment_with_session,
    get_last_alert_by_fingerprint,
    last_alert_enrichments_dict,
    normalize_enrichments,
    set_last_alert,
)
from core.dependencies import SINGLE_TENANT_UUID
from models.action_type import ActionType
from models.alert import AlertStatus
from models.db.alert import Alert, AlertAudit, AlertEnrichment, LastAlert


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
# Single-source-of-truth contract guard
# --------------------------------------------------------------------------- #
def test_enrichment_columns_match_model():
    assert LASTALERT_ENRICHMENT_COLUMNS == {
        "status", "status_disposable", "dismiss_mode", "dismissed_until", "assignee",
        "note", "deleted", "ticket_type", "ticket_url", "ticket_provider_id",
    }


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
    # `unknown_field` is intentionally NOT in LASTALERT_ENRICHMENT_COLUMNS.
    # (ticket_url is now allow-listed as a typed column; use a still-unknown key.)
    with pytest.raises(ValueError):
        normalize_enrichments({"unknown_field": "x"})


def test_unknown_key_discarded_non_strict():
    out = normalize_enrichments(
        {"status": "acknowledged", "unknown_field": "x"}, strict=False
    )
    assert out == {"status": "acknowledged"}


# --------------------------------------------------------------------------- #
# Read-path coercion: dismissed_until typed DateTime -> canonical wire string
# --------------------------------------------------------------------------- #
def test_last_alert_enrichments_dict_dismissed_until_is_wire_string():
    """`last_alert_enrichments_dict` must coerce the typed DateTime column to the
    legacy ISO "...%f.Z" wire string so JSON consumers (Elastic, SSE notify,
    Kafka, AlertDto.validate_dismissed) all see one canonical, serializable
    format. A raw datetime would break json.dumps and the strptime validator."""
    la = LastAlert()
    la.status = "suppressed"
    la.dismiss_mode = "dismiss_until"
    la.dismissed_until = datetime(2026, 6, 1, 12, 30, 45, 123456, tzinfo=timezone.utc)

    out = last_alert_enrichments_dict(la)
    val = out["dismissed_until"]

    assert isinstance(val, str)
    assert "T" in val
    assert val.endswith("Z")
    assert "+" not in val
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", val)


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


def test_tracking_dict_cannot_clobber_user_enrichment_columns(db_session):
    """`set_last_alert(tracking=...)` must never write user-enrichment columns
    (status/assignee/note/dismiss_*). Those belong to the enrich path."""
    # Seed lastalert + user enrichment
    _insert_alert_and_lastalert(db_session, "fp-guard", AlertStatus.FIRING.value)
    enrich_entity(
        SINGLE_TENANT_UUID, "fp-guard",
        {"status": "acknowledged", "assignee": "alice", "note": "user note"},
        action_type=ActionType.GENERIC_ENRICH, action_callee="alice",
        action_description="t", session=db_session,
    )

    # Re-fire: tracking attempts to clobber user-enrichment columns
    refire = _make_alert("fp-guard", AlertStatus.FIRING.value,
                         ts=datetime.now(tz=timezone.utc))
    db_session.add(refire)
    db_session.commit()
    set_last_alert(
        SINGLE_TENANT_UUID,
        refire,
        session=db_session,
        tracking={
            "last_received": datetime.now(tz=timezone.utc),
            "firing_counter": 7,
            # Hostile keys: must be ignored.
            "status": "resolved",
            "assignee": "evil",
            "note": "wiped",
            "dismiss_mode": "permanent",
        },
    )

    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-guard", session=db_session)
    # user-enrichment columns untouched
    assert la.status == "acknowledged"
    assert la.assignee == "alice"
    assert la.note == "user note"
    assert la.dismiss_mode is None
    # legitimate tracking columns updated
    assert la.firing_counter == 7


# --------------------------------------------------------------------------- #
# Incident enrichment stays on AlertEnrichment (EH-3b) — preserved until Phase 3
# --------------------------------------------------------------------------- #
def test_incident_enrich_writes_alertenrichment_not_lastalert(db_session):
    """Incident enrichment (entity_type='incident') must write the legacy
    AlertEnrichment JSONB row keyed by the incident UUID, and must NOT create a
    LastAlert row (incidents have none)."""
    incident_id = str(uuid.uuid4())
    enrich_entity(
        SINGLE_TENANT_UUID,
        incident_id,
        # arbitrary keys that have NO typed LastAlert column must be allowed
        {"status": "acknowledged", "ticket_url": "https://x/1", "severity": "high"},
        action_type=ActionType.GENERIC_ENRICH,
        action_callee="bob",
        action_description="incident enrich",
        session=db_session,
        entity_type="incident",
    )
    # AlertEnrichment row exists with arbitrary keys preserved (no rejection)
    enr = get_enrichment_with_session(db_session, SINGLE_TENANT_UUID, incident_id)
    assert enr is not None
    assert enr.enrichments["status"] == "acknowledged"
    assert enr.enrichments["ticket_url"] == "https://x/1"
    assert enr.enrichments["severity"] == "high"
    # no LastAlert created for the incident UUID
    assert (
        get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, incident_id, session=db_session)
        is None
    )
    # audit preserved
    audits = (
        db_session.query(AlertAudit)
        .filter(AlertAudit.fingerprint == incident_id)
        .all()
    )
    assert len(audits) == 1


def test_incident_enrich_merges_without_dismissed_translation(db_session):
    """A second incident enrich merges into the existing JSONB and performs NO
    dismissed -> dismiss_mode translation (legacy behavior)."""
    incident_id = str(uuid.uuid4())
    enrich_entity(
        SINGLE_TENANT_UUID, incident_id, {"note": "first"},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session, entity_type="incident",
    )
    enrich_entity(
        SINGLE_TENANT_UUID, incident_id, {"dismissed": True},
        action_type=ActionType.GENERIC_ENRICH, action_callee="bob",
        action_description="t", session=db_session, entity_type="incident",
    )
    enr = get_enrichment_with_session(db_session, SINGLE_TENANT_UUID, incident_id)
    # merge preserved the first key
    assert enr.enrichments["note"] == "first"
    # raw dismissed kept as-is; no translation to status/dismiss_mode
    assert enr.enrichments["dismissed"] is True
    assert "dismiss_mode" not in enr.enrichments


def test_incident_batch_enrich_writes_alertenrichment(db_session):
    incident_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    batch_enrich(
        SINGLE_TENANT_UUID,
        incident_ids,
        {"status": "resolved"},
        action_type=ActionType.GENERIC_ENRICH,
        action_callee="bob",
        action_description="t",
        session=db_session,
        entity_type="incident",
    )
    rows = (
        db_session.query(AlertEnrichment)
        .filter(AlertEnrichment.alert_fingerprint.in_(incident_ids))
        .all()
    )
    assert len(rows) == 2
    assert all(r.enrichments["status"] == "resolved" for r in rows)
    # no LastAlert rows created for incident UUIDs
    for iid in incident_ids:
        assert (
            get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, iid, session=db_session)
            is None
        )
