"""Incident enrichment lives on the dedicated ``incidentenrichment`` table.

The incident path writes/updates an ``IncidentEnrichment`` JSONB row keyed on
``incident_id`` (a real UUID FK to ``incident.id``) — no ``LastAlert``
involvement, no dismissed<->dismiss_mode translation, no D1 no-op and no strict
unknown-key rejection. Arbitrary keys are preserved verbatim. ``AlertAudit`` is
still written for every incident enrichment.

The alert enrichment path (``entity_type="alert"``) is unchanged: it writes typed
``LastAlert`` columns and never touches ``incidentenrichment``.
"""

import uuid
from uuid import UUID

from src.core.db.db import (
    enrich_entity,
    get_last_alert_by_fingerprint,
    set_last_alert,
)
from src.core.dependencies import SINGLE_TENANT_UUID
from src.models.action_type import ActionType
from src.models.db.alert import Alert, AlertAudit, IncidentEnrichment, LastAlert
from src.models.db.incident import Incident


def _make_incident(db_session) -> Incident:
    incident = Incident(
        tenant_id=SINGLE_TENANT_UUID,
        user_summary="s",
        generated_summary="s",
    )
    db_session.add(incident)
    db_session.commit()
    return incident


def _get_incident_enrichment(db_session, incident_id) -> IncidentEnrichment:
    return (
        db_session.query(IncidentEnrichment)
        .filter(
            IncidentEnrichment.tenant_id == SINGLE_TENANT_UUID,
            IncidentEnrichment.incident_id == UUID(str(incident_id)),
        )
        .first()
    )


def _audit_count(db_session, fingerprint) -> int:
    return (
        db_session.query(AlertAudit)
        .filter(
            AlertAudit.tenant_id == SINGLE_TENANT_UUID,
            AlertAudit.fingerprint == fingerprint,
        )
        .count()
    )


def test_incident_enrich_creates_incidentenrichment_row(db_session):
    incident = _make_incident(db_session)
    # incident ids arrive as strings from the route/event layer
    incident_id = str(incident.id)

    enrich_entity(
        SINGLE_TENANT_UUID,
        incident_id,
        {"ticket_url": "https://x", "severity": "high"},
        action_type=ActionType.INCIDENT_ENRICH,
        action_callee="bob@x",
        action_description="t",
        session=db_session,
        entity_type="incident",
    )

    enr = _get_incident_enrichment(db_session, incident_id)
    assert enr is not None  # row written (no D1 no-op for incidents)
    # arbitrary keys preserved verbatim (no strict rejection, no translation)
    assert enr.enrichments["ticket_url"] == "https://x"
    assert enr.enrichments["severity"] == "high"
    # no LastAlert created for an incident id
    assert (
        get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, incident_id, session=db_session)
        is None
    )
    assert _audit_count(db_session, incident_id) == 1


def test_incident_re_enrich_merges(db_session):
    incident = _make_incident(db_session)
    incident_id = str(incident.id)

    enrich_entity(
        SINGLE_TENANT_UUID,
        incident_id,
        {"foo": "1"},
        action_type=ActionType.INCIDENT_ENRICH,
        action_callee="bob@x",
        action_description="t",
        session=db_session,
        entity_type="incident",
    )
    enrich_entity(
        SINGLE_TENANT_UUID,
        incident_id,
        {"bar": "2"},
        action_type=ActionType.INCIDENT_ENRICH,
        action_callee="bob@x",
        action_description="t",
        session=db_session,
        entity_type="incident",
    )

    enr = _get_incident_enrichment(db_session, incident_id)
    # merge (not replace) — both keys present, single row (unique incident_id)
    assert enr.enrichments == {"foo": "1", "bar": "2"}


def test_incident_enrich_accepts_uuid_id(db_session):
    """The incident id may arrive as a UUID instance, not only a string."""
    incident = _make_incident(db_session)

    enrich_entity(
        SINGLE_TENANT_UUID,
        incident.id,  # a UUID, not a str
        {"foo": "1"},
        action_type=ActionType.INCIDENT_ENRICH,
        action_callee="bob@x",
        action_description="t",
        session=db_session,
        entity_type="incident",
    )

    enr = _get_incident_enrichment(db_session, incident.id)
    assert enr is not None
    assert enr.enrichments == {"foo": "1"}


def test_incident_enrich_no_dismissed_translation(db_session):
    incident = _make_incident(db_session)
    incident_id = str(incident.id)

    # the dismissed<->dismiss_mode translation must NOT be applied to incidents
    enrich_entity(
        SINGLE_TENANT_UUID,
        incident_id,
        {"dismissed": True},
        action_type=ActionType.INCIDENT_ENRICH,
        action_callee="bob@x",
        action_description="t",
        session=db_session,
        entity_type="incident",
    )

    enr = _get_incident_enrichment(db_session, incident_id)
    assert enr.enrichments == {"dismissed": True}
    assert "dismiss_mode" not in enr.enrichments
    assert "status" not in enr.enrichments


def test_incident_unenrich_removes_keys(db_session):
    incident = _make_incident(db_session)
    incident_id = str(incident.id)

    enrich_entity(
        SINGLE_TENANT_UUID,
        incident_id,
        {"foo": "1", "bar": "2"},
        action_type=ActionType.INCIDENT_ENRICH,
        action_callee="bob@x",
        action_description="t",
        session=db_session,
        entity_type="incident",
    )
    # force=True replaces the whole JSONB (how unenrich removes a key)
    enrich_entity(
        SINGLE_TENANT_UUID,
        incident_id,
        {"foo": "1"},
        action_type=ActionType.INCIDENT_UNENRICH,
        action_callee="bob@x",
        action_description="t",
        session=db_session,
        force=True,
        entity_type="incident",
    )

    enr = _get_incident_enrichment(db_session, incident_id)
    assert enr.enrichments == {"foo": "1"}


def test_alert_enrichment_path_writes_lastalert_not_incidentenrichment(db_session):
    """The alert path is unchanged: typed LastAlert columns, never an
    IncidentEnrichment row."""
    alert = Alert(
        id=uuid.uuid4(),
        tenant_id=SINGLE_TENANT_UUID,
        provider_type="test",
        provider_id="test",
        fingerprint="fp-alert",
        status="firing",
        severity="critical",
        name="a",
        alert_hash="hash-fp-alert",
    )
    db_session.add(alert)
    db_session.commit()
    set_last_alert(SINGLE_TENANT_UUID, alert, session=db_session)

    enrich_entity(
        SINGLE_TENANT_UUID,
        "fp-alert",
        {"status": "acknowledged", "assignee": "alice"},
        action_type=ActionType.GENERIC_ENRICH,
        action_callee="bob@x",
        action_description="t",
        session=db_session,
    )

    la = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, "fp-alert", session=db_session)
    assert la.status == "acknowledged"
    assert la.assignee == "alice"
    # no IncidentEnrichment row created for an alert fingerprint
    assert db_session.query(IncidentEnrichment).count() == 0
