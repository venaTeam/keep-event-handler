"""Deleting an incident removes the row and everything that hangs off it.

`delete_incident_by_id` used to soft-delete by writing a `deleted` status, a
value `IncidentStatus` no longer has. It is now a real DELETE, in step with
keep-api-gateway: both services share one database and must agree on what
deleting an incident means.

Mirrors `tests/test_incident_hard_delete.py` in keep-api-gateway.
"""

import uuid
from datetime import datetime, timezone

from src.core.db.db import (
    add_alerts_to_incident,
    delete_incident_by_id,
    set_last_alert,
)
from src.core.dependencies import SINGLE_TENANT_UUID
from src.models.alert import AlertStatus
from src.models.db.alert import (
    Alert,
    AlertAudit,
    IncidentEnrichment,
    LastAlert,
    LastAlertToIncident,
)
from src.models.db.incident import Incident, IncidentStatus


def _incident(db_session, name="delete-test", **kwargs) -> Incident:
    incident = Incident(
        tenant_id=SINGLE_TENANT_UUID,
        user_generated_name=name,
        user_summary="s",
        generated_summary="s",
        status=IncidentStatus.FIRING.value,
        **kwargs,
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    return incident


def _alert(db_session, fingerprint) -> str:
    alert = Alert(
        id=uuid.uuid4(),
        tenant_id=SINGLE_TENANT_UUID,
        timestamp=datetime.now(tz=timezone.utc),
        provider_type="test",
        provider_id="test",
        status=AlertStatus.FIRING.value,
        fingerprint=fingerprint,
        alert_hash="hash-" + fingerprint,
    )
    db_session.add(alert)
    db_session.commit()
    set_last_alert(SINGLE_TENANT_UUID, alert, session=db_session)
    return fingerprint


def _count(db_session, model, *criteria) -> int:
    db_session.expire_all()
    return db_session.query(model).filter(*criteria).count()


def test_delete_removes_the_incident_row(db_session):
    incident = _incident(db_session)

    assert delete_incident_by_id(SINGLE_TENANT_UUID, incident.id, session=db_session)

    assert _count(db_session, Incident, Incident.id == incident.id) == 0


def test_delete_accepts_a_string_id(db_session):
    incident = _incident(db_session)

    assert delete_incident_by_id(
        SINGLE_TENANT_UUID, str(incident.id), session=db_session
    )

    assert _count(db_session, Incident, Incident.id == incident.id) == 0


def test_delete_of_a_missing_incident_returns_false(db_session):
    """The gateway deletes first and then publishes, so by the time the delete
    event reaches this service the row is usually already gone."""
    assert not delete_incident_by_id(
        SINGLE_TENANT_UUID, uuid.uuid4(), session=db_session
    )


def test_delete_removes_dependents_but_keeps_the_alerts(db_session):
    incident = _incident(db_session)
    incident_id = incident.id
    fingerprint = _alert(db_session, "fp-delete-1")
    add_alerts_to_incident(
        SINGLE_TENANT_UUID, incident, [fingerprint], session=db_session
    )
    db_session.add(
        IncidentEnrichment(
            tenant_id=SINGLE_TENANT_UUID,
            incident_id=incident_id,
            enrichments={"note": "n"},
        )
    )
    db_session.add(
        AlertAudit(
            tenant_id=SINGLE_TENANT_UUID,
            fingerprint=str(incident_id),
            user_id="tester",
            action="incident comment",
            description="d",
        )
    )
    db_session.commit()

    assert delete_incident_by_id(SINGLE_TENANT_UUID, incident_id, session=db_session)

    assert (
        _count(
            db_session,
            LastAlertToIncident,
            LastAlertToIncident.incident_id == incident_id,
        )
        == 0
    )
    assert (
        _count(
            db_session,
            IncidentEnrichment,
            IncidentEnrichment.incident_id == incident_id,
        )
        == 0
    )
    assert (
        _count(db_session, AlertAudit, AlertAudit.fingerprint == str(incident_id)) == 0
    )
    # The alerts outlive the incident that grouped them.
    assert _count(db_session, Alert, Alert.fingerprint == fingerprint) == 1
    assert _count(db_session, LastAlert, LastAlert.fingerprint == fingerprint) == 1


def test_delete_clears_references_from_sibling_incidents(db_session):
    target = _incident(db_session, name="target")
    merged = _incident(db_session, name="merged", merged_into_incident_id=target.id)
    recurrence = _incident(
        db_session, name="recurrence", same_incident_in_the_past_id=target.id
    )
    merged_id, recurrence_id = merged.id, recurrence.id

    assert delete_incident_by_id(SINGLE_TENANT_UUID, target.id, session=db_session)

    db_session.expire_all()
    assert db_session.get(Incident, merged_id).merged_into_incident_id is None
    assert db_session.get(Incident, recurrence_id).same_incident_in_the_past_id is None
