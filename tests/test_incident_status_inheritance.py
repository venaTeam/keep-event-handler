"""Alerts linked to a suppressed/acknowledged incident inherit its state.

This is the event-handler half of the behaviour. It matters here specifically
because correlation lives on this side: the rules engine reaches alerts through
`assign_alert_to_incident` -> `add_alerts_to_incident`, so without the hook in
that function, dismissing an incident only quietens the alerts it already held
and the next alert a rule pulls in lights it up again.

Suppression travels as dismiss state, never as status='suppressed'. Alerts derive
suppression from dismiss_mode/dismissed_until, so inheriting the incident's
deadline is what makes the alert come back on the same clock; writing a status
would strand it suppressed after the deadline passed.

Mirrors `tests/test_incident_status_propagation.py` in keep-api-gateway.
"""

import uuid
from datetime import datetime, timedelta, timezone

from src.core.db.db import add_alerts_to_incident, set_last_alert
from src.core.dependencies import SINGLE_TENANT_UUID
from src.models.alert import AlertStatus
from src.models.db.alert import Alert, LastAlert
from src.models.db.incident import Incident, IncidentDismissMode, IncidentStatus


def _future(minutes=60):
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def _past(minutes=60):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def _incident(db_session, status=IncidentStatus.FIRING, **kwargs) -> Incident:
    incident = Incident(
        tenant_id=SINGLE_TENANT_UUID,
        user_generated_name="inherit-test",
        user_summary="s",
        generated_summary="s",
        status=status.value,
        **kwargs,
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)
    return incident


def _alert(db_session, fingerprint, status=AlertStatus.FIRING.value) -> str:
    alert = Alert(
        id=uuid.uuid4(),
        tenant_id=SINGLE_TENANT_UUID,
        timestamp=datetime.now(tz=timezone.utc),
        provider_type="test",
        provider_id="test",
        status=status,
        fingerprint=fingerprint,
        alert_hash="hash-" + fingerprint,
    )
    db_session.add(alert)
    db_session.commit()
    set_last_alert(SINGLE_TENANT_UUID, alert, session=db_session)
    return fingerprint


def _state(db_session, fingerprint) -> dict:
    db_session.expire_all()
    last_alert = (
        db_session.query(LastAlert)
        .filter(LastAlert.fingerprint == fingerprint)
        .one()
    )
    provider_status = (
        db_session.query(Alert.status)
        .filter(Alert.fingerprint == fingerprint)
        .scalar()
    )
    return {
        "effective": last_alert.get_effective_status(provider_status),
        "override": last_alert.status,
        "dismiss_mode": last_alert.dismiss_mode,
        "dismissed_until": last_alert.dismissed_until,
        "assignee": last_alert.assignee,
    }


def test_linking_to_a_firing_incident_inherits_nothing(db_session):
    incident = _incident(db_session)
    fp = _alert(db_session, "inh-firing")

    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [fp], session=db_session)

    state = _state(db_session, fp)
    assert state["effective"] == "firing"
    assert state["dismiss_mode"] is None


def test_linking_to_a_permanently_suppressed_incident_inherits_the_dismissal(
    db_session,
):
    incident = _incident(
        db_session, dismiss_mode=IncidentDismissMode.PERMANENT.value
    )
    fp = _alert(db_session, "inh-sup-permanent")

    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [fp], session=db_session)

    state = _state(db_session, fp)
    assert state["effective"] == "suppressed"
    assert state["dismiss_mode"] == IncidentDismissMode.PERMANENT.value
    # Never stored as a status — that is what lets a dismissal expire.
    assert state["override"] is None


def test_linking_inherits_the_incidents_deadline(db_session):
    deadline = _future(90)
    incident = _incident(
        db_session,
        dismiss_mode=IncidentDismissMode.DISMISS_UNTIL.value,
        dismissed_until=deadline,
    )
    fp = _alert(db_session, "inh-sup-until")

    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [fp], session=db_session)

    state = _state(db_session, fp)
    assert state["effective"] == "suppressed"
    assert state["dismiss_mode"] == IncidentDismissMode.DISMISS_UNTIL.value
    assert state["dismissed_until"] is not None


def test_an_expired_incident_dismissal_is_not_inherited(db_session):
    """An incident whose deadline has passed is firing again, so it imposes
    nothing — and must not hand out a dismissal that is already over."""
    incident = _incident(
        db_session,
        dismiss_mode=IncidentDismissMode.DISMISS_UNTIL.value,
        dismissed_until=_past(30),
    )
    assert incident.get_effective_status() == "firing"
    fp = _alert(db_session, "inh-sup-expired")

    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [fp], session=db_session)

    state = _state(db_session, fp)
    assert state["effective"] == "firing"
    assert state["dismiss_mode"] is None


def test_linking_to_an_acknowledged_incident_inherits_the_status(db_session):
    incident = _incident(db_session, status=IncidentStatus.ACKNOWLEDGED)
    fp = _alert(db_session, "inh-ack")

    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [fp], session=db_session)

    assert _state(db_session, fp)["effective"] == "acknowledged"


def test_acknowledged_incident_also_hands_over_its_assignee(db_session):
    incident = _incident(
        db_session, status=IncidentStatus.ACKNOWLEDGED, assignee="owner@keep"
    )
    fp = _alert(db_session, "inh-ack-assignee")

    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [fp], session=db_session)

    assert _state(db_session, fp)["assignee"] == "owner@keep"


def test_a_resolved_alert_is_never_dragged_out_of_resolved(db_session):
    incident = _incident(
        db_session, dismiss_mode=IncidentDismissMode.PERMANENT.value
    )
    fp = _alert(db_session, "inh-resolved", status=AlertStatus.RESOLVED.value)

    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [fp], session=db_session)

    state = _state(db_session, fp)
    assert state["effective"] == "resolved"
    assert state["dismiss_mode"] is None


def test_linking_to_a_resolved_incident_inherits_nothing(db_session):
    incident = _incident(db_session, status=IncidentStatus.RESOLVED)
    fp = _alert(db_session, "inh-on-resolved")

    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [fp], session=db_session)

    assert _state(db_session, fp)["effective"] == "firing"


def test_only_the_newly_linked_alerts_are_touched(db_session):
    """Re-linking must not re-stamp alerts that were already in the incident and
    have since been changed by hand."""
    incident = _incident(
        db_session, dismiss_mode=IncidentDismissMode.PERMANENT.value
    )
    first = _alert(db_session, "inh-first")
    add_alerts_to_incident(SINGLE_TENANT_UUID, incident, [first], session=db_session)
    assert _state(db_session, first)["effective"] == "suppressed"

    # The user un-dismisses that alert on its own.
    last_alert = (
        db_session.query(LastAlert)
        .filter(LastAlert.fingerprint == first)
        .one()
    )
    last_alert.dismiss_mode = None
    last_alert.dismissed_until = None
    db_session.commit()

    second = _alert(db_session, "inh-second")
    add_alerts_to_incident(
        SINGLE_TENANT_UUID, incident, [first, second], session=db_session
    )

    # `first` is already linked, so it is not a new fingerprint and keeps the
    # user's decision; `second` inherits.
    assert _state(db_session, first)["dismiss_mode"] is None
    assert _state(db_session, second)["effective"] == "suppressed"


def test_a_suppressed_incident_stays_eligible_for_grouping(db_session):
    """Suppression must not read as "closed": the stored status is still
    firing/acknowledged, so correlation keeps routing alerts into it rather than
    spawning a new incident per alert while it is dismissed."""
    incident = _incident(
        db_session, dismiss_mode=IncidentDismissMode.PERMANENT.value
    )
    assert incident.get_effective_status() == "suppressed"
    assert incident.status not in IncidentStatus.get_closed(return_values=True)
