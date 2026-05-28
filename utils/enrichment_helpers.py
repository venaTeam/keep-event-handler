import logging
from datetime import datetime, timezone
from typing import Optional

from opentelemetry import trace
from sqlmodel import Session
from models.alert import (
    AlertDto,
    AlertStatus,
    AlertWithIncidentLinkMetadataDto,
)
from models.db.alert import Alert, LastAlertToIncident

tracer = trace.get_tracer(__name__)
logger = logging.getLogger(__name__)


def javascript_iso_format(last_received) -> str:
    """
    https://stackoverflow.com/a/63894149/12012756
    Accepts either an ISO-format string or a datetime (since the ORM column
    is now TIMESTAMPTZ and may bypass AlertDto's string-coercion validator).
    """
    if isinstance(last_received, datetime):
        dt = last_received
    else:
        dt = datetime.fromisoformat(last_received)
    # Normalize to UTC so the output is canonical "...Z" regardless of input TZ.
    # Postgres TIMESTAMPTZ returns datetimes in the session TZ (often the server's
    # local TZ, e.g. +03:00), which would otherwise emit "+03:00" suffix and break
    # comparisons against enrichments that store canonical UTC "Z" strings.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def calculated_start_firing_time(
    alert: AlertDto, previous_alert: AlertDto | list[AlertDto]
) -> str:
    """
    Calculate the start firing time of an alert based on the previous alert.

    Args:
        alert (AlertDto): The alert to calculate the start firing time for.
        previous_alert (AlertDto): The previous alert.

    Returns:
        str: The calculated start firing time.
    """
    # if the alert is not firing, there is no start firing time
    if alert.status != AlertStatus.FIRING.value:
        return None
    # if this is the first alert, the start firing time is the same as the last received time
    if not previous_alert:
        return alert.last_received
    elif isinstance(previous_alert, list):
        previous_alert = previous_alert[0]
    # else, if the previous alert was firing, the start firing time is the same as the previous alert
    if previous_alert.status == AlertStatus.FIRING.value:
        return previous_alert.firing_start_time
    # else, if the previous alert was resolved, the start firing time is the same as the last received time
    else:
        return alert.last_received


def calculate_firing_time_since_last_resolved(
    alert: AlertDto, previous_alert: AlertDto | list[AlertDto]
) -> int:
    """
    Calculate the firing counter of an alert based on the previous alert.
    """
    # if the alert is resolved, there is no firing time.
    if alert.status == AlertStatus.RESOLVED.value:
        return None
    else:
        # if there is previous alert, we need to check if it has firing time
        if previous_alert:
            if isinstance(previous_alert, list):
                previous_alert = previous_alert[0]
            if (
                previous_alert.status == AlertStatus.RESOLVED.value
                and alert.status == AlertStatus.FIRING.value
            ):
                return alert.last_received
            # if the previous alert has firing time since last resolved, we need to return it
            if previous_alert.firing_start_time_since_last_resolved:
                return previous_alert.firing_start_time_since_last_resolved
        else:
            # if there is no previous alert, we need to check if the alert is firing
            if alert.status == AlertStatus.FIRING.value:
                return alert.last_received
            else:
                return None


def calculated_firing_counter(
    alert: AlertDto, previous_alert: AlertDto | list[AlertDto]
) -> int:
    """
    Calculate the firing counter of an alert based on the previous alert.

    Args:
        alert (AlertDto): The alert to calculate the firing counter for.
        previous_alert (AlertDto): The previous alert.

    Returns:
        int: The calculated firing counter.
    """
    # if its an acknowledged alert, the firing counter is 0

    if alert.status == AlertStatus.ACKNOWLEDGED.value:
        return 0

    # if this is the first alert, the firing counter is 1
    if not previous_alert:
        return 1
    elif isinstance(previous_alert, list):
        previous_alert = previous_alert[0]

    if previous_alert.status == AlertStatus.ACKNOWLEDGED.value:
        return 1

    # else, increment counter if the previous alert was firing
    # NOTE: firing_counter -> 0 only if acknowledged
    return previous_alert.firing_counter + 1


def calculated_unresolved_counter(
    alert: AlertDto, previous_alert: AlertDto | list[AlertDto]
) -> int:
    """
    Calculate the unresolved counter of an alert based on the previous alert.

    Args:
        alert (AlertDto): The alert to calculate the unresolved counter for.
        previous_alert (AlertDto): The previous alert.

    Returns:
        int: The calculated unresolved counter.
    """
    # if it's a resolved alert, the unresolved counter is 0
    if alert.status == AlertStatus.RESOLVED.value:
        return 0

    # if this is the first alert, the unresolved counter is 1
    if not previous_alert:
        return 1
    elif isinstance(previous_alert, list):
        previous_alert = previous_alert[0]

    if previous_alert.status == AlertStatus.RESOLVED.value:
        return 1

    # else, increment counter if the previous alert was firing
    # NOTE: unresolved_counter -> 0 only if resolved
    return previous_alert.unresolved_counter + 1


def _last_alert_to_dto_payload(last_alert) -> dict:
    """Build the DTO payload contribution (user enrichment + relocated tracking
    fields) from a LastAlert row's typed columns (Phase 2)."""
    payload: dict = {}
    # user enrichment state
    if last_alert.status is not None:
        payload["status"] = last_alert.status
    if last_alert.assignee is not None:
        payload["assignee"] = last_alert.assignee
    if last_alert.note is not None:
        payload["note"] = last_alert.note
    # derived dismissed compat field + dismiss details
    payload["dismissed"] = last_alert.status == "suppressed"
    if last_alert.dismiss_mode is not None:
        payload["dismiss_mode"] = last_alert.dismiss_mode
    if last_alert.dismissed_until is not None:
        ts = last_alert.dismissed_until
        if isinstance(ts, datetime):
            # Match the legacy "...%f.Z" wire format AlertDto.validate_dismissed parses
            # (strptime "%Y-%m-%dT%H:%M:%S.%fZ"); plain .isoformat() yields "...+00:00"
            # which the validator rejects and json.dumps cannot serialize a raw datetime.
            ts = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload["dismissed_until"] = ts
    payload["deleted"] = bool(last_alert.deleted)
    # relocated tracking fields
    if last_alert.last_received is not None:
        payload["last_received"] = last_alert.last_received
    payload["firing_counter"] = last_alert.firing_counter or 0
    payload["unresolved_counter"] = last_alert.unresolved_counter or 0
    if last_alert.started_at is not None:
        payload["started_at"] = last_alert.started_at
    if last_alert.firing_start_time is not None:
        payload["firing_start_time"] = last_alert.firing_start_time
    if last_alert.firing_start_time_since_last_resolved is not None:
        payload["firing_start_time_since_last_resolved"] = (
            last_alert.firing_start_time_since_last_resolved
        )
    return payload


def convert_db_alerts_to_dto_alerts(
    alerts: list[Alert | tuple[Alert, LastAlertToIncident]],
    with_incidents: bool = False,
    session: Optional[Session] = None,
) -> list[AlertDto | AlertWithIncidentLinkMetadataDto]:
    """
    Build AlertDtos, sourcing user-enrichment state and relocated tracking
    fields from the per-fingerprint LastAlert typed columns (Phase 2).

    Args:
        alerts (list[Alert]): The alerts to enrich.
        with_incidents (bool): enrich with incidents data

    Returns:
        list[AlertDto | AlertWithIncidentLinkMetadataDto]: The enriched alerts.
    """
    # Lazy import to avoid circular dependency
    from core.db.db import existed_or_new_session
    from models.db.alert import LastAlert
    from models.incident import IncidentDto
    from sqlmodel import select

    with existed_or_new_session(session) as session:
        # Batch-fetch LastAlert rows grouped by tenant_id so the WHERE clause
        # is the natural (tenant_id, fingerprint IN ...) prefix-index path
        # instead of a cartesian (tenant_id IN ..., fingerprint IN ...) that
        # would also return cross-tenant rows the caller has to discard.
        fps_by_tenant: dict[str, set[str]] = {}
        for _object in alerts:
            alert = _object if isinstance(_object, Alert) else _object[0]
            fps_by_tenant.setdefault(alert.tenant_id, set()).add(alert.fingerprint)

        last_alerts_by_key = {}
        for tid, fps in fps_by_tenant.items():
            if not fps:
                continue
            rows = session.exec(
                select(LastAlert)
                .where(LastAlert.tenant_id == tid)
                .where(LastAlert.fingerprint.in_(fps))
            ).all()
            for la in rows:
                last_alerts_by_key[(la.tenant_id, la.fingerprint)] = la

        alerts_dto = []
        with tracer.start_as_current_span("alerts_enrichment"):
            for _object in alerts:
                # We may have an Alert only or and Alert with an LastAlertToIncident
                if isinstance(_object, Alert):
                    alert, alert_to_incident = _object, None
                else:
                    alert, alert_to_incident = _object

                alert_payload = alert.dict()

                last_alert = last_alerts_by_key.get(
                    (alert.tenant_id, alert.fingerprint)
                )
                if last_alert is not None:
                    alert_payload.update(_last_alert_to_dto_payload(last_alert))

                if with_incidents:
                    if alert._incidents:
                        alert_payload["incident"] = ",".join(
                            str(incident.id) for incident in alert._incidents
                        )
                        alert_payload["incident_dto"] = [
                            IncidentDto.from_db_incident(incident)
                            for incident in alert._incidents
                        ]
                try:
                    if alert_to_incident is not None:
                        alert_dto = AlertWithIncidentLinkMetadataDto.from_db_instance(
                            alert, alert_to_incident, payload=alert_payload
                        )
                    else:
                        alert_dto = AlertDto(**alert_payload)

                except Exception:
                    # should never happen but just in case
                    logger.exception(
                        "Failed to parse alert",
                        extra={
                            "alert": alert,
                        },
                    )
                    continue

                alert_dto.event_id = str(alert.id)

                # if the alert is acknowledged, the firing counter is 0
                if alert_dto.status == AlertStatus.ACKNOWLEDGED.value:
                    alert_dto.firing_counter = 0

                # if the alert is resolved, the unresolved counter is 0
                if alert_dto.status == AlertStatus.RESOLVED.value:
                    alert_dto.unresolved_counter = 0

                # always update provider id and type to the new values
                alert_dto.provider_id = alert.provider_id
                alert_dto.provider_type = alert.provider_type
                alerts_dto.append(alert_dto)
    return alerts_dto
