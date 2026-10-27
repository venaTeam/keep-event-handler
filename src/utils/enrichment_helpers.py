import logging
from datetime import datetime, timezone
from typing import Optional

from opentelemetry import trace
from sqlmodel import Session
from src.models.alert import (
    AlertDto,
    AlertStatus,
    AlertWithIncidentLinkMetadataDto,
)
from src.models.db.alert import Alert, LastAlert, LastAlertToIncident

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


def derive_tracking_fields(
    alert_status: str,
    last_received: str,
    previous: Optional[LastAlert],
) -> dict:
    """Derive the cross-occurrence tracking fields for a new occurrence.

    ``previous`` is the LastAlert row as it stands *before* this occurrence is
    applied to it (None for a fingerprint's first occurrence). Every input lives
    on that row, so recording an occurrence never has to read the partitioned
    ``alert`` history.

    A previous row with a NULL ``status`` either predates the typed-column model
    or was written while the tracking calculation was disabled. NULL means the
    fingerprint was never resolved, acknowledged or dismissed, so it reads as
    firing; a missing start-time falls back to this occurrence's
    ``last_received`` rather than staying NULL forever.
    """
    firing = AlertStatus.FIRING.value
    resolved = AlertStatus.RESOLVED.value
    acknowledged = AlertStatus.ACKNOWLEDGED.value

    previous_status = None if previous is None else (previous.status or firing)

    if alert_status != firing:
        firing_start_time = None
    elif previous is None or previous_status != firing:
        firing_start_time = last_received
    else:
        firing_start_time = previous.firing_start_time or last_received

    if alert_status == resolved:
        since_last_resolved = None
    elif previous is None:
        since_last_resolved = last_received if alert_status == firing else None
    elif previous_status == resolved and alert_status == firing:
        since_last_resolved = last_received
    else:
        since_last_resolved = previous.firing_start_time_since_last_resolved
        if since_last_resolved is None and alert_status == firing:
            since_last_resolved = last_received

    if alert_status == acknowledged:
        firing_counter = 0
    elif previous is None or previous_status == acknowledged:
        firing_counter = 1
    else:
        firing_counter = (previous.firing_counter or 0) + 1

    if alert_status == resolved:
        unresolved_counter = 0
    elif previous is None or previous_status == resolved:
        unresolved_counter = 1
    else:
        unresolved_counter = (previous.unresolved_counter or 0) + 1

    return {
        "firing_start_time": firing_start_time,
        "firing_start_time_since_last_resolved": since_last_resolved,
        "firing_counter": firing_counter,
        "unresolved_counter": unresolved_counter,
    }


def _last_alert_to_dto_payload(last_alert) -> dict:
    """Build the DTO payload contribution (user enrichment + relocated tracking
    fields) from a LastAlert row's typed columns."""
    payload: dict = {}
    # user enrichment state
    if last_alert.status is not None:
        payload["status"] = last_alert.status
    if last_alert.assignee is not None:
        payload["assignee"] = last_alert.assignee
    if last_alert.note is not None:
        payload["note"] = last_alert.note
    # dismiss details
    if last_alert.dismiss_mode is not None:
        payload["dismiss_mode"] = last_alert.dismiss_mode
    if last_alert.dismissed_until is not None:
        ts = last_alert.dismissed_until
        if isinstance(ts, datetime):
            # Emit the typed DateTime column as an ISO 8601 "...%f.Z" string so
            # JSON consumers see a string on the wire; plain .isoformat() yields
            # "...+00:00" which json.dumps cannot serialize from a raw datetime.
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
    fields from the per-fingerprint LastAlert typed columns.

    Args:
        alerts (list[Alert]): The alerts to enrich.
        with_incidents (bool): enrich with incidents data

    Returns:
        list[AlertDto | AlertWithIncidentLinkMetadataDto]: The enriched alerts.
    """
    # Lazy import to avoid circular dependency
    from src.core.db.db import existed_or_new_session
    from src.models.db.alert import LastAlert
    from src.models.incident import IncidentDto
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
