import logging

from event_management.process_event_task import process_event

from models.event_dto import EventDTO
from models.action_type import ActionType
from enum import Enum

logger = logging.getLogger(__name__)

class EventType(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"
    ENRICH = "enrich"
    BATCH_ENRICH = "batch_enrich"


def _process_enrich_event(event_dto: EventDTO):
    from core.db.db import enrich_entity

    logger.info(
        f"Processing enrich event",
        extra={
            "tenant_id": event_dto.tenant_id,
            "fingerprint": event_dto.fingerprint,
        "event": event_dto.event,
        },
    )
    # Extract metadata AND cast action_type string back into an ActionType Enum
    # so we don't crash with "'str' has no attribute 'value'" in enrich_entity.
    action_type = ActionType(event_dto.event.pop("action_type"))
    action_callee = event_dto.event.pop("action_callee", "unknown")
    action_description = event_dto.event.pop("action_description", "")
    audit_enabled = event_dto.event.pop("audit_enabled", False)
    force = event_dto.event.pop("force", False)

    enrich_entity(
            event_dto.tenant_id,
            event_dto.fingerprint,
            event_dto.event,
            action_type,
            action_callee,
            action_description,
            audit_enabled=audit_enabled,
            session=None,
            force=force,
        )

def _process_batch_enrich_event(event_dto: EventDTO):
    from core.db.db import batch_enrich

    logger.info(
        f"Processing batch enrich event",
        extra={
            "tenant_id": event_dto.tenant_id,
            "fingerprint": event_dto.fingerprint,
        },
    )

    action_type = ActionType(event_dto.event.pop("action_type"))
    action_callee = event_dto.event.pop("action_callee", "unknown")
    action_description = event_dto.event.pop("action_description", "")
    audit_enabled = event_dto.event.pop("audit_enabled", False)

    batch_enrich(
            event_dto.tenant_id,
            event_dto.fingerprint,
            event_dto.event,
            action_type,
            action_callee,
            action_description,
            audit_enabled=audit_enabled,
            session=None,
        )



def _process_incident_event(event_dto: EventDTO):
    from core.db.db import create_incident_from_dict, delete_incident_by_id, update_incident_from_dto_by_id
    from models.incident import IncidentDtoIn
    from uuid import UUID

    action = event_dto.event.get("action", "create")
    incident_id = event_dto.event.get("id")

    logger.info(
        f"Processing {action} incident event",
        extra={
            "tenant_id": event_dto.tenant_id,
            "trace_id": event_dto.trace_id,
            "incident_id": incident_id,
            "action": action,
        },
    )
    
    if action == "create":
        create_incident_from_dict(
            tenant_id=event_dto.tenant_id,
            incident_data=event_dto.event,
            session=None,
        )
    elif action == "update":
        update_data = event_dto.event.get("update_data", {})
        generated_by_ai = event_dto.event.get("generated_by_ai", False)
        incident_dto_in = IncidentDtoIn(**update_data)
        update_incident_from_dto_by_id(
            tenant_id=event_dto.tenant_id,
            incident_id=UUID(incident_id),
            updated_incident_dto=incident_dto_in,
            generated_by_ai=generated_by_ai,
            session=None,
        )
    elif action == "delete":
        delete_incident_by_id(
            tenant_id=event_dto.tenant_id,
            incident_id=UUID(incident_id),
            session=None,
        )
        
    logger.info(
        f"Incident {action} event processed successfully",
        extra={
            "tenant_id": event_dto.tenant_id,
            "trace_id": event_dto.trace_id,
            "incident_id": incident_id,
            "action": action,
        },
    )

    return [{"status": "success", "message": f"Incident {action} processed from Kafka"}]


def _process_alert_event(event_dto: EventDTO):
    logger.info(
        f"Processing alert event: {event_dto.trace_id}",
        extra={
            "tenant_id": event_dto.tenant_id,
            "provider_type": event_dto.provider_type,
            "provider_id": event_dto.provider_id,
            "fingerprint": event_dto.fingerprint,
            "trace_id": event_dto.trace_id,
        },
    )

    # Call process_event directly (it's synchronous)
    resp = process_event(
        ctx={},  # No ARQ context in standalone mode
        tenant_id=event_dto.tenant_id,
        provider_type=event_dto.provider_type,
        provider_id=event_dto.provider_id,
        fingerprint=event_dto.fingerprint,
        api_key_name=event_dto.api_key_name,
        trace_id=event_dto.trace_id,
        event=event_dto.event,
        notify_client=event_dto.notify_client,
        timestamp_forced=event_dto.timestamp_forced,
        provider_name=event_dto.provider_name,
    )

    logger.info(
        "Alert event processed successfully",
        extra={
            "tenant_id": event_dto.tenant_id,
            "trace_id": event_dto.trace_id,
        },
    )
    return resp


FUNC_MAP = {
    EventType.ALERT: _process_alert_event,
    EventType.INCIDENT: _process_incident_event,
    EventType.ENRICH: _process_enrich_event,
    EventType.BATCH_ENRICH: _process_batch_enrich_event
}


def process_event_sync(event_dto: EventDTO):
    """
    Synchronous wrapper for processing events.
    Used by the confluent-kafka consumer which runs in a synchronous context.
    """
    logger.info(
        f"Processing event: {event_dto.trace_id}",
        extra={
            "event_type": event_dto.event_type,
            "tenant_id": event_dto.tenant_id,
            "provider_type": event_dto.provider_type,
            "provider_id": event_dto.provider_id,
            "fingerprint": event_dto.fingerprint,
            "trace_id": event_dto.trace_id,
        },
    )

    if event_dto.event_type in FUNC_MAP:
        return FUNC_MAP[event_dto.event_type](event_dto)
    else:
        raise logger.warning(f"Unknown event type: {event_dto.event_type}, ignoring event")


async def process_event_wrapper(
    ctx: dict,
    event_dto: EventDTO,
):
    """
    Wrapper controller for processing events. 
    This is called by both the ARQ worker (ctx is populated) 
    and the Kafka Consumer (ctx is empty/dummy).
    """
    logger.info(
        f"Processing event: {event_dto.trace_id}",
        extra={
            "tenant_id": event_dto.tenant_id,
            "provider_type": event_dto.provider_type,
            "provider_id": event_dto.provider_id,
            "fingerprint": event_dto.fingerprint,
            "trace_id": event_dto.trace_id,
        },
    )

    if event_dto.event_type == "incident" or event_dto.provider_type == "keep-incident":
        return _process_incident_event(event_dto)
    else:
        return _process_alert_event(event_dto)

