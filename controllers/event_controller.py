import asyncio
import functools
import logging

from event_management.process_event_task import process_event

from models.event_dto import EventDTO
from enum import Enum

logger = logging.getLogger(__name__)
logger = logging.getLogger(__name__)

class EventType(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"


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


def process_event_sync(event_dto: EventDTO):
    """
    Synchronous wrapper for processing events.
    Used by the confluent-kafka consumer which runs in a synchronous context.
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

    if event_dto.event_type == EventType.INCIDENT:
        return _process_incident_event(event_dto)
    elif event_dto.event_type == EventType.ALERT:
        return _process_alert_event(event_dto)
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

