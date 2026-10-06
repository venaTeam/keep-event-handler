import logging

from src.event_management.process_event_task import process_event

from src.models.event_dto import EventDTO, EventType


logger = logging.getLogger(__name__)

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
            "event_type": event_dto.event_type,
            "tenant_id": event_dto.tenant_id,
            "provider_type": event_dto.provider_type,
            "provider_id": event_dto.provider_id,
            "fingerprint": event_dto.fingerprint,
            "trace_id": event_dto.trace_id,
        },
    )

    # Only new alerts are consumed here. Enrichment, delete and incident changes
    # are written by keep-api-gateway directly; such an event can still arrive
    # from the topic's backlog, and is skipped rather than retried.
    if event_dto.event_type not in (None, EventType.ALERT):
        logger.warning(
            f"Ignoring non-alert event: {event_dto.event_type}",
            extra={
                "event_type": event_dto.event_type,
                "tenant_id": event_dto.tenant_id,
                "trace_id": event_dto.trace_id,
            },
        )
        return None

    return _process_alert_event(event_dto)
