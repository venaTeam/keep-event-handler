import asyncio
import functools
import logging

# TODO: Remove this import
from keep.common.event_management.process_event_task import process_event

from models.event_dto import EventDTO

logger = logging.getLogger(__name__)

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

    # Prepare partial function for sync execution
    process_event_func_sync = functools.partial(
        process_event,
        ctx=ctx,
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

    loop = asyncio.get_running_loop()
    
    # If in ARQ, use the provided thread pool. Else (Kafka), use default executor.
    executor = ctx.get("pool") if ctx else None
    
    resp = await loop.run_in_executor(executor, process_event_func_sync)
    
    logger.info(
        "Event processed successfully",
        extra={
            "tenant_id": event_dto.tenant_id,
            "trace_id": event_dto.trace_id,
        },
    )
    return resp
