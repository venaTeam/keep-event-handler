import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from uuid import uuid4

import redis
from arq import Worker, cron
from arq.worker import create_worker
from dotenv import find_dotenv, load_dotenv
from pydantic.utils import import_string
from starlette.datastructures import CommaSeparatedStrings

# TODO: remove
import logging_conf
from config.consts import (
    KEEP_ARQ_QUEUE_BASIC,
    KEEP_ARQ_TASK_POOL,
    KEEP_ARQ_TASK_POOL_ALL,
    KEEP_ARQ_TASK_POOL_BASIC_PROCESSING,
    WATCHER_LAPSED_TIME,
    ARQ_KEEP_RESULT,
    ARQ_EXPIRES,
)

# TODO: remove
from keep.common.redis_settings import get_redis_settings
from core.event_controller import process_event_wrapper
from core.event_dto import EventDTO

# Load environment variables
load_dotenv(find_dotenv())
logging_conf.setup_logging()
logger = logging.getLogger(__name__)

# Current worker will pick up tasks only according to its execution pool:
all_tasks_for_the_worker = []

if KEEP_ARQ_TASK_POOL in [KEEP_ARQ_TASK_POOL_ALL, KEEP_ARQ_TASK_POOL_BASIC_PROCESSING]:
    logger.info(
        "Enabling basic processing tasks for the worker",
        extra={"task_pool": KEEP_ARQ_TASK_POOL},
    )
    all_tasks_for_the_worker += [
        ("keep.common.event_management.process_event_task.async_process_event", KEEP_ARQ_QUEUE_BASIC),
        (
            "keep.common.event_management.process_topology_task.async_process_topology",
            KEEP_ARQ_QUEUE_BASIC,
        ),
        (
            "keep.common.event_management.process_incident_task.async_process_incident",
            KEEP_ARQ_QUEUE_BASIC,
        ),
    ]


RQ_BACKGROUND_FUNCTIONS: Optional[CommaSeparatedStrings] = CommaSeparatedStrings([task for task, _ in all_tasks_for_the_worker])

FUNCTIONS: list = (
    [
        import_string(background_function)
        for background_function in list(ARQ_BACKGROUND_FUNCTIONS)
    ]
    if ARQ_BACKGROUND_FUNCTIONS is not None
    else list()
)



# Register the event controller as the ARQ function
# We alias it to 'process_event_in_worker' to match what the producer enqueues
async def process_event_in_worker(ctx, *args, **kwargs):
    # Map ARQ kwargs to DTO
    event_dto = EventDTO(
        tenant_id=kwargs.get("tenant_id"),
        trace_id=kwargs.get("trace_id"),
        event=kwargs.get("event"),
        provider_type=kwargs.get("provider_type"),
        provider_id=kwargs.get("provider_id"),
        fingerprint=kwargs.get("fingerprint"),
        api_key_name=kwargs.get("api_key_name"),
        provider_name=kwargs.get("provider_name"),
        timestamp_forced=kwargs.get("timestamp_forced"),
        notify_client=kwargs.get("notify_client", True),
    )
    return await process_event_wrapper(ctx, event_dto=event_dto)

FUNCTIONS.append(process_event_in_worker)


async def startup(ctx):
    """ARQ worker startup callback"""
    EVENT_WORKERS = int(KEEP_EVENT_WORKERS)  
    # Create dedicated threadpool
    process_event_executor = ThreadPoolExecutor(
        max_workers=EVENT_WORKERS, thread_name_prefix="process_event_worker"
    )
    ctx["pool"] = process_event_executor


async def shutdown(ctx):
    """ARQ worker shutdown callback"""
    # Clean up any resources if needed
    if "pool" in ctx:
        ctx["pool"].shutdown(wait=True)


class WorkerSettings:
    """
    Settings for the ARQ worker.
    """

    on_startup = startup
    on_shutdown = shutdown
    redis_settings = get_redis_settings()
    timeout = 30
    functions: list = FUNCTIONS
    cron_jobs: list = [
        cron(
            "keep.common.event_management.process_watcher_task.async_process_watcher",
            second=max(0, WATCHER_LAPSED_TIME - 1),
        )
    ]
    queue_name: str
    health_check_interval: int = 10
    health_check_key: str

    def __init__(self, queue_name: str):
        self.queue_name = queue_name


def get_arq_worker(queue_name: str) -> Worker:
    """
    Create and configure an ARQ worker for the specified queue.
    """
    keep_result = int(ARQ_KEEP_RESULT)
    expires = int(ARQ_EXPIRES)

    # generate a worker id so each worker will have a different health check key
    worker_id = str(uuid4()).replace("-", "")
    worker = create_worker(
        WorkerSettings,
        keep_result=keep_result,
        expires_extra_ms=expires,
        queue_name=queue_name,
        health_check_key=f"{queue_name}:{worker_id}:health-check",
    )
    return worker


async def safe_run_worker(worker: Worker, number_of_errors_before_restart=0):
    """
    Run a worker with automatic reconnection in case of Redis connection errors.

    Args:
        worker: The ARQ worker to run
    """
    try:
        number_of_errors = 0
        while True:
            try:
                await worker.async_run()
            except asyncio.CancelledError:  # pragma: no cover
                # happens on shutdown, fine
                pass
            except redis.exceptions.ConnectionError:
                number_of_errors += 1
                # we want to raise an exception if we have too many errors
                if (
                    number_of_errors_before_restart
                    and number_of_errors >= number_of_errors_before_restart
                ):
                    logger.error(
                        f"Worker encountered {number_of_errors} errors, restarting..."
                    )
                    raise
                logger.exception("Failed to connect to Redis... Retry in 3 seconds")
                await asyncio.sleep(3)
                continue
            except Exception:
                number_of_errors += 1
                # we want to raise an exception if we have too many errors
                if (
                    number_of_errors_before_restart
                    and number_of_errors >= number_of_errors_before_restart
                ):
                    logger.error(
                        f"Worker encountered {number_of_errors} errors, restarting..."
                    )
                    raise
                # o.w: log the error and continue
                logger.exception("Worker error")
                await asyncio.sleep(3)
                continue

            break
    finally:
        await worker.close()
