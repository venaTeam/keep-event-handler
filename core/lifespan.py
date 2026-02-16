import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from config.config import config


from core.bootstrap import Bootstrap

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan handler.
    
    For KAFKA messaging, this lifespan is NOT used for consumption.
    The Kafka consumer runs as a standalone process via consumer_main.py.
    
    For REDIS messaging, the Redis/ARQ consumer is started here.
    """
    # Startup
    logger.info("Starting Event Handler Service")
    
    bootstrap = await Bootstrap.get_instance()
    
    # Initialize DB and other resources
    await bootstrap.run_on_starting()

    messaging_type = config("MESSAGING_TYPE", default="REDIS").upper()
    consumer = None

    if messaging_type == "KAFKA":
        # For Kafka, the consumer runs as a standalone process (consumer_main.py)
        # This lifespan is only used for health checks and metrics endpoints
        logger.info(
            "MESSAGING_TYPE is KAFKA - Kafka consumer runs standalone. "
            "Use consumer_main.py for consumption."
        )
        # Don't start the blocking consumer here - it would block the FastAPI app

    yield

    # Shutdown
    logger.info("Shutting down Event Handler Service")

    if consumer:
        await consumer.stop()

    logger.info("Event Handler Service stopped")
