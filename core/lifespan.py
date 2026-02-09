import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from core.kafka_consumer import KafkaEventConsumer


from core.bootstrap import Bootstrap

logger = logging.getLogger(__name__)




@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Event Handler Service")
    
    bootstrap = await Bootstrap.get_instance()
    
    # Initialize DB and other resources
    await bootstrap.run_on_starting()
    
    consumer = KafkaEventConsumer()
    await consumer.start()

    yield

    # Shutdown
    logger.info("Shutting down Event Handler Service")

    if consumer:
        await consumer.stop()

    logger.info("Event Handler Service stopped")
