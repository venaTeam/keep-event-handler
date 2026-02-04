import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from config.consts import MESSAGING_TYPE


from core.bootstrap import Bootstrap

logger = logging.getLogger(__name__)




@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Event Handler Service")
    
    bootstrap = await Bootstrap.get_instance()
    
    # Initialize DB and other resources
    await bootstrap.run_on_starting()

    messaging_type = MESSAGING_TYPE.upper()
    consumer = None

    if messaging_type == "KAFKA":
        from core.kafka_consumer import KafkaEventConsumer

        logger.info("MESSAGING_TYPE is KAFKA - starting Kafka Consumer")
        consumer = KafkaEventConsumer()
    else:
        # Default to REDIS / ARQ
        from core.redis_consumer import RedisEventConsumer

        logger.info(f"MESSAGING_TYPE is {messaging_type} - starting Redis Consumer (ARQ)")
        consumer = RedisEventConsumer()

    # Start the consumer (whether Redis or Kafka)
    await consumer.start()

    yield

    # Shutdown
    logger.info("Shutting down Event Handler Service")

    if consumer:
        await consumer.stop()

    logger.info("Event Handler Service stopped")
