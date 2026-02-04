import asyncio
import logging

from core.bootstrap import Bootstrap
from core.kafka_consumer import EventConsumer


class RedisEventConsumer(EventConsumer):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._worker_task = None
        self._worker_id = "worker-service"

    async def start(self):
        self.logger.info("Starting Redis Consumer (ARQ Worker)")
        bootstrap = await Bootstrap.get_instance()
        loop = asyncio.get_running_loop()
        self._worker_task = loop.create_task(bootstrap.run_arq_worker(self._worker_id))

    async def stop(self):
        self.logger.info("Stopping Redis Consumer")
        if self._worker_task:
            if not self._worker_task.done():
                self._worker_task.cancel()
                try:
                    await self._worker_task
                except asyncio.CancelledError:
                    pass
        self.logger.info("Redis Consumer stopped")
