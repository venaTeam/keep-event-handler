import abc
import asyncio
import json
import logging

from aiokafka import AIOKafkaConsumer

from config.consts import MAX_PROCESSING_RETRIES, KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC, KAFKA_CONSUMER_GROUP, KAFKA_SECURITY_PROTOCOL, KAFKA_SASL_MECHANISM, KAFKA_SASL_USERNAME, KAFKA_SASL_PASSWORD, KAFKA_SSL_CAFILE, KAFKA_SSL_CERTFILE, KAFKA_SSL_KEYFILE
from controllers.event_controller import process_event_wrapper
from models.event_dto import EventDTO


class EventConsumer(abc.ABC):
    @abc.abstractmethod
    async def start(self):
        pass

    @abc.abstractmethod
    async def stop(self):
        pass


class KafkaEventConsumer(EventConsumer):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        bootstrap_servers = KAFKA_BOOTSTRAP_SERVERS
        try:
            self.bootstrap_servers = json.loads(bootstrap_servers)
            if not isinstance(self.bootstrap_servers, list):
                self.bootstrap_servers = str(self.bootstrap_servers).split(",")
        except json.JSONDecodeError:
            self.bootstrap_servers = bootstrap_servers.split(",")
        self.topic = KAFKA_TOPIC
        self.group_id = KAFKA_CONSUMER_GROUP

        # SASL config
        self.security_protocol = KAFKA_SECURITY_PROTOCOL
        self.sasl_mechanism = KAFKA_SASL_MECHANISM
        # Handle None vs empty string vs missing config
        self.sasl_plain_username = KAFKA_SASL_USERNAME
        self.sasl_plain_password = KAFKA_SASL_PASSWORD

        # SSL config
        self.ssl_cafile = KAFKA_SSL_CAFILE
        self.ssl_certfile = KAFKA_SSL_CERTFILE
        self.ssl_keyfile = KAFKA_SSL_KEYFILE

        ssl_context = None
        if self.security_protocol in ["SSL", "SASL_SSL"]:
            import ssl
            ssl_context = ssl.create_default_context(cafile=self.ssl_cafile)
            if self.ssl_certfile and self.ssl_keyfile:
                ssl_context.load_cert_chain(
                    certfile=self.ssl_certfile, keyfile=self.ssl_keyfile
                )

        self.consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            # auto_offset_reset="earliest", # or latest? Default is latest.
            enable_auto_commit=False,
            security_protocol=self.security_protocol,
            sasl_mechanism=self.sasl_mechanism,
            sasl_plain_username=self.sasl_plain_username,
            sasl_plain_password=self.sasl_plain_password,
            ssl_context=ssl_context,
            api_version="auto",
        )
        self._running = False
        self._task = None

    async def start(self):
        if self._running:
            return

        self.logger.info(f"Starting Kafka Consumer on topic {self.topic}")
        await self.consumer.start()
        self._running = True

        # Create a background task to consume messages
        loop = asyncio.get_running_loop()
        self._task = loop.create_task(self._consume_loop())

    async def stop(self):
        if not self._running:
            return

        self.logger.info("Stopping Kafka Consumer")
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        await self.consumer.stop()
        self.logger.info("Kafka Consumer stopped")

    async def _consume_loop(self):
        try:
            async for msg in self.consumer:
                if not self._running:
                    break

                try:
                    payload = json.loads(msg.value.decode("utf-8"))
                    self.logger.debug(
                        f"Received event from Kafka: {payload.get('trace_id')}"
                    )

                    # Construct DTO
                    event_dto = EventDTO(
                        tenant_id=payload.get("tenant_id"),
                        trace_id=payload.get("trace_id"),
                        event=payload.get("event"),
                        provider_type=payload.get("provider_type"),
                        provider_id=payload.get("provider_id"),
                        fingerprint=payload.get("fingerprint"),
                        api_key_name=payload.get("api_key_name"),
                        provider_name=payload.get("provider_name"),
                    )

                    # Run logic via controller with retries
                    # We pass an empty dict as ctx since we are not in ARQ
                    # Retry using config
                    for i in range(MAX_PROCESSING_RETRIES):
                        try:
                            await process_event_wrapper(
                                ctx={},
                                event_dto=event_dto,
                            )
                            # If successful, break retry loop
                            break
                        except Exception as e:
                            self.logger.warning(
                                f"Error processing Kafka message (attempt {i+1}/{MAX_PROCESSING_RETRIES}): {e}"
                            )
                            if i == MAX_PROCESSING_RETRIES - 1:
                                # if this was the last attempt, re-raise
                                raise e
                            # otherwise wait a bit
                            await asyncio.sleep(1)

                    # Manually commit offset after successful processing
                    await self.consumer.commit()

                except Exception as e:
                    # Critical: Do NOT commit. Log exception.
                    # TODO: this should trigger a DLQ.
                    # For now, we ensure we don't lose the message by not committing.
                    self.logger.exception(f"Error processing Kafka message (trace_id={payload.get('trace_id', 'unknown')}): {e} - Message will be reprocessed on restart.")
                    # CRITICAL: We want to crash the loop so the pod restarts or alerts trigger
                    # rather than skipping the message silently.
                    raise e


        except Exception as e:
            self.logger.exception(f"Kafka consumer loop crashed: {e}")
            # Ensure we mark as not running so we know it stopped
            self._running = False
            # Re-raising might not crash the whole app because it's in a background task,
            # but it will stop consumption.
            # In a real K8s scenario, liveness probe should fail or we should explicitly exit.
            # For now, logging exception and stopping loop is what we requested.
            raise e
