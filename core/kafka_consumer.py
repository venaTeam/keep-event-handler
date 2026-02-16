"""
Kafka consumer for the event handler service using confluent-kafka.
Runs a synchronous consumer loop - designed to run standalone without gunicorn.
"""
import abc
import json
import logging
import signal
import threading
import time
from typing import Optional

from confluent_kafka import Consumer, KafkaError, KafkaException

from config.consts import MAX_PROCESSING_RETRIES
from config.config import config
from core.metrics import (
    events_in_counter,
    events_out_counter,
    events_error_counter,
    processing_time_summary,
)
from controllers.event_controller import process_event_sync
from models.event_dto import EventDTO


logger = logging.getLogger(__name__)


class EventConsumer(abc.ABC):
    @abc.abstractmethod
    def start(self):
        pass

    @abc.abstractmethod
    def stop(self):
        pass


class KafkaEventConsumer(EventConsumer):
    """
    Synchronous Kafka consumer using confluent-kafka.
    Runs in a blocking loop, suitable for standalone process execution.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._running = False
        self._consumer: Optional[Consumer] = None
        self._shutdown_event = threading.Event()

        # Parse bootstrap servers
        bootstrap_servers = config(
            "KAFKA_BOOTSTRAP_SERVERS", default="localhost:9092"
        )
        try:
            parsed = json.loads(bootstrap_servers)
            if isinstance(parsed, list):
                self.bootstrap_servers = ",".join(parsed)
            else:
                self.bootstrap_servers = str(parsed)
        except json.JSONDecodeError:
            self.bootstrap_servers = bootstrap_servers

        self.topic = config("KAFKA_TOPIC", default="keep-events")
        self.group_id = config("KAFKA_CONSUMER_GROUP", default="keep-event-handler")

        # Consumer tuning
        self._poll_timeout = float(config("KAFKA_POLL_TIMEOUT_SECONDS", default="1.0"))
        self._session_timeout = int(config("KAFKA_SESSION_TIMEOUT_MS", default="45000"))
        self._max_poll_interval = int(config("KAFKA_MAX_POLL_INTERVAL_MS", default="300000"))

        # Security config
        self.security_protocol = config("KAFKA_SECURITY_PROTOCOL", default="PLAINTEXT")
        self.sasl_mechanism = config("KAFKA_SASL_MECHANISM", default="PLAIN")
        self.sasl_plain_username = config("KAFKA_SASL_USERNAME", default=None)
        self.sasl_plain_password = config("KAFKA_SASL_PASSWORD", default=None)

        # SSL config
        self.ssl_cafile = config("KAFKA_SSL_CAFILE", default=None)
        self.ssl_certfile = config("KAFKA_SSL_CERTFILE", default=None)
        self.ssl_keyfile = config("KAFKA_SSL_KEYFILE", default=None)

    def _build_consumer_config(self) -> dict:
        """Build confluent-kafka consumer configuration."""
        conf = {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,  # Manual commit after processing
            "session.timeout.ms": self._session_timeout,
            "max.poll.interval.ms": self._max_poll_interval,
            "security.protocol": self.security_protocol,
        }

        # SASL configuration
        if self.security_protocol in ["SASL_PLAINTEXT", "SASL_SSL"]:
            conf["sasl.mechanism"] = self.sasl_mechanism
            if self.sasl_plain_username:
                conf["sasl.username"] = self.sasl_plain_username
            if self.sasl_plain_password:
                conf["sasl.password"] = self.sasl_plain_password

        # SSL configuration
        if self.security_protocol in ["SSL", "SASL_SSL"]:
            if self.ssl_cafile:
                conf["ssl.ca.location"] = self.ssl_cafile
            if self.ssl_certfile:
                conf["ssl.certificate.location"] = self.ssl_certfile
            if self.ssl_keyfile:
                conf["ssl.key.location"] = self.ssl_keyfile

        return conf

    def _redact_config(self, conf: dict) -> dict:
        """Redact sensitive values from config for logging."""
        redacted = conf.copy()
        for key in ["sasl.password", "ssl.key.password"]:
            if key in redacted:
                redacted[key] = "***REDACTED***"
        return redacted

    def start(self):
        """Start the consumer loop. This is blocking."""
        if self._running:
            self.logger.warning("Consumer already running")
            return

        conf = self._build_consumer_config()
        self.logger.info(f"Starting Kafka Consumer on topic '{self.topic}' with config: {self._redact_config(conf)}")

        self._consumer = Consumer(conf)
        self._consumer.subscribe(
            [self.topic],
            on_assign=self._on_assign,
            on_revoke=self._on_revoke
        )
        self._running = True

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            self._consume_loop()
        finally:
            self._cleanup()

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self._running = False
        self._shutdown_event.set()

    def _on_assign(self, consumer, partitions):
        """Callback when partitions are assigned."""
        self.logger.info(f"Partitions assigned: {[p.partition for p in partitions]}")

    def _on_revoke(self, consumer, partitions):
        """Callback when partitions are revoked (rebalance)."""
        self.logger.info(f"Partitions revoked: {[p.partition for p in partitions]}")
        # Commit any pending offsets before rebalance
        try:
            consumer.commit(asynchronous=False)
        except KafkaException as e:
            self.logger.warning(f"Failed to commit during rebalance: {e}")

    def _consume_loop(self):
        """Main consumption loop - blocking and synchronous."""
        self.logger.info("Entering consume loop...")
        consecutive_errors = 0
        max_consecutive_errors = 10

        while self._running:
            try:
                msg = self._consumer.poll(timeout=self._poll_timeout)

                if msg is None:
                    # No message available, continue polling
                    consecutive_errors = 0
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        # End of partition - not an error
                        self.logger.debug(f"Reached end of partition {msg.partition()}")
                    else:
                        self.logger.error(f"Consumer error: {msg.error()}")
                        consecutive_errors += 1
                        if consecutive_errors >= max_consecutive_errors:
                            raise KafkaException(msg.error())
                    continue

                # Reset error counter on successful poll
                consecutive_errors = 0

                # Process the message
                self._process_message(msg)

                # Commit offset after successful processing
                self._consumer.commit(msg, asynchronous=False)

            except KeyboardInterrupt:
                self.logger.info("KeyboardInterrupt received, shutting down...")
                break
            except KafkaException as e:
                self.logger.exception(f"Kafka exception in consume loop: {e}")
                if not self._running:
                    break
                # Brief backoff before retrying
                self._shutdown_event.wait(timeout=1.0)
            except Exception as e:
                self.logger.exception(f"Unexpected error in consume loop: {e}")
                events_error_counter.inc()
                # Don't crash on individual message errors, continue processing
                continue

        self.logger.info("Exited consume loop")

    def _process_message(self, msg):
        """Process a single Kafka message."""
        events_in_counter.inc()
        payload = None

        try:
            payload = json.loads(msg.value().decode("utf-8"))
            trace_id = payload.get("trace_id", "unknown")
            self.logger.debug(f"Processing message: {trace_id}")

            # Construct DTO
            event_dto = EventDTO(
                tenant_id=payload.get("tenant_id"),
                trace_id=trace_id,
                event=payload.get("event"),
                provider_type=payload.get("provider_type"),
                provider_id=payload.get("provider_id"),
                fingerprint=payload.get("fingerprint"),
                api_key_name=payload.get("api_key_name"),
                provider_name=payload.get("provider_name"),
            )

            # Process with retries and timing
            with processing_time_summary.time():
                self._process_with_retries(event_dto)

            events_out_counter.inc()
            self.logger.debug(f"Successfully processed message: {trace_id}")

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to decode message: {e}")
            events_error_counter.inc()
            # Still allow commit to avoid getting stuck on malformed messages
            # In production, consider sending to DLQ instead
        except Exception as e:
            trace_id = payload.get("trace_id", "unknown") if payload else "unknown"
            self.logger.exception(
                f"Error processing Kafka message (trace_id={trace_id}): {e}"
            )
            events_error_counter.inc()
            # Re-raise to prevent commit - message will be reprocessed
            raise

    def _process_with_retries(self, event_dto: EventDTO):
        """Process event with retry logic."""
        for attempt in range(MAX_PROCESSING_RETRIES):
            try:
                process_event_sync(event_dto)
                return
            except Exception as e:
                self.logger.warning(
                    f"Error processing event (attempt {attempt + 1}/{MAX_PROCESSING_RETRIES}): {e}"
                )
                if attempt == MAX_PROCESSING_RETRIES - 1:
                    raise
                # Exponential backoff, max 10s
                time.sleep(min(2 ** attempt, 10))

    def stop(self):
        """Stop the consumer gracefully."""
        self.logger.info("Stopping Kafka consumer...")
        self._running = False
        self._shutdown_event.set()

    def _cleanup(self):
        """Cleanup resources."""
        if self._consumer:
            self.logger.info("Closing Kafka consumer...")
            try:
                self._consumer.close()
            except Exception as e:
                self.logger.error(f"Error closing consumer: {e}")
            self._consumer = None
        self.logger.info("Kafka consumer stopped")
