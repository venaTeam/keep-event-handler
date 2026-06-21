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
from pydantic import ValidationError
from requests.exceptions import HTTPError
from sqlalchemy.exc import OperationalError

from src.config.consts import (
    MAX_PROCESSING_RETRIES,
    KAFKA_RETRY_MAX_SLEEP_SECONDS,
    KAFKA_RETRY_POLL_GAP_SAFETY_FACTOR,
)
from src.config.config import config
from src.core.metrics import (
    events_in_counter,
    events_out_counter,
    events_error_counter,
    processing_time_summary,
)
from src.controllers.event_controller import process_event_sync
from src.event_management.process_event_task import record_terminal_error
from src.models.event_dto import EventDTO


logger = logging.getLogger(__name__)


class PoisonMessageError(Exception):
    """A message that can never succeed on retry (bad payload, unknown type,
    validation failure, or a client/4xx error from the gateway). Routed to the
    terminal sink and committed instead of retried."""


def _gateway_http_status(exc: Exception) -> Optional[int]:
    """Best-effort HTTP status from a requests HTTPError raised by a gateway
    call somewhere in the processing path."""
    if isinstance(exc, HTTPError) and exc.response is not None:
        return exc.response.status_code
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def classify_error(exc: Exception) -> str:
    """Classify a processing error as 'poison' (no retry) or 'transient'
    (bounded retry).

    poison: json.JSONDecodeError, unknown event_type, Pydantic ValidationError,
            gateway HTTP 4xx.
    transient: DB OperationalError / lock, gateway 5xx / timeout, everything
            else (default to transient so a genuinely retryable bug still
            gets its bounded retries rather than being dropped).
    """
    if isinstance(exc, (PoisonMessageError, json.JSONDecodeError, ValidationError)):
        return "poison"

    status = _gateway_http_status(exc)
    if status is not None:
        if 400 <= status < 500:
            return "poison"
        # 5xx (and anything else non-4xx) is transient.
        return "transient"

    # DB operational/lock errors are transient by construction.
    if isinstance(exc, OperationalError):
        return "transient"

    # Unknown errors: default to transient (bounded retry), not poison —
    # a real transient bug shouldn't be silently dropped on first failure.
    return "transient"


class RetryBudget:
    """Batch-wide retry budget. Aborts remaining retries once the time elapsed
    since the last poll approaches max.poll.interval.ms (scaled by the safety
    factor), so accumulated retry sleep can never trigger a consumer-group
    rebalance. Per-attempt sleep is capped by KAFKA_RETRY_MAX_SLEEP_SECONDS."""

    def __init__(
        self,
        max_poll_interval_ms: int,
        safety_factor: float = KAFKA_RETRY_POLL_GAP_SAFETY_FACTOR,
        max_sleep_seconds: int = KAFKA_RETRY_MAX_SLEEP_SECONDS,
        clock=time.monotonic,
    ):
        self._budget_seconds = (max_poll_interval_ms / 1000.0) * safety_factor
        self._max_sleep_seconds = max_sleep_seconds
        self._clock = clock
        self._started_at = clock()

    def reset(self):
        """Call right after a successful poll: the budget is measured from the
        most recent poll so the whole batch shares one deadline."""
        self._started_at = self._clock()

    def elapsed(self) -> float:
        return self._clock() - self._started_at

    def remaining(self) -> float:
        return self._budget_seconds - self.elapsed()

    def exhausted(self) -> bool:
        return self.remaining() <= 0

    def sleep_for(self, attempt: int) -> float:
        """Bounded backoff for this attempt, never overrunning the remaining
        budget. Returns the seconds slept."""
        backoff = min(2 ** attempt, self._max_sleep_seconds)
        # Never sleep past the budget deadline.
        backoff = max(0.0, min(backoff, self.remaining()))
        if backoff > 0:
            time.sleep(backoff)
        return backoff


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
            "KAFKA_BOOTSTRAP_SERVERS", default="localhost:29092"
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

                # Fresh retry budget per poll (batch-wide once batching lands).
                budget = RetryBudget(self._max_poll_interval)

                # Process the message; terminal handling (poison / retry
                # exhausted) records + signals commit so a bad message can't
                # freeze the partition forever.
                should_commit = self._process_message(msg, budget)

                if should_commit:
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

    def _process_message(self, msg, budget: "RetryBudget") -> bool:
        """Process a single Kafka message.

        Returns True if the offset should be committed (success, poison, or
        retry-exhausted — all terminal), False only when the message is
        genuinely unresolved and should be redelivered (e.g. an unexpected
        error in terminal handling itself).
        """
        events_in_counter.inc()
        payload = None

        # Decode the raw payload. A non-JSON message is poison and committed
        # (we keep the raw bytes for the terminal record).
        raw_text = None
        try:
            raw_text = msg.value().decode("utf-8")
            payload = json.loads(raw_text)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to decode message (poison): {e}")
            events_error_counter.inc()
            self._record_terminal(
                payload={"raw": raw_text} if raw_text is not None else None,
                error=e,
            )
            return True  # commit past the malformed message

        trace_id = payload.get("trace_id", "unknown")
        self.logger.debug(f"Processing message: {trace_id}")

        try:
            # Construct DTO. A bad shape raises pydantic ValidationError =
            # poison.
            try:
                event_dto = EventDTO(
                    tenant_id=payload.get("tenant_id"),
                    trace_id=trace_id,
                    event=payload.get("event"),
                    provider_type=payload.get("provider_type"),
                    provider_id=payload.get("provider_id"),
                    fingerprint=payload.get("fingerprint"),
                    api_key_name=payload.get("api_key_name"),
                    provider_name=payload.get("provider_name"),
                    event_type=payload.get("event_type"),
                )
            except ValidationError as e:
                self.logger.error(
                    f"Invalid event payload (poison, trace_id={trace_id}): {e}"
                )
                events_error_counter.inc()
                self._record_terminal(payload=payload, error=e)
                return True

            # Process with bounded, batch-wide retries and timing.
            with processing_time_summary.time():
                self._process_with_retries(event_dto, budget, payload)

            events_out_counter.inc()
            self.logger.debug(f"Successfully processed message: {trace_id}")
            return True

        except Exception as e:
            # Should not normally reach here — _process_with_retries handles
            # its own terminal recording. Be defensive: record + commit rather
            # than freeze the partition.
            self.logger.exception(
                f"Unexpected error processing message (trace_id={trace_id}): {e}"
            )
            events_error_counter.inc()
            try:
                self._record_terminal(payload=payload, error=e)
            except Exception:
                self.logger.exception("Terminal recording failed; not committing")
                return False
            return True

    def _process_with_retries(
        self, event_dto: EventDTO, budget: "RetryBudget", payload: dict
    ):
        """Process an event with bounded, batch-wide retry.

        A poison error is never retried. A transient error retries up to
        MAX_PROCESSING_RETRIES, with each attempt's backoff bounded by both
        KAFKA_RETRY_MAX_SLEEP_SECONDS and the remaining batch-wide budget. When
        retries are exhausted (attempt cap, classified poison, or budget
        exhaustion), the message is recorded via the storm-guarded error sink
        (terminal) and NOT re-raised, so its offset can be committed.
        """
        for attempt in range(MAX_PROCESSING_RETRIES):
            try:
                process_event_sync(event_dto)
                return
            except Exception as e:
                kind = classify_error(e)
                self.logger.warning(
                    f"Error processing event "
                    f"(attempt {attempt + 1}/{MAX_PROCESSING_RETRIES}, "
                    f"class={kind}): {e}"
                )

                if kind == "poison":
                    self.logger.error(
                        "Poison message — recording and committing (no retry)"
                    )
                    self._record_terminal(payload=payload, error=e)
                    return

                # transient
                if attempt == MAX_PROCESSING_RETRIES - 1:
                    self.logger.error(
                        "Retries exhausted (attempt cap) — recording and committing"
                    )
                    self._record_terminal(payload=payload, error=e)
                    return

                if budget.exhausted():
                    self.logger.error(
                        "Retry budget exhausted (poll-interval guard) — "
                        "recording and committing"
                    )
                    self._record_terminal(payload=payload, error=e)
                    return

                budget.sleep_for(attempt)

    def _record_terminal(self, payload, error: Exception):
        """Terminal sink for a poison / retry-exhausted message: persist the
        raw payload via the storm-guarded AlertRaw(error=True) path so the
        partition can advance. Best-effort: never raises into the consume loop."""
        tenant_id = payload.get("tenant_id") if isinstance(payload, dict) else None
        provider_type = (
            payload.get("provider_type") if isinstance(payload, dict) else None
        )
        try:
            record_terminal_error(
                tenant_id=tenant_id,
                provider_type=provider_type,
                raw_event=payload,
                error_message=f"{type(error).__name__}: {error}",
            )
        except Exception:
            self.logger.exception("Failed to record terminal error for poison message")

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
