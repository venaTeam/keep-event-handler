"""Synchronous, acknowledgement-bearing producer for B5 matched messages."""

import json
import logging
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from typing import Any, Protocol

from confluent_kafka import Producer

from src.bl.automations import settings
from src.config.config import config
from src.config.consts import MATCHED_ALERTS_TOPIC, MAX_PROCESSING_RETRIES
from src.core.metrics import (
    automation_matched_producer_ready,
    automation_matched_publish_duration_seconds,
    automation_matched_publish_total,
)

logger = logging.getLogger(__name__)


class MatchedPublishError(RuntimeError):
    """The raw record is unresolved and must not be committed."""


class MatchedContractError(ValueError):
    """An upstream alert cannot be serialized to the matched contract."""


class ProducerClient(Protocol):
    def produce(
        self,
        topic: str,
        *,
        key: bytes,
        value: bytes,
        on_delivery: Callable[[object, object], None],
    ) -> None: ...

    def poll(self, timeout: float) -> int: ...
    def flush(self, timeout: float) -> int: ...
    def list_topics(self, timeout: float) -> Any: ...


class MatchedProducer:
    def __init__(
        self,
        client: ProducerClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float], None] = time.sleep,
    ) -> None:
        self._clock = clock
        self._wait = wait
        self._lock = threading.Lock()
        self._enabled = settings.read_matching_enabled()
        self._healthy = not self._enabled
        self._recovery_pending = False
        logger.info(
            "Matched publishing configuration "
            "(enabled=%s, topic=%s, publish_timeout_seconds=%s, max_attempts=%s)",
            self._enabled, MATCHED_ALERTS_TOPIC,
            settings.read_matched_publish_timeout_seconds(),
            max(1, MAX_PROCESSING_RETRIES),
        )
        self._client = (
            client if client is not None else Producer(self._config())
        ) if self._enabled else None

    @staticmethod
    def _config() -> dict[str, Any]:
        servers = config("MATCHED_KAFKA_BOOTSTRAP_SERVERS", default="localhost:29092")
        try:
            parsed = json.loads(servers)
            servers = ",".join(parsed) if isinstance(parsed, list) else str(parsed)
        except json.JSONDecodeError:
            pass
        result = {
            "bootstrap.servers": servers,
            "security.protocol": config(
                "MATCHED_KAFKA_SECURITY_PROTOCOL", default="PLAINTEXT"
            ),
            "enable.idempotence": True,
            "acks": "all",
            "delivery.timeout.ms": int(
                settings.read_matched_publish_timeout_seconds() * 1000
            ),
        }
        if result["security.protocol"] in ("SASL_PLAINTEXT", "SASL_SSL"):
            result["sasl.mechanism"] = config(
                "MATCHED_KAFKA_SASL_MECHANISM", default="PLAIN"
            )
            result["sasl.username"] = config(
                "MATCHED_KAFKA_SASL_USERNAME", default=None
            )
            result["sasl.password"] = config(
                "MATCHED_KAFKA_SASL_PASSWORD", default=None
            )
        for env, key in (
            ("MATCHED_KAFKA_SSL_CAFILE", "ssl.ca.location"),
            ("MATCHED_KAFKA_SSL_CERTFILE", "ssl.certificate.location"),
            ("MATCHED_KAFKA_SSL_KEYFILE", "ssl.key.location"),
        ):
            value = config(env, default=None)
            if value:
                result[key] = value
        return result

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def healthy(self) -> bool:
        """Last observed state without triggering broker I/O."""
        return self._healthy

    def health(self) -> tuple[bool, str]:
        if not self._enabled:
            return True, "matched publishing disabled"
        if not self._healthy:
            self.start()
        reason = "producer healthy" if self._healthy else "producer unavailable"
        return self._healthy, reason

    def _mark_ready(self) -> None:
        self._healthy = True
        automation_matched_producer_ready.set(1)
        if self._recovery_pending:
            self._recovery_pending = False
            logger.info("Matched producer recovered (topic=%s)", MATCHED_ALERTS_TOPIC)

    @contextmanager
    def _lock_until(self, deadline: float):
        remaining = max(0, deadline - self._clock())
        if not self._lock.acquire(timeout=remaining):
            self._healthy = False
            self._recovery_pending = True
            automation_matched_producer_ready.set(0)
            raise MatchedPublishError("matched producer lock deadline exceeded")
        try:
            if self._clock() >= deadline:
                self._healthy = False
                self._recovery_pending = True
                automation_matched_producer_ready.set(0)
                raise MatchedPublishError("matched producer deadline exceeded")
            yield
        finally:
            self._lock.release()

    def start(self) -> bool:
        """Return True when started or disabled; False only on startup failure."""
        if not self._enabled:
            return True
        deadline = self._clock() + settings.read_matched_publish_timeout_seconds()
        try:
            with self._lock_until(deadline):
                metadata = self._client.list_topics(
                    timeout=max(0, deadline - self._clock())
                )
                topics = getattr(metadata, "topics", None)
                topic = None if topics is None else topics.get(MATCHED_ALERTS_TOPIC)
                topic_error = None if topic is None else getattr(topic, "error", None)
                if topic is None or topic_error is not None:
                    raise MatchedPublishError(
                        f"matched topic metadata unavailable: {MATCHED_ALERTS_TOPIC}"
                    )
            self._mark_ready()
            logger.info("Matched producer ready (topic=%s)", MATCHED_ALERTS_TOPIC)
            return True
        except Exception as error:
            self._healthy = False
            self._recovery_pending = True
            automation_matched_producer_ready.set(0)
            logger.error(
                "Matched producer metadata check failed: %s", type(error).__name__
            )
            return False

    def publish(self, messages: Sequence[Mapping[str, Any]]) -> None:
        if not self._enabled or not messages:
            return
        # Validate the entire alert fan-out before Kafka can accept any part.
        encoded: list[tuple[bytes, bytes]] = []
        try:
            for message in messages:
                automation_id = message["automation_id"]
                if not isinstance(automation_id, str) or not automation_id.strip():
                    raise ValueError("automation_id must be a non-empty string")
                value = json.dumps(
                    message, separators=(",", ":"), allow_nan=False
                ).encode("utf-8")
                encoded.append((automation_id.encode("utf-8"), value))
        except (KeyError, TypeError, ValueError, RecursionError) as error:
            raise MatchedContractError("invalid matched-message payload") from error
        deadline = self._clock() + settings.read_matched_publish_timeout_seconds()
        attempts = max(1, MAX_PROCESSING_RETRIES)
        started = self._clock()
        try:
            for attempt in range(attempts):
                try:
                    self._publish_encoded(encoded, deadline)
                    return
                except MatchedPublishError:
                    remaining = deadline - self._clock()
                    if attempt == attempts - 1 or remaining <= 0:
                        raise
                    logger.debug(
                        "Retrying matched publish "
                        "(topic=%s, next_attempt=%s, max_attempts=%s, "
                        "records=%s, remaining_seconds=%.3f)",
                        MATCHED_ALERTS_TOPIC, attempt + 2, attempts,
                        len(encoded), remaining,
                    )
                    self._wait(min(
                        settings.read_matched_queue_retry_seconds() * (2 ** attempt),
                        remaining,
                    ))
                    if self._clock() >= deadline:
                        raise
        finally:
            automation_matched_publish_duration_seconds.observe(self._clock() - started)

    def _publish_encoded(
        self, encoded: Sequence[tuple[bytes, bytes]], deadline: float
    ) -> None:
        """One delivery attempt; retries reuse bytes without repeating DB work."""
        logger.debug(
            "Publishing matched-message batch (topic=%s, records=%s)",
            MATCHED_ALERTS_TOPIC,
            len(encoded),
        )
        pending = set(range(len(encoded)))
        failures: list[object] = []

        def callback(index: int) -> Callable[[object, object], None]:
            def delivered(error: object, _message: object) -> None:
                pending.discard(index)
                if error is not None:
                    failures.append(error)
            return delivered

        polling_error = None
        with self._lock_until(deadline):
            for index, (key, value) in enumerate(encoded):
                while True:
                    # A queue retry or previous enqueue may have used the budget.
                    # Leave unsent records pending so they cannot count as acknowledged.
                    if self._clock() >= deadline:
                        break
                    try:
                        self._client.produce(
                            MATCHED_ALERTS_TOPIC,
                            key=key,
                            value=value,
                            on_delivery=callback(index),
                        )
                        break
                    except BufferError:
                        if self._clock() >= deadline:
                            failures.append("queue_full")
                            pending.discard(index)
                            break
                        try:
                            self._client.poll(0)
                        except Exception as error:
                            polling_error = error
                            break
                        self._wait(min(
                            settings.read_matched_queue_retry_seconds(),
                            max(0, deadline - self._clock()),
                        ))
                    except Exception as error:
                        failures.append(error)
                        pending.discard(index)
                        break
                if polling_error is not None or self._clock() >= deadline:
                    break

            while pending and polling_error is None and self._clock() < deadline:
                try:
                    self._client.poll(min(0.05, max(0, deadline - self._clock())))
                except Exception as error:
                    polling_error = error

        acknowledged = len(encoded) - len(pending) - len(failures)
        if failures or pending or polling_error is not None:
            automation_matched_publish_total.labels(result="failed").inc(
                len(failures) + len(pending)
            )
            if acknowledged:
                automation_matched_publish_total.labels(
                    result="acknowledged"
                ).inc(acknowledged)
            self._healthy = False
            self._recovery_pending = True
            automation_matched_producer_ready.set(0)
            logger.warning(
                "Matched-message delivery incomplete "
                "(topic=%s, acknowledged=%s, total=%s, failed=%s, pending=%s, "
                "poll_error=%s)",
                MATCHED_ALERTS_TOPIC,
                acknowledged,
                len(encoded),
                len(failures),
                len(pending),
                type(polling_error).__name__ if polling_error is not None else None,
            )
            raise MatchedPublishError(
                f"matched delivery incomplete ({acknowledged}/{len(encoded)} acknowledged)"
            ) from polling_error
        automation_matched_publish_total.labels(result="acknowledged").inc(
            len(encoded)
        )
        self._mark_ready()
        logger.debug(
            "Matched-message batch acknowledged (topic=%s, records=%s)",
            MATCHED_ALERTS_TOPIC,
            len(encoded),
        )

    def stop(self) -> None:
        if not self._enabled:
            return
        remaining = self._client.flush(
            settings.read_matched_shutdown_timeout_seconds()
        )
        if remaining:
            logger.error(
                "Matched producer stopped with %s undelivered records", remaining
            )
        else:
            logger.info("Matched producer stopped cleanly")


_producer = MatchedProducer()


def get_matched_producer() -> MatchedProducer:
    return _producer
