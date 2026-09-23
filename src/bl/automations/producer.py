"""Synchronous, acknowledgement-bearing producer for B5 matched messages."""

import json
import logging
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Protocol

from confluent_kafka import Producer, KafkaError, KafkaException

from src.bl.automations import settings
from src.config.config import config
from src.config.consts import MATCHED_ALERTS_TOPIC, MAX_PROCESSING_RETRIES
from src.core.metrics import (
    automation_matched_dlq_total,
    automation_matched_dlq_ready,
    automation_matched_producer_ready,
    automation_matched_publish_duration_seconds,
    automation_matched_publish_total,
)

logger = logging.getLogger(__name__)
delivery_budget = ContextVar('matched_delivery_budget', default=None)
delivery_context = ContextVar('matched_delivery_context', default={})


def bounded_deadline(clock):
    budget = delivery_budget.get()
    remaining = settings.read_matched_publish_timeout_seconds()
    if budget is not None:
        remaining = min(remaining, max(0, budget.remaining()))
    return clock() + remaining


def error_detail(error):
    """Expose Kafka's fixed error name/code, never arbitrary exception text."""
    if isinstance(error, KafkaException) and error.args:
        error = error.args[0]
    if isinstance(error, KafkaError):
        return {'class': 'KafkaError', 'code': error.code(), 'reason': error.name()}
    return {'class': type(error).__name__, 'reason': 'delivery_failed'}


def permanent_error(error):
    if isinstance(error, KafkaException) and error.args:
        error = error.args[0]
    return isinstance(error, KafkaError) and not error.retriable()


class MatchedPublishError(RuntimeError):
    """The raw record is unresolved and must not be committed."""

    unresolved = None
    permanent = False


class MatchedLockTimeout(MatchedPublishError):
    """Local lock wait exhausted the deadline; broker health is unknown."""


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
        headers: list[tuple[str, bytes]] | None = None,
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
        dlq_client: ProducerClient | None = None,
    ) -> None:
        self._clock = clock
        self._wait = wait
        self._lock = threading.Lock()
        self._enabled = settings.read_matching_enabled()
        self._healthy = not self._enabled
        self._recovery_pending = False
        self._delivery_failed = False
        self._last_error = None
        self._last_check = float('-inf')
        self._dlq_client = dlq_client
        self._dlq_lock = threading.Lock()
        self._dlq_healthy = not self._enabled
        self._dlq_error = None
        self._dlq_delivery_failed = False
        self._last_result = None
        self._last_failure_at = None
        self._dlq_topic = config('MATCHED_KAFKA_DLQ_TOPIC', default='matched-alerts-dlq')
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
    def _config(dlq=False) -> dict[str, Any]:
        def read(name, default=None):
            inherited = config('MATCHED_KAFKA_' + name, default=default)
            return config('MATCHED_KAFKA_DLQ_' + name, default=inherited) if dlq else inherited
        servers = read('BOOTSTRAP_SERVERS', 'localhost:29092')
        try:
            parsed = json.loads(servers)
            servers = ",".join(parsed) if isinstance(parsed, list) else str(parsed)
        except json.JSONDecodeError:
            pass
        result = {
            "bootstrap.servers": servers,
            "security.protocol": read('SECURITY_PROTOCOL', 'PLAINTEXT'),
            "enable.idempotence": True,
            "acks": "all",
            "delivery.timeout.ms": int(
                settings.read_matched_publish_timeout_seconds() * 1000
            ),
        }
        if result["security.protocol"] in ("SASL_PLAINTEXT", "SASL_SSL"):
            result['sasl.mechanism'] = read('SASL_MECHANISM', 'PLAIN')
            result['sasl.username'] = read('SASL_USERNAME')
            result['sasl.password'] = read('SASL_PASSWORD')
        for env, key in (
            ("MATCHED_KAFKA_SSL_CAFILE", "ssl.ca.location"),
            ("MATCHED_KAFKA_SSL_CERTFILE", "ssl.certificate.location"),
            ("MATCHED_KAFKA_SSL_KEYFILE", "ssl.key.location"),
        ):
            value = read(env.removeprefix('MATCHED_KAFKA_'))
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
        if self._clock() - self._last_check >= 30 and (not self._healthy or not self._dlq_healthy):
            self.start()
        ok = self._healthy and self._dlq_healthy
        return ok, json.dumps(self.health_details())

    def health_details(self):
        return {'enabled': self._enabled, 'matched': {'topic': MATCHED_ALERTS_TOPIC,
                'healthy': self._healthy, 'last_error': self._last_error},
                'last_failure_at': self._last_failure_at,
                'dlq': {'topic': self._dlq_topic, 'healthy': self._dlq_healthy,
                        'last_error': self._dlq_error}, 'last_result': self._last_result}

    def _mark_ready(self) -> None:
        self._healthy = True
        self._delivery_failed = False
        self._last_error = None
        automation_matched_producer_ready.set(1)
        if self._recovery_pending:
            self._recovery_pending = False
            logger.info("Matched producer recovered (topic=%s)", MATCHED_ALERTS_TOPIC)

    @contextmanager
    def _lock_until(self, deadline: float):
        remaining = max(0, deadline - self._clock())
        if not self._lock.acquire(timeout=remaining):
            raise MatchedLockTimeout("matched producer lock deadline exceeded")
        try:
            if self._clock() >= deadline:
                raise MatchedLockTimeout("matched producer deadline exceeded before broker I/O")
            yield
        finally:
            self._lock.release()

    def start(self) -> bool:
        """Return True when started or disabled; False only on startup failure."""
        if not self._enabled:
            return True
        self._last_check = self._clock()
        self._check_dlq()
        deadline = bounded_deadline(self._clock)
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
            if not self._delivery_failed:
                self._mark_ready()
            logger.debug("Matched topic metadata available (topic=%s)", MATCHED_ALERTS_TOPIC)
            return True
        except MatchedLockTimeout:
            logger.debug("Matched producer metadata check skipped: local lock deadline exceeded")
            return False
        except Exception as error:
            self._last_error = type(error).__name__ + ': topic metadata unavailable'
            self._healthy = False
            self._recovery_pending = True
            automation_matched_producer_ready.set(0)
            logger.error(
                "Matched producer metadata check failed: %s", type(error).__name__
            )
            return False

    def publish(self, messages: Sequence[Mapping[str, Any]]) -> str | None:
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
        deadline = bounded_deadline(self._clock)
        attempts = max(1, MAX_PROCESSING_RETRIES)
        started = self._clock()
        try:
            for attempt in range(attempts):
                try:
                    self._publish_encoded(encoded, deadline)
                    self._last_result = 'matched'
                    return 'matched'
                except MatchedPublishError as error:
                    if error.unresolved is not None:
                        encoded = error.unresolved
                    remaining = deadline - self._clock()
                    if error.permanent or attempt == attempts - 1 or remaining <= 0:
                        return self._send_dlq(encoded, error)
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
                        return self._send_dlq(encoded, error)
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
        acknowledged_indices = set()
        failures: list[object] = []

        def callback(index: int) -> Callable[[object, object], None]:
            def delivered(error: object, _message: object) -> None:
                pending.discard(index)
                if error is not None:
                    failures.append(error)
                else:
                    acknowledged_indices.add(index)
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
            self._delivery_failed = True
            self._last_failure_at = time.time()
            self._last_error = error_detail(polling_error or (failures[0] if failures else None))
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
            error = MatchedPublishError(
                f"matched delivery incomplete ({acknowledged}/{len(encoded)} acknowledged)"
            )
            error.unresolved = [record for i, record in enumerate(encoded) if i not in acknowledged_indices]
            error.permanent = any(permanent_error(failure) for failure in failures)
            raise error from polling_error
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
        deadline = self._clock() + settings.read_matched_shutdown_timeout_seconds()
        for destination, client in (("matched", self._client), ("dlq", self._dlq_client)):
            if client is None:
                continue
            try:
                remaining = client.flush(max(0, deadline - self._clock()))
                if remaining:
                    logger.error("Producer shutdown: destination=%s undelivered=%s", destination, remaining)
            except Exception as error:
                logger.error("Producer shutdown failed: destination=%s error=%s", destination, type(error).__name__)

    def _get_dlq(self):
        if self._dlq_client is None:
            self._dlq_client = Producer(self._config(dlq=True))
        return self._dlq_client

    def _check_dlq(self):
        if not self._dlq_lock.acquire(blocking=False):
            return
        try:
            metadata = self._get_dlq().list_topics(timeout=settings.read_matched_publish_timeout_seconds())
            topic = getattr(metadata, 'topics', {}).get(self._dlq_topic)
            if topic is None or getattr(topic, 'error', None):
                raise MatchedPublishError('DLQ metadata unavailable')
            # Metadata cannot clear an earlier delivery failure.
            if not self._dlq_delivery_failed:
                self._dlq_healthy = True
                self._dlq_error = None
        except Exception as error:
            self._dlq_healthy = False
            self._dlq_error = type(error).__name__ + ': DLQ metadata unavailable'
        finally:
            automation_matched_dlq_ready.set(int(self._dlq_healthy))
            self._dlq_lock.release()

    def _send_dlq(self, encoded, cause, record_type='delivery'):
        deadline = bounded_deadline(self._clock)
        if not self._dlq_lock.acquire(timeout=max(0, deadline - self._clock())):
            raise MatchedPublishError('matched DLQ lock timeout; raw offset unresolved') from cause
        try:
            client = self._get_dlq()
            pending = set(range(len(encoded)))
            failed = {}
            def callback(index):
                def delivered(error, message):
                    pending.discard(index)
                    if error is not None:
                        failed[index] = error_detail(error)
                return delivered
            headers = [('matched-dlq-version', b'1'), ('record-type', record_type.encode()),
                       ('original-topic', MATCHED_ALERTS_TOPIC.encode()),
                       ('error-class', type(cause).__name__.encode()),
                       ('error-detail', json.dumps(self._last_error).encode())]
            headers.extend((name, str(value)[:256].encode())
                           for name, value in delivery_context.get().items())
            for i, (key, value) in enumerate(encoded):
                while self._clock() < deadline:
                    try:
                        client.produce(self._dlq_topic, key=key, value=value,
                                       headers=headers, on_delivery=callback(i))
                        break
                    except BufferError:
                        client.poll(0)
                        self._wait(min(settings.read_matched_queue_retry_seconds(),
                                       max(0, deadline - self._clock())))
            while pending and self._clock() < deadline:
                client.poll(min(0.05, max(0, deadline - self._clock())))
            if pending or failed:
                error = MatchedPublishError('DLQ acknowledgement missing')
                error.detail = next(iter(failed.values()), {'reason': 'acknowledgement_timeout'})
                raise error
            self._dlq_healthy = True
            self._dlq_delivery_failed = False
            self._dlq_error = None
            self._last_result = 'dlq'
            automation_matched_dlq_total.labels(result='acknowledged', kind=record_type).inc(len(encoded))
            logger.warning('Matched messages parked in DLQ: topic=%s records=%s kind=%s; '
                           'this fan-out resolved, automation execution pending recovery',
                           self._dlq_topic, len(encoded), record_type,
                           extra=delivery_context.get())
            return 'dlq'
        except Exception as error:
            self._dlq_healthy = False
            self._dlq_delivery_failed = True
            self._dlq_error = getattr(error, 'detail', error_detail(error))
            self._last_result = 'unresolved'
            automation_matched_dlq_total.labels(result='failed', kind=record_type).inc(len(encoded))
            logger.error('Matched DLQ failed: topic=%s error=%s; raw offset unresolved',
                         self._dlq_topic, type(error).__name__, extra=delivery_context.get())
            raise MatchedPublishError(str(cause) + '; DLQ delivery failed; raw offset unresolved') from error
        finally:
            automation_matched_dlq_ready.set(int(self._dlq_healthy))
            self._dlq_lock.release()

    def reject(self, tenant_id, alert, matches, error):
        from src.bl.automations.rejection import rejection_payload
        try:
            value = rejection_payload(tenant_id, alert, matches, error)
            if len(value) > 65536:
                raise ValueError('rejection identity exceeds diagnostic limit')
        except Exception as encoding_error:
            raise MatchedPublishError('Cannot encode contract rejection; raw offset unresolved') from encoding_error
        return self._send_dlq([(tenant_id.encode(), value)], error, 'contract_rejection')


_producer = MatchedProducer()


def get_matched_producer() -> MatchedProducer:
    return _producer
