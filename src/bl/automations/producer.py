"""Synchronous, acknowledgement-bearing producer for B5 matched messages."""

import json
import logging
import threading
import time

from confluent_kafka import Producer

from src.bl.automations import settings
from src.config.config import config
from src.config.consts import MATCHED_ALERTS_TOPIC
from src.core.metrics import (
    automation_matched_producer_ready,
    automation_matched_publish_duration_seconds,
    automation_matched_publish_total,
)

logger = logging.getLogger(__name__)


class MatchedPublishError(RuntimeError):
    """The raw record is unresolved and must not be committed."""


class MatchedProducer:
    def __init__(self, client=None, clock=time.monotonic, wait=time.sleep):
        self._clock = clock
        self._wait = wait
        self._lock = threading.Lock()
        self._enabled = settings.read_matched_publish_enabled()
        self._healthy = not self._enabled
        self._client = client or (Producer(self._config()) if self._enabled else None)

    @staticmethod
    def _config():
        servers = config("KAFKA_BOOTSTRAP_SERVERS", default="localhost:29092")
        try:
            parsed = json.loads(servers)
            servers = ",".join(parsed) if isinstance(parsed, list) else str(parsed)
        except json.JSONDecodeError:
            pass
        result = {
            "bootstrap.servers": servers,
            "security.protocol": config("KAFKA_SECURITY_PROTOCOL", default="PLAINTEXT"),
            "enable.idempotence": True,
            "acks": "all",
        }
        if result["security.protocol"] in ("SASL_PLAINTEXT", "SASL_SSL"):
            result["sasl.mechanism"] = config("KAFKA_SASL_MECHANISM", default="PLAIN")
            result["sasl.username"] = config("KAFKA_SASL_USERNAME", default=None)
            result["sasl.password"] = config("KAFKA_SASL_PASSWORD", default=None)
        for env, key in (("KAFKA_SSL_CAFILE", "ssl.ca.location"),
                         ("KAFKA_SSL_CERTFILE", "ssl.certificate.location"),
                         ("KAFKA_SSL_KEYFILE", "ssl.key.location")):
            value = config(env, default=None)
            if value:
                result[key] = value
        return result

    @property
    def enabled(self):
        return self._enabled

    def health(self):
        if not self._enabled:
            return True, "matched publishing disabled"
        return self._healthy, "producer healthy" if self._healthy else "producer unavailable"

    def start(self):
        if not self._enabled:
            return False
        try:
            self._client.list_topics(timeout=settings.read_matched_publish_timeout_seconds())
            self._healthy = True
            automation_matched_producer_ready.set(1)
            return True
        except Exception as error:
            self._healthy = False
            automation_matched_producer_ready.set(0)
            logger.error("Matched producer metadata check failed: %s", type(error).__name__)
            return False

    def publish(self, messages):
        if not self._enabled or not messages:
            return
        deadline = self._clock() + settings.read_matched_publish_timeout_seconds()
        pending = set(range(len(messages)))
        failures = []

        def callback(index):
            def delivered(error, _message):
                pending.discard(index)
                if error is not None:
                    failures.append(error)
            return delivered

        started = self._clock()
        with self._lock:
            for index, message in enumerate(messages):
                value = json.dumps(message, separators=(",", ":"), default=str).encode()
                while True:
                    try:
                        self._client.produce(
                            MATCHED_ALERTS_TOPIC,
                            key=message["automation_id"].encode(),
                            value=value,
                            on_delivery=callback(index),
                        )
                        break
                    except BufferError:
                        if self._clock() >= deadline:
                            failures.append("queue_full")
                            pending.discard(index)
                            break
                        self._client.poll(0)
                        self._wait(settings.read_matched_queue_retry_seconds())

            while pending and self._clock() < deadline:
                self._client.poll(min(0.05, max(0, deadline - self._clock())))

        automation_matched_publish_duration_seconds.observe(self._clock() - started)
        acknowledged = len(messages) - len(pending) - len(failures)
        if failures or pending:
            automation_matched_publish_total.labels(result="failed").inc(
                len(failures) + len(pending)
            )
            if acknowledged:
                automation_matched_publish_total.labels(result="acknowledged").inc(acknowledged)
            self._healthy = False
            automation_matched_producer_ready.set(0)
            raise MatchedPublishError(
                f"matched delivery incomplete ({acknowledged}/{len(messages)} acknowledged)"
            )
        automation_matched_publish_total.labels(result="acknowledged").inc(len(messages))
        self._healthy = True
        automation_matched_producer_ready.set(1)

    def stop(self):
        if self._client is not None:
            remaining = self._client.flush(settings.read_matched_shutdown_timeout_seconds())
            if remaining:
                logger.error("Matched producer stopped with %s undelivered records", remaining)


_producer = MatchedProducer()


def get_matched_producer():
    return _producer
