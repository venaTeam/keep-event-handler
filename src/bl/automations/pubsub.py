"""Subscribes to the automations `reload` channel.

The channel is a **signal, never data** (automation-contracts.md). This listener
therefore never reads a message payload -- it only ever calls
`service.signal()`. That is deliberate and load-bearing: the channel is
unauthenticated, so if a payload were ever parsed here it would become an
untrusted-input path into the alert-ingestion process.

Two things here are not tuning, they are correctness:

**One client for the process lifetime.** `Redis.from_url()` constructs a NEW
`ConnectionPool` every call. Rebuilding the client on each reconnect leaks file
descriptors into the Kafka consumer process -- at the backoff cap that is
~2880/day -- until EMFILE stops librdkafka opening sockets and ingestion dies.
This is the platform's signature failure: the watcher leaked one pooled
connection per 60s tick and died in ~15 minutes. So: construct once, reconnect
by re-subscribing on the same client.

**`health_check_interval` and `socket_keepalive`.** The `reload` channel is idle
by definition, and redis-py does not PING unless `health_check_interval` is set.
Any idle-timeout device between here and Redis (NLB 350s, ELB 60s, most
corporate NATs) silently drops the connection; `get_message()` then returns None
forever with no exception, and a `pubsub_connected` derived from socket state
would keep reporting 1. So liveness is derived from the last message or the last
successful health check, never from the socket.
"""

import logging
import threading
import time

from src.bl.automations import settings
from src.config.consts import AUTOMATION_RELOAD_CHANNEL, REDIS_URL
from src.core.metrics import (
    automation_index_config_missing,
    automation_pubsub_connected,
    automation_pubsub_reconnects_total,
)

logger = logging.getLogger(__name__)

# How long without a message or a successful health check before the listener
# is reported as not connected.
_LIVENESS_GRACE_MULTIPLIER = 3
_HEALTH_CHECK_INTERVAL_SECONDS = 30
# Bounded so shutdown never waits on a full poll, and so the loop is not a spin.
_POLL_TIMEOUT_SECONDS = 1.0


class ReloadSubscriber:
    """Turns `reload` publishes into `service.signal()` calls."""

    def __init__(self, service, url: str | None = None, client_factory=None):
        self._service = service
        self._url = REDIS_URL if url is None else url
        self._client_factory = client_factory
        self._client = None
        self._pubsub = None
        self._stop = threading.Event()
        self._thread = None
        self._failures = 0
        self._last_alive = 0.0

    @property
    def enabled(self) -> bool:
        """Empty REDIS_URL is a quiet degradation, not an off switch.

        The reload worker still runs on its timer; only sub-second convergence
        is lost, so the staleness bound stays at its worst case. This is
        reported as its own gauge precisely so it is never confused with
        `index_ready == 0`, which means matching is doing nothing at all.
        """
        return bool(self._url)

    def start(self) -> None:
        if not self.enabled:
            automation_index_config_missing.labels(setting="redis_url").set(1)
            automation_pubsub_connected.set(0)
            logger.info(
                "automations: REDIS_URL unset -- the reload subscriber is disabled. "
                "The index still reloads every %ss; sub-second convergence is off.",
                settings.read_reload_seconds(),
            )
            return
        automation_index_config_missing.labels(setting="redis_url").set(0)
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="automation-index-pubsub", daemon=True
        )
        self._thread.start()

    def stop(self, deadline: float | None = None) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=deadline)
            self._thread = None
        self._close()
        automation_pubsub_connected.set(0)

    # -- internals ---------------------------------------------------------

    def _build_client(self):
        if self._client_factory is not None:
            return self._client_factory()
        import redis

        return redis.Redis.from_url(
            self._url,
            health_check_interval=_HEALTH_CHECK_INTERVAL_SECONDS,
            socket_keepalive=True,
            socket_connect_timeout=5,
            socket_timeout=_POLL_TIMEOUT_SECONDS + 5,
            # The payload is never read; decoding it would be pure waste and an
            # invitation to start parsing an unauthenticated channel.
            decode_responses=False,
        )

    def _close(self) -> None:
        for closeable in (self._pubsub, self._client):
            if closeable is None:
                continue
            try:
                closeable.close()
            except Exception:  # noqa: BLE001 - closing must never raise onward
                logger.debug("automations: error closing a redis handle", exc_info=True)
        self._pubsub = None

    def _subscribe(self) -> None:
        """Reconnect by re-subscribing on the EXISTING client.

        The client is built at most once. If a pubsub object already exists it
        is closed before being replaced, so a reconnect cannot accumulate
        subscriptions or sockets.
        """
        if self._client is None:
            self._client = self._build_client()
        if self._pubsub is not None:
            try:
                self._pubsub.close()
            except Exception:  # noqa: BLE001
                logger.debug("automations: error closing pubsub", exc_info=True)
            self._pubsub = None
        self._pubsub = self._client.pubsub(ignore_subscribe_messages=True)
        self._pubsub.subscribe(AUTOMATION_RELOAD_CHANNEL)
        self._mark_alive()

    def _mark_alive(self) -> None:
        self._last_alive = time.time()
        self._failures = 0
        automation_pubsub_connected.set(1)

    def _refresh_liveness(self) -> None:
        """Liveness from evidence, not from socket state."""
        grace = _HEALTH_CHECK_INTERVAL_SECONDS * _LIVENESS_GRACE_MULTIPLIER
        if time.time() - self._last_alive > grace:
            automation_pubsub_connected.set(0)

    def _backoff_seconds(self) -> float:
        # Floor of 1s: this also guards a non-connection error loop, and
        # anything faster is a hot spin stealing GIL from the consumer thread.
        cap = settings.read_pubsub_max_backoff_seconds()
        return min(cap, max(1.0, 2 ** min(self._failures, 8)))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._pubsub is None:
                    self._subscribe()

                message = self._pubsub.get_message(timeout=_POLL_TIMEOUT_SECONDS)
                if message is not None:
                    # The payload is deliberately not read.
                    self._mark_alive()
                    self._service.signal()
                    logger.debug("automations: reload signal received")
                else:
                    self._refresh_liveness()
            except Exception as error:  # noqa: BLE001
                if _is_idle_timeout(error):
                    # An idle poll, not a disconnect. Treating it as one would
                    # tear down a healthy subscription every poll.
                    self._refresh_liveness()
                    continue
                self._failures += 1
                automation_pubsub_reconnects_total.inc()
                automation_pubsub_connected.set(0)
                delay = self._backoff_seconds()
                if self._failures <= 3:
                    logger.error(
                        "automations: reload subscriber lost (%s); retrying in %ss",
                        _redacted(error, self._url),
                        delay,
                    )
                else:
                    logger.debug(
                        "automations: reload subscriber still down (%s)",
                        _redacted(error, self._url),
                    )
                self._close()
                # stop_event.wait, never time.sleep -- otherwise shutdown stalls
                # for the whole backoff.
                self._stop.wait(delay)
                if not self._stop.is_set():
                    try:
                        self._subscribe()
                        # Reload-on-reconnect: a publish during the outage is
                        # gone (pub/sub is at-most-once), so converge now rather
                        # than waiting for the timer.
                        self._service.signal()
                    except Exception:  # noqa: BLE001
                        # Next iteration retries with a longer backoff.
                        pass
        automation_pubsub_connected.set(0)


def _is_idle_timeout(error: Exception) -> bool:
    try:
        import redis.exceptions as redis_exceptions
    except Exception:  # pragma: no cover - redis is a hard dependency
        return False
    # TimeoutError is an idle poll returning nothing; ConnectionError is a real
    # disconnect. Conflating them tears down a healthy subscription.
    return isinstance(error, redis_exceptions.TimeoutError) and not isinstance(
        error, redis_exceptions.ConnectionError
    )


def _redacted(error: Exception, url: str) -> str:
    """redis-py routinely puts the connection target in the message."""
    return settings.redact_url(str(error)) if url else str(error)
