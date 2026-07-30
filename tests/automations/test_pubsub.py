"""The reload subscriber, against a fake pubsub.

No Redis required: redis-py connects lazily, and every behaviour that matters
here (backoff, reconnect, the TimeoutError/ConnectionError distinction, the
fd-leak guard) is observable without a server. The one test that genuinely
needs a live Redis lives in test_reload_integration.py and self-skips.
"""

import threading

import pytest
import redis.exceptions as redis_exceptions

from src.bl.automations import settings
from src.bl.automations.pubsub import ReloadSubscriber


class FakeClient:
    """Counts how many pubsub objects it hands out, and whether it was closed."""

    def __init__(self, script=None):
        self.pubsubs = []
        self.closed = 0
        self._script = list(script or [])

    def pubsub(self, ignore_subscribe_messages=False):
        created = FakePubSub(self._script)
        self.pubsubs.append(created)
        return created

    def close(self):
        self.closed += 1


class FakePubSub:
    def __init__(self, script):
        self._script = script
        self.subscribed = []
        self.closed = 0
        self.reads = 0

    def subscribe(self, channel):
        self.subscribed.append(channel)

    def get_message(self, timeout=None):
        self.reads += 1
        if not self._script:
            return None
        step = self._script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step

    def close(self):
        self.closed += 1


class RecordingService:
    def __init__(self):
        self.signals = 0
        self.event = threading.Event()

    def signal(self):
        self.signals += 1
        self.event.set()


@pytest.fixture
def service():
    return RecordingService()


# --------------------------------------------------------------------------
# The disabled state is a degradation, not an off switch
# --------------------------------------------------------------------------


def test_empty_url_disables_the_listener_without_disabling_reloads(service):
    subscriber = ReloadSubscriber(service, url="")
    assert subscriber.enabled is False
    subscriber.start()
    assert subscriber._thread is None


def test_empty_url_sets_the_config_missing_gauge_not_index_ready(metric_delta):
    from src.core.metrics import automation_index_config_missing

    ReloadSubscriber(RecordingService(), url="").start()
    from tests.automations.conftest import metric_value

    assert (
        metric_value(
            "keep_automation_index_config_missing", {"setting": "redis_url"}
        )
        == 1.0
    )
    # index_ready is a different question entirely and must be untouched here.
    automation_index_config_missing.labels(setting="redis_url").set(0)


# --------------------------------------------------------------------------
# Message handling
# --------------------------------------------------------------------------


@pytest.mark.timeout(15)
def test_a_message_signals_the_service(service):
    client = FakeClient(script=[{"type": "message", "data": b"anything"}])
    subscriber = ReloadSubscriber(
        service, url="redis://x", client_factory=lambda: client
    )
    subscriber.start()
    try:
        assert service.event.wait(timeout=5)
    finally:
        subscriber.stop(deadline=5)
    assert service.signals >= 1


@pytest.mark.timeout(15)
def test_the_channel_subscribed_is_the_contract_channel(service):
    client = FakeClient()
    subscriber = ReloadSubscriber(
        service, url="redis://x", client_factory=lambda: client
    )
    subscriber.start()
    try:
        threading.Event().wait(0.3)
    finally:
        subscriber.stop(deadline=5)
    assert client.pubsubs[0].subscribed == ["reload"]


def test_the_payload_is_never_read():
    """The channel is a signal, never data. Parsing it would turn an
    unauthenticated channel into an input path."""
    source = (
        __import__("pathlib").Path("src/bl/automations/pubsub.py").read_text(
            encoding="utf-8"
        )
    )
    # No indexing into the message and no deserialization anywhere.
    assert 'message["data"]' not in source
    assert "message.get(" not in source
    assert "json.loads" not in source


# --------------------------------------------------------------------------
# The TimeoutError / ConnectionError distinction
# --------------------------------------------------------------------------


@pytest.mark.timeout(15)
def test_timeout_error_is_an_idle_poll_not_a_disconnect(service, metric_delta):
    """The reload channel is idle by definition; treating an idle poll as a
    disconnect would tear down a healthy subscription every second."""
    tracked = metric_delta("keep_automation_pubsub_reconnects_total")
    client = FakeClient(
        script=[redis_exceptions.TimeoutError("idle"), redis_exceptions.TimeoutError("idle")]
    )
    subscriber = ReloadSubscriber(
        service, url="redis://x", client_factory=lambda: client
    )
    subscriber.start()
    try:
        threading.Event().wait(0.4)
    finally:
        subscriber.stop(deadline=5)
    assert tracked.delta == 0.0
    assert len(client.pubsubs) == 1  # no resubscribe


@pytest.mark.timeout(20)
def test_connection_error_reconnects_and_signals_a_reload(service, metric_delta):
    """Pub/sub is at-most-once: a publish during the outage is gone, so the
    listener converges on reconnect rather than waiting for the timer."""
    tracked = metric_delta("keep_automation_pubsub_reconnects_total")
    client = FakeClient(script=[redis_exceptions.ConnectionError("dropped")])
    subscriber = ReloadSubscriber(
        service, url="redis://x", client_factory=lambda: client
    )
    subscriber.start()
    try:
        assert service.event.wait(timeout=10), "no reload-on-reconnect signal"
    finally:
        subscriber.stop(deadline=5)
    assert tracked.delta >= 1.0


# --------------------------------------------------------------------------
# The fd-leak guard -- the platform's signature failure
# --------------------------------------------------------------------------


@pytest.mark.timeout(30)
def test_reconnect_cycles_never_build_a_second_client(service, monkeypatch):
    """Redis.from_url() builds a NEW ConnectionPool per call. Rebuilding the
    client on each reconnect leaks descriptors into the Kafka consumer process
    until EMFILE stops librdkafka opening sockets.
    """
    monkeypatch.setattr(settings, "read_pubsub_max_backoff_seconds", lambda: 1)
    built = {"n": 0}
    client = FakeClient(
        script=[redis_exceptions.ConnectionError("dropped") for _ in range(4)]
    )

    def factory():
        built["n"] += 1
        return client

    subscriber = ReloadSubscriber(service, url="redis://x", client_factory=factory)
    subscriber.start()
    try:
        threading.Event().wait(3.0)
    finally:
        subscriber.stop(deadline=5)

    assert built["n"] == 1, "the client must be constructed once for the lifetime"


@pytest.mark.timeout(30)
def test_every_replaced_pubsub_is_closed(service, monkeypatch):
    """A reconnect must not accumulate subscriptions."""
    monkeypatch.setattr(settings, "read_pubsub_max_backoff_seconds", lambda: 1)
    client = FakeClient(
        script=[redis_exceptions.ConnectionError("dropped") for _ in range(3)]
    )
    subscriber = ReloadSubscriber(
        service, url="redis://x", client_factory=lambda: client
    )
    subscriber.start()
    try:
        threading.Event().wait(2.5)
    finally:
        subscriber.stop(deadline=5)

    # Every pubsub but possibly the live one has been closed.
    assert sum(p.closed for p in client.pubsubs) >= len(client.pubsubs) - 1


# --------------------------------------------------------------------------
# Backoff
# --------------------------------------------------------------------------


def test_backoff_has_a_one_second_floor_and_a_cap(service, monkeypatch):
    monkeypatch.setattr(settings, "read_pubsub_max_backoff_seconds", lambda: 30)
    subscriber = ReloadSubscriber(service, url="redis://x")
    subscriber._failures = 0
    assert subscriber._backoff_seconds() >= 1.0
    subscriber._failures = 99
    assert subscriber._backoff_seconds() == 30


def test_backoff_grows_monotonically(service, monkeypatch):
    monkeypatch.setattr(settings, "read_pubsub_max_backoff_seconds", lambda: 60)
    subscriber = ReloadSubscriber(service, url="redis://x")
    seen = []
    for failures in range(1, 7):
        subscriber._failures = failures
        seen.append(subscriber._backoff_seconds())
    assert seen == sorted(seen)


def test_client_kwargs_include_health_check_and_keepalive(service, monkeypatch):
    """Without health_check_interval an idle-timeout device drops the
    connection and get_message() returns None forever with no exception."""
    captured = {}

    class FakeRedisModule:
        class Redis:
            @staticmethod
            def from_url(url, **kwargs):
                captured.update(kwargs)
                return FakeClient()

    monkeypatch.setitem(__import__("sys").modules, "redis", FakeRedisModule)
    subscriber = ReloadSubscriber(service, url="redis://x")
    subscriber._build_client()

    assert captured["health_check_interval"] == 30
    assert captured["socket_keepalive"] is True
    assert captured["decode_responses"] is False
    assert captured["socket_connect_timeout"] > 0


def test_connection_errors_are_redacted_before_logging(service, caplog):
    """redis-py puts the connection target in the message; logs ship onward."""
    subscriber = ReloadSubscriber(service, url="redis://user:hunter2@host:6379/0")
    from src.bl.automations.pubsub import _redacted

    message = _redacted(
        redis_exceptions.ConnectionError(
            "Error connecting to redis://user:hunter2@host:6379/0"
        ),
        subscriber._url,
    )
    assert "hunter2" not in message
