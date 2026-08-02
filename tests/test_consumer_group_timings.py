"""
Tests for the consumer-group timing config.

`session.timeout.ms` bounds how long a hard-killed pod's partitions stay
unassigned (no LeaveGroup is sent on SIGKILL), so it is the single
highest-leverage knob against the observed ingestion stall. It is only safe to
lower it if `heartbeat.interval.ms` comes down with it — which previously wasn't
even settable, since the config builder never emitted it.
"""

from unittest.mock import MagicMock, patch

from src.core.kafka_consumer import KafkaEventConsumer


def _consumer(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with patch("src.core.kafka_consumer.Consumer", return_value=MagicMock()):
        return KafkaEventConsumer()


def test_heartbeat_is_emitted_and_fits_inside_the_session_window(monkeypatch):
    consumer = _consumer(monkeypatch, KAFKA_SESSION_TIMEOUT_MS="45000")
    conf = consumer._build_consumer_config()

    assert conf["session.timeout.ms"] == 45000
    assert "heartbeat.interval.ms" in conf
    # The broker needs several heartbeats per session window.
    assert conf["heartbeat.interval.ms"] * 3 <= conf["session.timeout.ms"]


def test_heartbeat_scales_down_with_a_low_session_timeout(monkeypatch):
    consumer = _consumer(monkeypatch, KAFKA_SESSION_TIMEOUT_MS="6000")
    conf = consumer._build_consumer_config()

    assert conf["session.timeout.ms"] == 6000
    assert conf["heartbeat.interval.ms"] == 2000


def test_heartbeat_can_be_set_explicitly(monkeypatch):
    consumer = _consumer(
        monkeypatch,
        KAFKA_SESSION_TIMEOUT_MS="30000",
        KAFKA_HEARTBEAT_INTERVAL_MS="5000",
    )
    assert consumer._build_consumer_config()["heartbeat.interval.ms"] == 5000


def test_session_timeout_default_is_not_the_ten_minute_prod_value(monkeypatch):
    monkeypatch.delenv("KAFKA_SESSION_TIMEOUT_MS", raising=False)
    consumer = _consumer(monkeypatch)
    assert consumer._build_consumer_config()["session.timeout.ms"] == 45000
