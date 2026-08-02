"""
Tests for the consumer-group timing config.

`session.timeout.ms` bounds how long a hard-killed pod's partitions stay
unassigned (no LeaveGroup is sent on SIGKILL), so it is the single
highest-leverage knob against the observed ingestion stall. It is only safe to
lower it if `heartbeat.interval.ms` comes down with it — which previously wasn't
even settable, since the config builder never emitted it.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.core.kafka_consumer import KafkaEventConsumer


_TIMING_ENV = ("KAFKA_SESSION_TIMEOUT_MS", "KAFKA_HEARTBEAT_INTERVAL_MS")


def _config(monkeypatch, **env):
    """Build the consumer config with only the timing env vars this test sets,
    so a developer's exported KAFKA_* can't change the outcome."""
    for key in _TIMING_ENV:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with patch("src.core.kafka_consumer.Consumer", return_value=MagicMock()):
        return KafkaEventConsumer()._build_consumer_config()


@pytest.mark.parametrize("session_timeout", [6000, 30000, 45000, 300000])
def test_heartbeat_is_emitted_and_fits_inside_the_session_window(
    monkeypatch, session_timeout
):
    """The invariant that makes a low session timeout safe: heartbeat.interval.ms
    must leave room for several heartbeats per session window. Before this it
    wasn't even settable — the config builder never emitted it."""
    conf = _config(monkeypatch, KAFKA_SESSION_TIMEOUT_MS=str(session_timeout))

    assert conf["session.timeout.ms"] == session_timeout
    assert conf["heartbeat.interval.ms"] * 3 <= conf["session.timeout.ms"]


def test_heartbeat_defaults_hold_when_the_session_timeout_is_not_set(monkeypatch):
    conf = _config(monkeypatch)
    assert conf["heartbeat.interval.ms"] * 3 <= conf["session.timeout.ms"]


def test_heartbeat_can_be_set_explicitly(monkeypatch):
    conf = _config(
        monkeypatch,
        KAFKA_SESSION_TIMEOUT_MS="30000",
        KAFKA_HEARTBEAT_INTERVAL_MS="5000",
    )
    assert conf["heartbeat.interval.ms"] == 5000
