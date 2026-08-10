"""Consumer config: the heartbeat is actually emitted, and it tracks the
session timeout it is supposed to match.
"""
from unittest.mock import MagicMock, patch

import pytest


def build_config(env: dict):
    with patch.dict("os.environ", env, clear=False):
        with patch("src.core.kafka_consumer.Consumer", return_value=MagicMock()):
            from src.core.kafka_consumer import KafkaEventConsumer

            return KafkaEventConsumer()._build_consumer_config()


def test_heartbeat_is_emitted():
    """It used to be read from the env and dropped, so lowering the session
    timeout 'with a matching heartbeat' was impossible."""
    conf = build_config({"KAFKA_SESSION_TIMEOUT_MS": "45000"})

    assert "heartbeat.interval.ms" in conf


@pytest.mark.parametrize(
    "session_timeout,expected",
    [
        ("45000", 3000),  # librdkafka's own default -- 15 beats per window
        ("60000", 3000),
        ("6000", 2000),  # below ~9s the derivation starts to bite
        ("3000", 1000),
    ],
)
def test_heartbeat_tracks_the_session_timeout(session_timeout, expected):
    conf = build_config({"KAFKA_SESSION_TIMEOUT_MS": session_timeout})

    assert conf["heartbeat.interval.ms"] == expected


def test_explicit_heartbeat_is_honoured():
    conf = build_config(
        {"KAFKA_SESSION_TIMEOUT_MS": "45000", "KAFKA_HEARTBEAT_INTERVAL_MS": "5000"}
    )

    assert conf["heartbeat.interval.ms"] == 5000


@pytest.mark.parametrize("strategy", ["cooperative-sticky", "range,roundrobin"])
def test_librdkafka_accepts_the_config(strategy):
    """The mocked tests assert config as a dict of strings; nothing else in the
    suite hands it to librdkafka. A typo'd key or an invalid strategy would
    CrashLoop every pod at boot with the whole suite green. Constructing a
    Consumer validates locally — no broker, no network."""
    from confluent_kafka import Consumer

    conf = build_config({"KAFKA_PARTITION_ASSIGNMENT_STRATEGY": strategy})

    consumer = Consumer(conf)
    try:
        assert consumer is not None
    finally:
        consumer.close()


def test_heartbeat_is_capped_at_a_third_of_the_session():
    """The broker must see several heartbeats per session window; an
    over-large value would make the session expire between beats."""
    conf = build_config(
        {"KAFKA_SESSION_TIMEOUT_MS": "9000", "KAFKA_HEARTBEAT_INTERVAL_MS": "8000"}
    )

    assert conf["heartbeat.interval.ms"] == 3000
