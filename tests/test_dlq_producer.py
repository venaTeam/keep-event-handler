import json
from unittest.mock import MagicMock, patch

import pytest

from src.core import dlq_producer
from src.core.dlq_producer import (
    _bootstrap_servers,
    _build_dlq_payload,
    close,
    produce_to_dlq,
)


@pytest.fixture(autouse=True)
def reset_producer():
    dlq_producer._producer = None
    yield
    dlq_producer._producer = None


@pytest.fixture
def producer():
    fake = MagicMock()
    fake.flush.return_value = 0
    with patch.object(dlq_producer, "Producer", return_value=fake):
        yield fake


def sent_payload(fake) -> dict:
    return json.loads(fake.produce.call_args.kwargs["value"])


class TestBootstrapServers:
    def test_json_list(self, monkeypatch):
        monkeypatch.setattr(dlq_producer, "KAFKA_DLQ_BOOTSTRAP_SERVERS", '["a:1", "b:2"]')
        assert _bootstrap_servers() == "a:1,b:2"

    def test_comma_separated(self, monkeypatch):
        monkeypatch.setattr(dlq_producer, "KAFKA_DLQ_BOOTSTRAP_SERVERS", "a:1,b:2")
        assert _bootstrap_servers() == "a:1,b:2"

    def test_single_host(self, monkeypatch):
        monkeypatch.setattr(dlq_producer, "KAFKA_DLQ_BOOTSTRAP_SERVERS", "localhost:9092")
        assert _bootstrap_servers() == "localhost:9092"


class TestBuildDlqPayload:
    def test_envelope_fields(self):
        payload = _build_dlq_payload(
            {"name": "cpu", "fingerprint": "fp-1"},
            "ValueError: boom",
            tenant_id="t1",
            provider_type="grafana",
            fingerprint="fp-1",
            event_type="alert",
        )
        assert payload["alert"] == {"name": "cpu", "fingerprint": "fp-1"}
        assert payload["error"] == {"message": "ValueError: boom"}
        assert payload["tenant_id"] == "t1"
        assert payload["provider_type"] == "grafana"
        assert payload["fingerprint"] == "fp-1"
        assert payload["event_type"] == "alert"
        assert payload["dlq_topic"] == dlq_producer.KAFKA_DLQ_TOPIC

    def test_non_dict_event_is_wrapped(self):
        payload = _build_dlq_payload("not a dict", "err")
        assert payload["alert"] == {"_unserializable_payload": "not a dict"}


class TestProduceToDlq:
    def test_success_unwraps_inner_event(self, producer):
        payload = {
            "event": {"name": "cpu", "fingerprint": "fp-1"},
            "tenant_id": "t1",
            "provider_id": "p1",
            "fingerprint": "fp-1",
            "event_type": "alert",
        }

        assert produce_to_dlq(payload, ValueError("boom"), tenant_id="t1") is True

        args, kwargs = producer.produce.call_args
        assert args == (dlq_producer.KAFKA_DLQ_TOPIC,)
        assert kwargs["key"] == "fp-1"
        sent = sent_payload(producer)
        assert sent["alert"] == {"name": "cpu", "fingerprint": "fp-1"}
        assert sent["error"]["message"] == "ValueError: boom"
        assert sent["provider_id"] == "p1"
        producer.flush.assert_called_once()

    def test_payload_without_event_is_sent_whole(self, producer):
        assert produce_to_dlq({"raw": "not json"}, ValueError("bad")) is True
        assert sent_payload(producer)["alert"] == {"raw": "not json"}

    def test_none_payload_still_diverted(self, producer):
        assert produce_to_dlq(None, ValueError("bad")) is True
        sent = sent_payload(producer)
        assert sent["alert"] == {"_unserializable_payload": None}
        assert sent["event_type"] == "alert"

    def test_unserializable_values_are_stringified(self, producer):
        class Opaque:
            def __str__(self):
                return "opaque"

        assert produce_to_dlq({"event": {"obj": Opaque()}}, ValueError("x")) is True
        assert sent_payload(producer)["alert"] == {"obj": "opaque"}

    def test_undelivered_flush_is_failure(self, producer):
        producer.flush.return_value = 1
        assert produce_to_dlq({"event": {"a": 1}}, ValueError("x")) is False

    def test_produce_error_is_failure_not_raise(self, producer):
        producer.produce.side_effect = RuntimeError("broker down")
        assert produce_to_dlq({"event": {"a": 1}}, ValueError("x")) is False

    def test_producer_creation_failure(self):
        with patch.object(dlq_producer, "Producer", side_effect=RuntimeError("bad config")):
            assert produce_to_dlq({"event": {"a": 1}}, ValueError("x")) is False

    def test_producer_is_reused(self):
        fake = MagicMock()
        fake.flush.return_value = 0
        with patch.object(dlq_producer, "Producer", return_value=fake) as factory:
            produce_to_dlq({"event": {"a": 1}}, ValueError("x"))
            produce_to_dlq({"event": {"a": 2}}, ValueError("y"))
        factory.assert_called_once()


class TestFixes:
    def test_broker_rejection_is_failure(self, producer):
        """flush() returns 0 for a rejected message too; only the delivery
        report tells it apart from a delivered one."""

        def reject(*args, on_delivery, **kwargs):
            on_delivery(RuntimeError("TOPIC_AUTHORIZATION_FAILED"), None)

        producer.produce.side_effect = reject
        assert produce_to_dlq({"event": {"a": 1}}, ValueError("x")) is False

    def test_delivered_message_is_success(self, producer):
        def deliver(*args, on_delivery, **kwargs):
            on_delivery(None, MagicMock())

        producer.produce.side_effect = deliver
        assert produce_to_dlq({"event": {"a": 1}}, ValueError("x")) is True

    def test_trace_id_comes_from_the_message(self, producer):
        produce_to_dlq({"event": {"a": 1}, "trace_id": "tr-9"}, ValueError("x"))
        assert sent_payload(producer)["trace_id"] == "tr-9"

    def test_batch_stays_a_list(self, producer):
        batch = [{"fingerprint": "a"}, {"fingerprint": "b"}]
        produce_to_dlq({"event": batch, "fingerprint": "a"}, ValueError("x"))
        assert sent_payload(producer)["alert"] == batch
        assert producer.produce.call_args.kwargs["key"] == "a"

    def test_empty_list_is_wrapped(self, producer):
        produce_to_dlq({"event": []}, ValueError("x"))
        assert sent_payload(producer)["alert"] == {"_unserializable_payload": []}

    def test_replay_count_is_carried(self, producer):
        produce_to_dlq({"event": {"a": 1}, "dlq_replay_count": 2}, ValueError("x"))
        assert sent_payload(producer)["dlq_replay_count"] == 2

    def test_source_topic_follows_config(self, producer, monkeypatch):
        monkeypatch.setenv("KAFKA_TOPIC", "custom-events")
        produce_to_dlq({"event": {"a": 1}}, ValueError("x"))
        assert sent_payload(producer)["source_topic"] == "custom-events"


class TestClose:
    def test_flushes_and_resets(self, producer):
        produce_to_dlq({"event": {"a": 1}}, ValueError("x"))
        producer.flush.reset_mock()

        close()

        producer.flush.assert_called_once()
        assert dlq_producer._producer is None

    def test_never_raises(self, producer):
        produce_to_dlq({"event": {"a": 1}}, ValueError("x"))
        producer.flush.side_effect = RuntimeError("gone")
        close()
        assert dlq_producer._producer is None

    def test_noop_without_producer(self):
        close()
