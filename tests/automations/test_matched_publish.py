import pytest

import src.bl.automations.publish_matches as matched_publish
from src.bl.automations.models import AutomationMatch, CooldownSpec
from src.bl.automations.producer import (
    MatchedContractError,
    MatchedProducer,
    MatchedPublishError,
)
from src.bl.automations.publish_matches import build_messages


class FakeProducer:
    def __init__(self, errors=None):
        self.queued = []
        self.errors = list(errors or [])

    def produce(self, topic, key, value, on_delivery):
        self.queued.append((topic, key, value, on_delivery))

    def poll(self, timeout):
        if self.queued:
            _topic, _key, _value, callback = self.queued.pop(0)
            callback(self.errors.pop(0) if self.errors else None, object())

    def list_topics(self, timeout):
        return object()

    def flush(self, timeout):
        return len(self.queued)


class RaisingProducer(FakeProducer):
    def produce(self, topic, key, value, on_delivery):
        raise RuntimeError("local producer failure")


class MissingTopicProducer(FakeProducer):
    def list_topics(self, timeout):
        return type("Metadata", (), {"topics": {}})()


def alert():
    return {
        "id": "event-789",
        "fingerprint": "fp",
        "started_at": "2026-01-01T00:00:00Z",
    }


def test_producer_uses_dedicated_kafka_configuration(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "raw-kafka:9092")
    monkeypatch.setenv(
        "MATCHED_KAFKA_BOOTSTRAP_SERVERS",
        '["matched-a:9092", "matched-b:9092"]',
    )
    monkeypatch.setenv("MATCHED_KAFKA_SECURITY_PROTOCOL", "SASL_SSL")
    monkeypatch.setenv("MATCHED_KAFKA_SASL_MECHANISM", "SCRAM-SHA-512")
    monkeypatch.setenv("MATCHED_KAFKA_SASL_USERNAME", "matched-user")
    monkeypatch.setenv("MATCHED_KAFKA_SASL_PASSWORD", "matched-password")
    monkeypatch.setenv("MATCHED_KAFKA_SSL_CAFILE", "/matched/ca.pem")

    producer_config = MatchedProducer._config()

    assert producer_config["bootstrap.servers"] == "matched-a:9092,matched-b:9092"
    assert producer_config["security.protocol"] == "SASL_SSL"
    assert producer_config["sasl.mechanism"] == "SCRAM-SHA-512"
    assert producer_config["sasl.username"] == "matched-user"
    assert producer_config["sasl.password"] == "matched-password"
    assert producer_config["ssl.ca.location"] == "/matched/ca.pem"


def test_message_per_pair_exact_contract_and_key(monkeypatch):
    matches = (
        AutomationMatch("a-1", 300, None),
        AutomationMatch("a-2", 300, CooldownSpec(("site", "node_name"), 60)),
    )
    messages = build_messages("tenant-1", alert(), matches)

    assert [m["automation_id"] for m in messages] == ["a-1", "a-2"]
    assert {m["matched_m"] for m in messages} == {2}
    assert messages[0]["cooldown"] is None
    assert messages[1]["cooldown"] == {
        "fields": ["site", "node_name"], "seconds": 60, "scheme_ver": 1
    }
    assert set(messages[0]) == {"tenant_id", "alert", "automation_id", "matched_m", "cooldown"}


def test_missing_source_id_is_rejected_before_kafka():
    with pytest.raises(MatchedContractError, match="alert.id"):
        build_messages(
            "tenant",
            {"fingerprint": "fp", "started_at": "2026-01-01T00:00:00Z"},
            (AutomationMatch("a", 300, None),),
        )


def test_source_id_is_preserved_without_history_id():
    messages = build_messages(
        "tenant", alert(), (AutomationMatch("a", 300, None),)
    )

    assert messages[0]["alert"]["id"] == "event-789"
    assert "history_id" not in messages[0]["alert"]


@pytest.mark.parametrize("missing", ["fingerprint", "started_at"])
def test_required_alert_contract_fields_are_rejected(missing):
    payload = alert()
    payload.pop(missing)

    with pytest.raises(MatchedContractError, match=missing):
        build_messages("tenant", payload, (AutomationMatch("a", 300, None),))


def test_publish_matches_passes_original_alert_to_match(monkeypatch):
    source_alert = object()
    matched_alerts = []

    class ProducerStub:
        def publish(self, messages):
            raise AssertionError("M=0 must not publish")

    def capture_match(tenant_id, candidate):
        matched_alerts.append((tenant_id, candidate))
        return ()

    monkeypatch.setattr(matched_publish, "get_matched_producer", ProducerStub)
    monkeypatch.setattr(matched_publish, "match", capture_match)

    matched_publish.publish_matches("tenant", [source_alert])

    assert matched_alerts == [("tenant", source_alert)]


def test_fanout_is_enqueued_then_acknowledged():
    fake = FakeProducer()
    producer = MatchedProducer(client=fake)
    messages = build_messages(
        "tenant", alert(),
        (AutomationMatch("a-1", 300, None), AutomationMatch("a-2", 300, None)),
    )

    producer.publish(messages)

    assert fake.queued == []
    assert producer.health()[0] is True


def test_partial_delivery_raises_and_marks_unhealthy():
    producer = MatchedProducer(client=FakeProducer(errors=[None, RuntimeError("broker")]))
    messages = build_messages(
        "tenant", alert(),
        (AutomationMatch("a-1", 300, None), AutomationMatch("a-2", 300, None)),
    )

    with pytest.raises(MatchedPublishError, match="1/2 acknowledged"):
        producer.publish(messages)

    assert producer.healthy is False


def test_unexpected_client_error_is_always_an_unresolved_publish_error():
    producer = MatchedProducer(client=RaisingProducer())
    messages = build_messages(
        "tenant", alert(), (AutomationMatch("a-1", 300, None),)
    )

    with pytest.raises(MatchedPublishError):
        producer.publish(messages)


def test_start_requires_matched_topic_metadata():
    producer = MatchedProducer(client=MissingTopicProducer())

    assert producer.start() is False
    assert producer.healthy is False
