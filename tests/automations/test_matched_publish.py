import json
import pytest
from unittest.mock import Mock

from src.bl.automations import settings
import src.bl.automations.producer as producer_module

import src.bl.automations.publish_matches as matched_publish
from src.bl.automations.models import AutomationMatch, CooldownSpec
from src.bl.automations.producer import (
    MatchedContractError,
    MatchedProducer,
    MatchedPublishError,
)
from src.bl.automations.publish_matches import build_messages


@pytest.fixture(autouse=True)
def enable_matched_publishing(monkeypatch):
    monkeypatch.setattr(settings, "AUTOMATION_MATCHING_ENABLED", True)


def test_disabled_publishing_has_no_kafka_lifecycle(monkeypatch):
    monkeypatch.setattr(settings, "AUTOMATION_MATCHING_ENABLED", False)
    factory = Mock(side_effect=AssertionError("Kafka must not be constructed"))
    monkeypatch.setattr(producer_module, "Producer", factory)
    producer = MatchedProducer()

    assert producer.enabled is False
    assert producer.start() is False
    assert producer.health() == (True, "matched publishing disabled")
    producer.publish([{"invalid": "unused while disabled"}])
    producer.stop()
    factory.assert_not_called()


def test_disabled_publishing_still_probes_without_building_messages(monkeypatch):
    producer = Mock(enabled=False)
    matcher = Mock(return_value=(AutomationMatch("a", 300, None),))
    monkeypatch.setattr(matched_publish, "get_matched_producer", lambda: producer)
    monkeypatch.setattr(matched_publish, "match", matcher)
    source_alert = object()

    matched_publish.publish_matches("tenant", [source_alert])

    matcher.assert_called_once_with("tenant", source_alert)
    producer.publish.assert_not_called()


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


class FalseyProducer(FakeProducer):
    def __bool__(self):
        return False


def alert():
    return {
        "id": "event-789",
        "fingerprint": "fp",
        "time_created": "2026-01-01T00:00:00Z",
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


def test_explicit_falsey_client_is_not_replaced():
    client = FalseyProducer()

    producer = MatchedProducer(client=client)

    assert producer._client is client


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


@pytest.mark.parametrize("field", ["id", "fingerprint", "time_created"])
def test_missing_required_alert_field_is_rejected_before_kafka(field):
    payload = alert()
    payload.pop(field)

    with pytest.raises(MatchedContractError, match=field):
        build_messages("tenant", payload, (AutomationMatch("a", 300, None),))


def test_source_id_is_preserved_without_history_id():
    messages = build_messages(
        "tenant", alert(), (AutomationMatch("a", 300, None),)
    )

    assert messages[0]["alert"]["id"] == "event-789"
    assert "history_id" not in messages[0]["alert"]


@pytest.mark.parametrize("field", ["id", "fingerprint", "time_created"])
@pytest.mark.parametrize("invalid_value", [None, "", "   ", 7])
def test_required_alert_contract_fields_are_non_empty_strings(
    field, invalid_value
):
    payload = alert()
    payload[field] = invalid_value

    with pytest.raises(MatchedContractError, match=field):
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


def test_partial_delivery_raises_and_marks_unhealthy(caplog):
    producer = MatchedProducer(client=FakeProducer(errors=[None, RuntimeError("broker")]))
    messages = build_messages(
        "tenant", alert(),
        (AutomationMatch("a-1", 300, None), AutomationMatch("a-2", 300, None)),
    )

    with pytest.raises(MatchedPublishError, match="1/2 acknowledged"):
        producer.publish(messages)

    assert producer.healthy is False
    assert "Matched-message delivery incomplete" in caplog.text


def test_unexpected_client_error_is_always_an_unresolved_publish_error():
    producer = MatchedProducer(client=RaisingProducer())
    messages = build_messages(
        "tenant", alert(), (AutomationMatch("a-1", 300, None),)
    )

    with pytest.raises(MatchedPublishError):
        producer.publish(messages)


def test_empty_automation_id_is_a_contract_error():
    producer = MatchedProducer(client=FakeProducer())
    messages = build_messages(
        "tenant", alert(), (AutomationMatch("", 300, None),)
    )

    with pytest.raises(MatchedContractError, match="invalid matched-message"):
        producer.publish(messages)


def test_start_requires_matched_topic_metadata():
    producer = MatchedProducer(client=MissingTopicProducer())

    assert producer.start() is False
    assert producer.healthy is False


@pytest.mark.parametrize("bad_value", [object(), float("nan"), {"circular": None}])
def test_invalid_later_message_never_partially_enqueues(bad_value):
    if isinstance(bad_value, dict):
        bad_value["circular"] = bad_value
    fake = FakeProducer()
    producer = MatchedProducer(client=fake)
    producer._healthy = True
    with pytest.raises(MatchedContractError):
        producer.publish([
            {"automation_id": "valid"},
            {"automation_id": "invalid", "alert": bad_value},
        ])
    assert fake.queued == []
    assert producer.healthy is True


@pytest.mark.parametrize("raw_json", ["[]", "null", "broken"])
def test_invalid_snapshot_shape_is_contract_error(raw_json):
    source = Mock()
    source.json.return_value = raw_json
    with pytest.raises(MatchedContractError):
        build_messages("tenant", source, (AutomationMatch("a", 300, None),))


def test_bad_alert_is_counted_and_valid_siblings_publish(monkeypatch, caplog):
    from prometheus_client import generate_latest

    fake = FakeProducer()
    sent = []
    original_produce = fake.produce

    def capture(topic, key, value, on_delivery):
        sent.append(json.loads(value))
        original_produce(topic, key, value, on_delivery)

    fake.produce = capture
    producer = MatchedProducer(client=fake)
    monkeypatch.setattr(matched_publish, "get_matched_producer", lambda: producer)
    monkeypatch.setattr(matched_publish, "match", lambda *_: (AutomationMatch("a", 300, None),))
    metric = matched_publish.automation_matched_alerts_rejected_total
    before = next(s.value for s in metric.collect()[0].samples if s.name.endswith("_total"))
    bad = dict(alert(), time_created=None, secret="do-not-log-this")

    matched_publish.publish_matches("tenant", [alert(), bad, dict(alert(), id="last")])

    assert [m["alert"]["id"] for m in sent] == ["event-789", "last"]
    assert fake.queued == []
    after = next(s.value for s in metric.collect()[0].samples if s.name.endswith("_total"))
    assert after == before + 1
    assert b"keep_automation_matched_alerts_rejected_total" in generate_latest()
    assert "alert_index=1" in caplog.text
    assert "time_created" in caplog.text
    assert "do-not-log-this" not in caplog.text


def test_delivery_failure_is_not_rejected_as_bad_data(monkeypatch):
    producer = MatchedProducer(client=FakeProducer(errors=[RuntimeError("broker")]))
    monkeypatch.setattr(matched_publish, "get_matched_producer", lambda: producer)
    monkeypatch.setattr(matched_publish, "match", lambda *_: (AutomationMatch("a", 300, None),))
    rejected = Mock()
    monkeypatch.setattr(matched_publish, "automation_matched_alerts_rejected_total", rejected)
    with pytest.raises(MatchedPublishError):
        matched_publish.publish_matches("tenant", [alert()])
    rejected.inc.assert_not_called()
