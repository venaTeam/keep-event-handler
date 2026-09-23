import json
import pytest
from unittest.mock import Mock, call

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
    monkeypatch.setattr(producer_module, "MAX_PROCESSING_RETRIES", 1)
    # Existing failure tests exercise the unresolved path: both destinations down.
    monkeypatch.setattr(producer_module, 'Producer', lambda *_: RaisingProducer())


def test_disabled_publishing_has_no_kafka_lifecycle(monkeypatch):
    monkeypatch.setattr(settings, "AUTOMATION_MATCHING_ENABLED", False)
    factory = Mock(side_effect=AssertionError("Kafka must not be constructed"))
    monkeypatch.setattr(producer_module, "Producer", factory)
    producer = MatchedProducer()

    assert producer.enabled is False
    assert producer.start() is True
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

    def produce(self, topic, key, value, on_delivery, headers=None):
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
    def produce(self, topic, key, value, on_delivery, headers=None):
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
    assert producer_config["delivery.timeout.ms"] == 5000


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
    assert producer.healthy is True


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
    producer = MatchedProducer(client=fake, dlq_client=FakeProducer())
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
    assert "alert_id='event-789'" in caplog.text
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


@pytest.mark.parametrize("queue_full", [False, True])
def test_poll_exception_is_unresolved_and_marks_producer_unhealthy(queue_full, caplog):
    client = Mock()
    if queue_full:
        client.produce.side_effect = BufferError()
    client.poll.side_effect = ValueError("sensitive broker details")
    producer = MatchedProducer(client=client)
    producer._healthy = True

    with pytest.raises(MatchedPublishError, match="0/2 acknowledged"):
        producer.publish([{"automation_id": "a"}, {"automation_id": "b"}])

    assert producer.healthy is False
    assert client.produce.call_count == (1 if queue_full else 2)
    assert "poll_error=ValueError" in caplog.text
    assert "sensitive broker details" not in caplog.text


def test_poll_exception_after_partial_ack_preserves_counts(monkeypatch):
    client = FakeProducer()
    original_poll = client.poll

    def poll_then_fail(timeout):
        original_poll(timeout)
        raise RuntimeError("poll failed")

    client.poll = poll_then_fail
    metrics = Mock()
    monkeypatch.setattr(producer_module, "automation_matched_publish_total", metrics)
    producer = MatchedProducer(client=client)

    with pytest.raises(MatchedPublishError, match="1/2 acknowledged"):
        producer.publish([{"automation_id": "a"}, {"automation_id": "b"}])

    assert metrics.labels.call_args_list == [
        call(result="failed"),
        call(result="acknowledged"),
    ]
    assert metrics.labels.return_value.inc.call_args_list == [call(1), call(1)]
    assert producer.healthy is False


def test_delivery_retry_reuses_serialization_and_recovers(monkeypatch, caplog):
    caplog.set_level("DEBUG", logger=producer_module.__name__)
    monkeypatch.setattr(producer_module, "MAX_PROCESSING_RETRIES", 3)
    client = FakeProducer(errors=[RuntimeError("temporary"), None])
    clock = [0.0]
    waits = []

    def wait(seconds):
        waits.append(seconds)
        clock[0] += seconds

    dumps = Mock(wraps=json.dumps)
    duration = Mock()
    monkeypatch.setattr(producer_module, "automation_matched_publish_duration_seconds", duration)
    monkeypatch.setattr(producer_module.json, "dumps", dumps)
    producer = MatchedProducer(client=client, clock=lambda: clock[0], wait=wait)
    producer.publish([{"automation_id": "a"}])

    dumps.assert_called_once()
    assert waits == [0.01]
    assert producer.healthy is True
    assert client.queued == []
    duration.observe.assert_called_once_with(0.01)
    assert "next_attempt=2" in caplog.text
    assert "remaining_seconds=" in caplog.text
    assert "Matched publishing configuration" in caplog.text
    assert caplog.text.count("Matched producer recovered") == 1
    producer.publish([{"automation_id": "a"}])
    assert caplog.text.count("Matched producer recovered") == 1


def test_delivery_retry_deadline_is_shared_and_backoff_is_bounded(monkeypatch):
    monkeypatch.setattr(producer_module, "MAX_PROCESSING_RETRIES", 10)
    monkeypatch.setattr(settings, "AUTOMATION_MATCHED_PUBLISH_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(settings, "AUTOMATION_MATCHED_QUEUE_RETRY_SECONDS", 0.06)
    clock = [0.0]
    waits = []
    client = Mock()
    client.produce.side_effect = RuntimeError("unavailable")

    def wait(seconds):
        waits.append(seconds)
        clock[0] += seconds

    producer = MatchedProducer(client=client, clock=lambda: clock[0], wait=wait)
    with pytest.raises(MatchedPublishError):
        producer.publish([{"automation_id": "a"}])

    assert client.produce.call_count == 2
    assert waits == pytest.approx([0.06, 0.04])
    assert clock[0] == pytest.approx(0.1)


@pytest.mark.parametrize("seconds,expected", [(5, 5000), (0, 100), (-1, 100)])
def test_client_delivery_timeout_uses_clamped_publish_timeout(monkeypatch, seconds, expected):
    monkeypatch.setattr(settings, "AUTOMATION_MATCHED_PUBLISH_TIMEOUT_SECONDS", seconds)
    assert MatchedProducer._config()["delivery.timeout.ms"] == expected


@pytest.mark.parametrize("queue_full", [False, True])
def test_expired_deadline_does_not_enqueue_more_messages(monkeypatch, queue_full):
    monkeypatch.setattr(settings, "AUTOMATION_MATCHED_PUBLISH_TIMEOUT_SECONDS", 0.1)
    clock = [0.0]
    client = Mock()

    def produce(*args, **kwargs):
        clock[0] = 0.1
        if queue_full:
            raise BufferError()

    client.produce.side_effect = produce
    producer = MatchedProducer(client=client, clock=lambda: clock[0])
    duration = Mock()
    monkeypatch.setattr(producer_module, "automation_matched_publish_duration_seconds", duration)

    with pytest.raises(MatchedPublishError, match="0/2 acknowledged"):
        producer.publish([{"automation_id": "a"}, {"automation_id": "b"}])

    client.produce.assert_called_once()
    client.poll.assert_not_called()
    duration.observe.assert_called_once_with(0.1)
    assert producer.healthy is False


@pytest.mark.parametrize("operation", ["publish", "start"])
@pytest.mark.parametrize("healthy", [False, True])
def test_contended_lock_uses_operation_deadline(monkeypatch, operation, healthy):
    import time
    monkeypatch.setattr(settings, "AUTOMATION_MATCHED_PUBLISH_TIMEOUT_SECONDS", 0.1)
    client = Mock()
    producer = MatchedProducer(client=client)
    producer._healthy = healthy
    producer._recovery_pending = not healthy
    gauge = Mock()
    monkeypatch.setattr(producer_module, "automation_matched_producer_ready", gauge)
    producer._lock.acquire()
    started = time.monotonic()
    try:
        if operation == "publish":
            with pytest.raises(producer_module.MatchedPublishError, match="lock deadline"):
                producer.publish([{"automation_id": "a"}])
        else:
            assert producer.start() is False
    finally:
        producer._lock.release()
    assert time.monotonic() - started < 1.0
    client.produce.assert_not_called()
    client.list_topics.assert_not_called()
    assert producer.healthy is healthy
    assert producer._recovery_pending is not healthy
    gauge.set.assert_not_called()


@pytest.mark.parametrize("operation", ["publish", "start"])
@pytest.mark.parametrize("healthy", [False, True])
def test_deadline_expired_on_acquire_preserves_health(monkeypatch, operation, healthy):
    clock = [0.0]
    client = Mock()
    producer = MatchedProducer(client=client, clock=lambda: clock[0])
    producer._healthy = healthy
    producer._recovery_pending = not healthy
    gauge = Mock()
    monkeypatch.setattr(producer_module, "automation_matched_producer_ready", gauge)
    lock = Mock()
    def acquire(timeout):
        clock[0] += timeout
        return True
    lock.acquire.side_effect = acquire
    producer._lock = lock
    if operation == "publish":
        with pytest.raises(producer_module.MatchedPublishError):
            producer.publish([{"automation_id": "a"}])
    else:
        assert producer.start() is False
    lock.release.assert_called_once()
    client.produce.assert_not_called()
    client.list_topics.assert_not_called()
    assert producer.healthy is healthy
    assert producer._recovery_pending is not healthy
    gauge.set.assert_not_called()


def test_metadata_check_gets_only_budget_remaining_after_lock():
    clock = [0.0]
    client = Mock()
    client.list_topics.return_value = type("Metadata", (), {
        "topics": {producer_module.MATCHED_ALERTS_TOPIC: type("Topic", (), {"error": None})()}
    })()
    producer = MatchedProducer(client=client, clock=lambda: clock[0])
    lock = Mock()
    def acquire(timeout):
        clock[0] += 2.0
        return True
    lock.acquire.side_effect = acquire
    producer._lock = lock
    assert producer.start() is True
    client.list_topics.assert_called_once_with(timeout=3.0)
    lock.release.assert_called_once()
