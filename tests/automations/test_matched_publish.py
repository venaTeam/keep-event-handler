import uuid
import pytest

from src.bl.automations.models import AutomationMatch, CooldownSpec
from src.bl.automations.producer import MatchedProducer, MatchedPublishError
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


def alert():
    return {"history_id": str(uuid.uuid4()), "fingerprint": "fp", "time_created": "2026-01-01T00:00:00Z"}


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


def test_missing_history_id_is_rejected_before_kafka():
    with pytest.raises(ValueError, match="history_id"):
        build_messages("tenant", {"fingerprint": "fp"}, (AutomationMatch("a", 300, None),))


def test_fanout_is_enqueued_then_acknowledged(monkeypatch):
    from src.bl.automations import settings
    monkeypatch.setattr(settings, "AUTOMATION_MATCHED_PUBLISH_ENABLED", True)
    fake = FakeProducer()
    producer = MatchedProducer(client=fake)
    messages = build_messages(
        "tenant", alert(),
        (AutomationMatch("a-1", 300, None), AutomationMatch("a-2", 300, None)),
    )

    producer.publish(messages)

    assert fake.queued == []
    assert producer.health()[0] is True


def test_partial_delivery_raises_and_marks_unhealthy(monkeypatch):
    from src.bl.automations import settings
    monkeypatch.setattr(settings, "AUTOMATION_MATCHED_PUBLISH_ENABLED", True)
    producer = MatchedProducer(client=FakeProducer(errors=[None, RuntimeError("broker")]))
    messages = build_messages(
        "tenant", alert(),
        (AutomationMatch("a-1", 300, None), AutomationMatch("a-2", 300, None)),
    )

    with pytest.raises(MatchedPublishError, match="1/2 acknowledged"):
        producer.publish(messages)

    assert producer.health()[0] is False
