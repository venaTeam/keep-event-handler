"""Exercise delivery errors through the real controller and task exception handler."""

import json
from unittest.mock import MagicMock

import pytest
from arq import Retry

import src.bl.automations.publish_matches as publishing
import src.event_management.process_event_task as task
from src.bl.automations.models import AutomationMatch
from src.bl.automations.producer import MatchedPublishError, MatchedLockTimeout
from src.controllers.event_controller import process_event_sync
from src.core.kafka_consumer import KafkaEventConsumer, RetryBudget
from src.models.event_dto import EventDTO


@pytest.fixture
def delivery_flow(monkeypatch):
    session = MagicMock()
    monkeypatch.setattr(task, "get_session_sync", lambda: session)
    enrichments = MagicMock()
    enrichments.run_extraction_rules.side_effect = lambda event, **kwargs: event
    monkeypatch.setattr(task, "EnrichmentsBl", lambda *args: enrichments)
    monkeypatch.setattr(task, "KEEP_MAINTENANCE_WINDOWS_ENABLED", False)
    monkeypatch.setattr(task, "KEEP_ALERT_FIELDS_ENABLED", False)
    monkeypatch.setattr(task, "KEEP_CORRELATION_ENABLED", False)
    monkeypatch.setattr(task, "ElasticClient", MagicMock())
    monkeypatch.setattr(task, "get_notification_cache", MagicMock())
    monkeypatch.setattr(task, "_submit_notify", MagicMock())
    monkeypatch.setattr(task, "_submit_preset_notify", MagicMock())
    dedup = MagicMock()
    dedup.apply_deduplication.side_effect = lambda event, *args: event
    monkeypatch.setattr(task, "AlertDeduplicator", lambda *args: dedup)
    monkeypatch.setattr(task, "get_last_alert_hashes_by_fingerprints", lambda *args: {})
    save = MagicMock(return_value=[])
    monkeypatch.setattr(task, "__save_to_db", save)
    errors = MagicMock()
    monkeypatch.setattr(task, "__save_error_alerts", errors)
    error_counter = MagicMock()
    monkeypatch.setattr(task, "events_error_counter", error_counter)
    producer = MagicMock(enabled=True)
    producer.publish.side_effect = MatchedPublishError("broker unavailable")
    monkeypatch.setattr(publishing, "get_matched_producer", lambda: producer)
    monkeypatch.setattr(publishing, "match", lambda *_: (AutomationMatch("a", 300, None),))
    dto = EventDTO(tenant_id="tenant", trace_id="trace", event={
        "id": "upstream-id", "name": "test alert", "fingerprint": "fp",
        "time_created": "2026-01-01T00:00:00Z",
    })
    return dto, session, save, errors, error_counter, producer


def test_controller_propagates_delivery_failure_and_closes_session(delivery_flow):
    dto, session, save, errors, counter, producer = delivery_flow
    with pytest.raises(MatchedPublishError, match="broker unavailable"):
        process_event_sync(dto)
    save.assert_called_once()
    producer.publish.assert_called_once()
    errors.assert_not_called()
    counter.inc.assert_not_called()
    session.close.assert_called_once()


@pytest.mark.parametrize("failure", [MatchedPublishError("broker unavailable"), MatchedLockTimeout("lock deadline")])
def test_real_task_delivery_failure_prevents_raw_commit(delivery_flow, monkeypatch, failure):
    dto, session, save, errors, counter, producer = delivery_flow
    producer.publish.side_effect = failure
    kafka = MagicMock()
    monkeypatch.setattr("src.core.kafka_consumer.Consumer", lambda *args: kafka)
    consumer = KafkaEventConsumer()
    consumer._consumer = kafka
    terminal = MagicMock()
    monkeypatch.setattr(consumer, "_record_terminal", terminal)
    message = MagicMock()
    message.value.return_value = json.dumps(dto.dict()).encode()
    message.topic.return_value = "raw"
    message.partition.return_value = 0
    message.offset.return_value = 10
    consumer._process_batch([message], RetryBudget(300000, max_sleep_seconds=0))
    producer.publish.assert_called_once()
    save.assert_called_once()
    kafka.commit.assert_not_called()
    terminal.assert_not_called()
    errors.assert_not_called()
    counter.inc.assert_not_called()
    session.close.assert_called_once()


@pytest.mark.parametrize("failure", [MatchedPublishError("broker unavailable"), ValueError("bad event")])
def test_arq_keeps_error_recording_and_retry(delivery_flow, failure):
    dto, session, save, errors, counter, producer = delivery_flow
    producer.publish.side_effect = failure
    with pytest.raises(Retry):
        task.process_event(
            ctx={"job_try": 1}, tenant_id=dto.tenant_id,
            provider_type=None, provider_id=None, fingerprint=None,
            api_key_name=None, trace_id=dto.trace_id, event=dto.event,
        )
    errors.assert_called_once()
    counter.inc.assert_called_once()
    session.close.assert_called_once()


def test_other_kafka_errors_keep_existing_terminal_handling(delivery_flow):
    dto, session, save, errors, counter, producer = delivery_flow
    producer.publish.side_effect = ValueError("bad event")
    assert process_event_sync(dto) is None
    errors.assert_called_once()
    counter.inc.assert_called_once()
    session.close.assert_called_once()


@pytest.mark.parametrize("notify", [False, True])
def test_processing_finishes_before_publish_failure(delivery_flow, monkeypatch, notify):
    dto, session, save, errors, counter, producer = delivery_flow
    dto.notify_client = notify
    order = []
    def save_alerts(*args):
        order.append("save")
        for alert in args[4]:
            alert.event_id = "db-id"
        return args[4]
    save.side_effect = save_alerts
    monkeypatch.setattr(task, "KEEP_ALERT_FIELDS_ENABLED", True)
    monkeypatch.setattr(task, "bulk_upsert_alert_fields", lambda **kwargs: order.append("fields"))
    elastic = MagicMock(enabled=True)
    elastic.index_alert.side_effect = lambda **kwargs: order.append("elastic")
    monkeypatch.setattr(task, "ElasticClient", lambda **kwargs: elastic)
    rules = MagicMock()
    rules.run_rules.side_effect = lambda *args, **kwargs: order.append("rules") or []
    monkeypatch.setattr(task, "KEEP_CORRELATION_ENABLED", True)
    monkeypatch.setattr(task, "RulesEngine", lambda **kwargs: rules)
    monkeypatch.setattr(task, "_submit_notify", lambda *args: order.append("notify"))
    monkeypatch.setattr(task, "_submit_preset_notify", lambda *args: order.append("presets"))
    def fail(messages):
        order.append("publish")
        raise MatchedPublishError("broker unavailable")
    producer.publish.side_effect = fail
    with pytest.raises(MatchedPublishError):
        process_event_sync(dto)
    assert order == ["save", "fields", "elastic", "rules"] + (
        ["notify", "presets"] if notify else []
    ) + ["publish"]
    errors.assert_not_called()
    session.close.assert_called_once()


@pytest.mark.parametrize("failure_point", ["get_notification_cache", "_submit_notify", "_submit_preset_notify"])
def test_notification_failure_does_not_suppress_publish(delivery_flow, monkeypatch, caplog, failure_point):
    dto, session, save, errors, counter, producer = delivery_flow
    monkeypatch.setattr(task, failure_point, MagicMock(side_effect=RuntimeError("private details")))
    producer.publish.side_effect = None
    process_event_sync(dto)
    producer.publish.assert_called_once()
    errors.assert_not_called()
    assert "Failed to schedule alert notifications" in caplog.text
    assert "private details" not in caplog.text


def test_full_duplicate_still_publishes_after_processing(delivery_flow):
    dto, session, save, errors, counter, producer = delivery_flow
    dto.event["is_full_duplicate"] = True
    dto.notify_client = False
    producer.publish.side_effect = None
    process_event_sync(dto)
    assert save.call_args.args[4] == []
    assert len(save.call_args.args[5]) == 1
    assert producer.publish.call_args.args[0][0]["alert"]["id"] == "upstream-id"
    errors.assert_not_called()
