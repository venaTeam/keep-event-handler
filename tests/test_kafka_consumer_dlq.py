"""
Terminal failures in the consumer are diverted to the DLQ topic (replayed by
keep-reconciler) instead of written to alertraw. These tests pin the
`_record_terminal` decision tree and the `reason` label each failure path
passes to it.
"""

from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import HTTPError

from src.core import kafka_consumer
from src.core.kafka_consumer import KafkaEventConsumer, RetryBudget

PAYLOAD = {
    "tenant_id": "t1",
    "provider_type": "grafana",
    "event": {"name": "cpu", "fingerprint": "fp-1"},
}


def _http_error(status: int) -> HTTPError:
    response = MagicMock()
    response.status_code = status
    return HTTPError(response=response)


@pytest.fixture
def sink(monkeypatch):
    """Patches every collaborator of `_record_terminal`; storm guard lets
    everything through and the DLQ flag is on unless a test says otherwise."""
    produce = MagicMock(return_value=True)
    diverted = MagicMock()
    guard = MagicMock(return_value=True)
    monkeypatch.setattr(kafka_consumer, "produce_to_dlq", produce)
    monkeypatch.setattr(kafka_consumer, "dlq_diverted_total", diverted)
    monkeypatch.setattr(kafka_consumer, "should_record_error", guard)
    monkeypatch.setattr(kafka_consumer, "KEEP_HANDLER_DLQ_ENABLED", True)
    return MagicMock(produce=produce, diverted=diverted, guard=guard)


@pytest.fixture
def consumer():
    c = KafkaEventConsumer()
    c.logger = MagicMock()
    return c


class TestRecordTerminal:
    def test_diverts_and_counts_by_reason(self, consumer, sink):
        consumer._record_terminal(PAYLOAD, ValueError("boom"), reason="poison")

        sink.produce.assert_called_once()
        kwargs = sink.produce.call_args.kwargs
        assert kwargs["payload"] is PAYLOAD
        assert kwargs["tenant_id"] == "t1"
        assert kwargs["provider_type"] == "grafana"
        sink.diverted.labels.assert_called_once_with(reason="poison")
        sink.diverted.labels.return_value.inc.assert_called_once()
        consumer.logger.error.assert_not_called()

    def test_storm_guard_suppresses_divert(self, consumer, sink):
        sink.guard.return_value = False

        consumer._record_terminal(PAYLOAD, ValueError("boom"), reason="poison")

        sink.produce.assert_not_called()
        sink.diverted.labels.assert_not_called()
        assert sink.guard.call_args.kwargs["error_class"] == "terminal"
        assert sink.guard.call_args.kwargs["error_message"] == "ValueError: boom"

    @pytest.mark.parametrize("reason", ["attempt_cap", "budget_exhausted", "unexpected"])
    def test_outage_failures_are_never_storm_guarded(self, consumer, sink, reason):
        """During an outage every alert fails with the same message; each one is
        recoverable, so none may be suppressed."""
        sink.guard.return_value = False

        consumer._record_terminal(PAYLOAD, ValueError("db down"), reason=reason)

        sink.guard.assert_not_called()
        sink.produce.assert_called_once()
        sink.diverted.labels.assert_called_once_with(reason=reason)

    @pytest.mark.parametrize("reason", ["poison", "malformed"])
    def test_repeatable_failures_are_storm_guarded(self, consumer, sink, reason):
        sink.guard.return_value = False

        consumer._record_terminal(PAYLOAD, ValueError("bad"), reason=reason)

        sink.guard.assert_called_once()
        sink.produce.assert_not_called()

    def test_flag_off_keeps_the_alertraw_path(self, consumer, sink, monkeypatch):
        """With the flag off nothing changes: the old alertraw write, committed."""
        monkeypatch.setattr(kafka_consumer, "KEEP_HANDLER_DLQ_ENABLED", False)
        alertraw = MagicMock()
        monkeypatch.setattr(kafka_consumer, "record_terminal_error", alertraw)

        assert consumer._record_terminal(PAYLOAD, ValueError("boom"), reason="attempt_cap") is True

        sink.produce.assert_not_called()
        alertraw.assert_called_once_with(
            tenant_id="t1",
            provider_type="grafana",
            raw_event=PAYLOAD,
            error_message="ValueError: boom",
        )

    def test_flag_off_alertraw_failure_still_commits(self, consumer, sink, monkeypatch):
        monkeypatch.setattr(kafka_consumer, "KEEP_HANDLER_DLQ_ENABLED", False)
        monkeypatch.setattr(
            kafka_consumer, "record_terminal_error", MagicMock(side_effect=RuntimeError("db"))
        )

        assert consumer._record_terminal(PAYLOAD, ValueError("boom"), reason="poison") is True

    def test_successful_divert_commits(self, consumer, sink):
        assert consumer._record_terminal(PAYLOAD, ValueError("boom"), reason="poison") is True
        assert sink.produce.call_args.kwargs["reason"] == "poison"

    def test_failed_divert_is_not_committed(self, consumer, sink):
        """With the flag on, a DLQ write that fails must not lose the event:
        the caller leaves it uncommitted so it is processed again."""
        sink.produce.return_value = False

        assert consumer._record_terminal(PAYLOAD, ValueError("boom"), reason="attempt_cap") is False

        sink.diverted.labels.assert_not_called()
        assert "uncommitted" in consumer.logger.error.call_args.args[0]

    def test_storm_guarded_poison_is_committed(self, consumer, sink):
        sink.guard.return_value = False
        assert consumer._record_terminal(PAYLOAD, ValueError("bad"), reason="poison") is True

    def test_never_raises(self, consumer, sink):
        sink.produce.side_effect = RuntimeError("unexpected")

        assert consumer._record_terminal(PAYLOAD, ValueError("boom"), reason="poison") is False

        consumer.logger.exception.assert_called_once()

    def test_non_dict_payload(self, consumer, sink):
        consumer._record_terminal(None, ValueError("boom"), reason="malformed")

        kwargs = sink.produce.call_args.kwargs
        assert kwargs["tenant_id"] is None
        assert kwargs["provider_type"] is None


class TestReasons:
    """Each failure path labels its divert, so `dlq_diverted_total{reason}`
    says why events were lost."""

    def _run(self, consumer, side_effect, budget=None, retries=3):
        with patch.object(KafkaEventConsumer, "_record_terminal") as terminal:
            with patch.object(kafka_consumer, "MAX_PROCESSING_RETRIES", retries):
                with patch.object(kafka_consumer, "process_event_sync", side_effect=side_effect):
                    with patch.object(kafka_consumer, "_resolve_ingestion_tenant", return_value="t1"):
                        with patch.object(kafka_consumer.time, "sleep"):
                            consumer._process_with_retries(
                                MagicMock(),
                                budget or RetryBudget(max_poll_interval_ms=300000),
                                dict(PAYLOAD),
                            )
        terminal.assert_called_once()
        return terminal.call_args.kwargs["reason"]

    def test_poison(self, consumer):
        assert self._run(consumer, _http_error(400)) == "poison"

    def test_attempt_cap(self, consumer):
        assert self._run(consumer, _http_error(503)) == "attempt_cap"

    def test_budget_exhausted(self, consumer):
        clock = [0.0]
        budget = RetryBudget(
            max_poll_interval_ms=1000, safety_factor=0.8, clock=lambda: clock[0]
        )
        clock[0] = 1.0  # already past the 0.8s budget
        assert self._run(consumer, _http_error(503), budget=budget, retries=5) == "budget_exhausted"

    def test_malformed_json(self, consumer):
        msg = MagicMock()
        msg.value.return_value = b"not json"
        with patch.object(KafkaEventConsumer, "_record_terminal", return_value=True) as terminal:
            assert consumer._process_message(msg, RetryBudget(max_poll_interval_ms=300000)) is True
        assert terminal.call_args.kwargs["reason"] == "malformed"
        assert terminal.call_args.kwargs["payload"] == {"raw": "not json"}

    def test_invalid_payload_shape(self, consumer):
        msg = MagicMock()
        msg.value.return_value = b'{"event": "not-a-dict", "tenant_id": 1}'
        with patch.object(kafka_consumer, "EventDTO", side_effect=_validation_error()):
            with patch.object(KafkaEventConsumer, "_record_terminal") as terminal:
                consumer._process_message(msg, RetryBudget(max_poll_interval_ms=300000))
        assert terminal.call_args.kwargs["reason"] == "poison"


def _validation_error():
    from pydantic import BaseModel

    class Model(BaseModel):
        x: int

    try:
        Model(x="nope")
    except Exception as e:
        return e


class TestCommitDecision:
    """`_process_message` commits exactly when the terminal record was written."""

    def _message(self, value: bytes):
        msg = MagicMock()
        msg.value.return_value = value
        return msg

    @pytest.mark.parametrize("written", [True, False])
    def test_malformed(self, consumer, written):
        with patch.object(KafkaEventConsumer, "_record_terminal", return_value=written):
            result = consumer._process_message(
                self._message(b"not json"), RetryBudget(max_poll_interval_ms=300000)
            )
        assert result is written

    @pytest.mark.parametrize("written", [True, False])
    def test_retry_exhausted(self, consumer, written):
        msg = self._message(b'{"event": {"name": "x"}, "tenant_id": "t1"}')
        with patch.object(KafkaEventConsumer, "_record_terminal", return_value=written):
            with patch.object(kafka_consumer, "process_event_sync", side_effect=_http_error(503)):
                with patch.object(kafka_consumer, "_resolve_ingestion_tenant", return_value="t1"):
                    with patch.object(kafka_consumer, "MAX_PROCESSING_RETRIES", 1):
                        result = consumer._process_message(
                            msg, RetryBudget(max_poll_interval_ms=300000)
                        )
        assert result is written

    def test_success(self, consumer):
        msg = self._message(b'{"event": {"name": "x"}, "tenant_id": "t1"}')
        with patch.object(kafka_consumer, "process_event_sync"):
            with patch.object(kafka_consumer, "_resolve_ingestion_tenant", return_value="t1"):
                assert consumer._process_message(msg, RetryBudget(max_poll_interval_ms=300000)) is True


def test_failed_dlq_write_rewinds_and_pauses_the_partition(sink):
    """A terminal failure whose DLQ write fails goes down the same unresolved
    path as any other: rewound, paused with backoff, not committed."""
    sink.produce.return_value = False
    kafka = MagicMock()
    with patch.object(kafka_consumer, "Consumer", return_value=kafka):
        consumer = KafkaEventConsumer()
    consumer._consumer = kafka

    msg = MagicMock()
    msg.value.return_value = b"not json"  # malformed -> terminal right away
    msg.topic.return_value = "keep-events"
    msg.partition.return_value = 0
    msg.offset.return_value = 7

    consumer._process_batch([msg], RetryBudget(max_poll_interval_ms=300000))

    kafka.commit.assert_not_called()
    rewound = kafka.seek.call_args.args[0]
    assert (rewound.topic, rewound.partition, rewound.offset) == ("keep-events", 0, 7)
    kafka.pause.assert_called_once()
    assert ("keep-events", 0) in consumer._replay_due
