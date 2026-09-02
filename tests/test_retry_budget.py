"""
Tests for the batch-wide retry budget, poison-vs-transient classifier, and
terminal commit behavior in the Kafka consumer.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError
from requests.exceptions import HTTPError, Timeout
from sqlalchemy.exc import OperationalError

from src.bl.automations.producer import MatchedPublishError
from src.core.kafka_consumer import (
    KafkaEventConsumer,
    PoisonMessageError,
    RetryBudget,
    classify_error,
)


def _http_error(status_code: int) -> HTTPError:
    resp = MagicMock()
    resp.status_code = status_code
    return HTTPError(response=resp)


def _validation_error() -> ValidationError:
    class _M(BaseModel):
        x: int

    try:
        _M(x="not-an-int")
    except ValidationError as e:
        return e


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def test_classify_json_decode_error_is_poison():
    try:
        json.loads("{bad")
    except json.JSONDecodeError as e:
        assert classify_error(e) == "poison"


def test_classify_validation_error_is_poison():
    assert classify_error(_validation_error()) == "poison"


def test_classify_poison_message_error_is_poison():
    assert classify_error(PoisonMessageError("unknown event_type")) == "poison"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 499])
def test_classify_gateway_4xx_is_poison(status):
    assert classify_error(_http_error(status)) == "poison"


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_classify_gateway_5xx_is_transient(status):
    assert classify_error(_http_error(status)) == "transient"


def test_classify_db_operational_error_is_transient():
    assert classify_error(OperationalError("stmt", {}, Exception("locked"))) == "transient"


def test_classify_timeout_is_transient():
    assert classify_error(Timeout("gateway timed out")) == "transient"


def test_classify_unknown_defaults_to_transient():
    assert classify_error(RuntimeError("who knows")) == "transient"


# --------------------------------------------------------------------------- #
# RetryBudget
# --------------------------------------------------------------------------- #


def test_budget_exhausts_at_safety_factor_of_poll_interval():
    clock = [0.0]
    budget = RetryBudget(
        max_poll_interval_ms=10000,  # 10s
        safety_factor=0.8,           # budget = 8s
        max_sleep_seconds=30,
        clock=lambda: clock[0],
    )
    assert budget.exhausted() is False
    clock[0] = 7.9
    assert budget.exhausted() is False
    clock[0] = 8.1
    assert budget.exhausted() is True


def test_budget_sleep_is_capped_by_max_sleep():
    budget = RetryBudget(
        max_poll_interval_ms=10_000_000,  # huge, so budget isn't the limiter
        safety_factor=0.8,
        max_sleep_seconds=5,
    )
    with patch("src.core.kafka_consumer.time.sleep") as mock_sleep:
        slept = budget.sleep_for(attempt=10)  # 2**10 would be 1024s
        assert slept == 5  # capped
        mock_sleep.assert_called_once_with(5)


def test_budget_sleep_never_overruns_remaining():
    clock = [0.0]
    budget = RetryBudget(
        max_poll_interval_ms=10000,  # budget = 8s
        safety_factor=0.8,
        max_sleep_seconds=30,
        clock=lambda: clock[0],
    )
    clock[0] = 6.0  # 2s remaining
    with patch("src.core.kafka_consumer.time.sleep") as mock_sleep:
        slept = budget.sleep_for(attempt=3)  # 2**3 = 8s, but only 2s remain
        assert slept == 2.0
        mock_sleep.assert_called_once_with(2.0)


# --------------------------------------------------------------------------- #
# _process_with_retries terminal routing
# --------------------------------------------------------------------------- #


def _consumer():
    c = KafkaEventConsumer()
    return c


def test_poison_never_retries_and_records_terminal():
    consumer = _consumer()
    budget = RetryBudget(max_poll_interval_ms=300000)
    payload = {"tenant_id": "t1", "provider_type": "grafana"}

    with patch("src.core.kafka_consumer.MAX_PROCESSING_RETRIES", 3):
        with patch("src.core.kafka_consumer.process_event_sync") as mock_process:
            mock_process.side_effect = _http_error(400)  # poison
            with patch("src.core.kafka_consumer.record_terminal_error") as mock_terminal:
                consumer._process_with_retries(MagicMock(), budget, payload)

    # Poison: tried exactly once, no retry.
    assert mock_process.call_count == 1
    mock_terminal.assert_called_once()


def test_transient_retries_then_terminal_at_cap():
    consumer = _consumer()
    budget = RetryBudget(max_poll_interval_ms=300000)
    payload = {"tenant_id": "t1", "provider_type": "grafana"}

    with patch("src.core.kafka_consumer.MAX_PROCESSING_RETRIES", 3):
        with patch("src.core.kafka_consumer.process_event_sync") as mock_process:
            mock_process.side_effect = _http_error(503)  # transient
            with patch("src.core.kafka_consumer.record_terminal_error") as mock_terminal:
                with patch("src.core.kafka_consumer.time.sleep"):
                    consumer._process_with_retries(MagicMock(), budget, payload)

    # Transient: retried up to the cap, then recorded terminal.
    assert mock_process.call_count == 3
    mock_terminal.assert_called_once()


def test_budget_exhaustion_routes_to_terminal_not_another_retry():
    consumer = _consumer()
    payload = {"tenant_id": "t1", "provider_type": "grafana"}

    # Budget already exhausted at the time of the first failure.
    clock = [0.0]
    budget = RetryBudget(
        max_poll_interval_ms=1000,  # budget = 0.8s
        safety_factor=0.8,
        clock=lambda: clock[0],
    )

    with patch("src.core.kafka_consumer.MAX_PROCESSING_RETRIES", 5):
        with patch("src.core.kafka_consumer.process_event_sync") as mock_process:
            mock_process.side_effect = _http_error(503)  # transient
            with patch("src.core.kafka_consumer.record_terminal_error") as mock_terminal:
                with patch("src.core.kafka_consumer.time.sleep") as mock_sleep:
                    clock[0] = 1.0  # past the 0.8s budget
                    consumer._process_with_retries(MagicMock(), budget, payload)

    # First failure -> budget exhausted -> terminal, NOT another attempt.
    assert mock_process.call_count == 1
    mock_sleep.assert_not_called()
    mock_terminal.assert_called_once()


def test_success_does_not_record_terminal():
    consumer = _consumer()
    budget = RetryBudget(max_poll_interval_ms=300000)
    payload = {"tenant_id": "t1", "provider_type": "grafana"}

    with patch("src.core.kafka_consumer.process_event_sync") as mock_process:
        mock_process.return_value = None
        with patch("src.core.kafka_consumer.record_terminal_error") as mock_terminal:
            consumer._process_with_retries(MagicMock(), budget, payload)

    assert mock_process.call_count == 1
    mock_terminal.assert_not_called()


def test_matched_publish_exhaustion_is_unresolved_not_terminal():
    consumer = KafkaEventConsumer()
    budget = RetryBudget(300000, max_sleep_seconds=0)
    payload = {"tenant_id": "t1"}
    with patch(
        "src.core.kafka_consumer.process_event_sync",
        side_effect=MatchedPublishError("broker unavailable"),
    ), patch("src.core.kafka_consumer.record_terminal_error") as terminal:
        resolved = consumer._process_with_retries(MagicMock(), budget, payload)

    assert resolved is False
    terminal.assert_not_called()
