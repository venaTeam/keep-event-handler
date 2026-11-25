import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from src.core.kafka_consumer import KafkaEventConsumer, RetryBudget
from src.core.tenant_resolution import GENERIC_TENANT_UUID
from src.logging_conf import (
    CONFIG,
    LogContextFilter,
    reset_log_context,
    set_log_context,
)


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def captured():
    handler = _ListHandler()
    handler.addFilter(LogContextFilter())
    logger = logging.getLogger("test.log_context")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    yield logger, handler.records
    logger.removeHandler(handler)


def _kafka_msg(payload):
    msg = MagicMock()
    msg.value.return_value = json.dumps(payload).encode("utf-8")
    msg.topic.return_value = "keep-events"
    msg.partition.return_value = 0
    msg.offset.return_value = 0
    return msg


def test_filter_is_attached_to_default_handler():
    assert "log_context" in CONFIG["handlers"]["default"]["filters"]


def test_logs_inside_event_get_context(captured):
    logger, records = captured

    def fake_process(event_dto):
        logger.info("inside event")

    with patch("src.core.kafka_consumer.Consumer"), patch(
        "src.core.kafka_consumer.process_event_sync", side_effect=fake_process
    ):
        consumer = KafkaEventConsumer()
        consumer._process_message(
            _kafka_msg({"trace_id": "trace-1", "tenant_id": "tenant-1", "event": {}}),
            RetryBudget(max_poll_interval_ms=300000),
        )

    record = next(r for r in records if r.getMessage() == "inside event")
    # No operator in the event, so it is routed to the general tenant
    assert record.tenant_id == GENERIC_TENANT_UUID
    assert record.trace_id == "trace-1"

    # Context is reset once the event is done
    logger.info("after event")
    assert not hasattr(records[-1], "tenant_id")
    assert not hasattr(records[-1], "trace_id")


def test_explicit_extra_wins(captured):
    logger, records = captured
    tokens = set_log_context("ctx-tenant", "ctx-trace")
    try:
        logger.info("explicit", extra={"tenant_id": "explicit-tenant"})
    finally:
        reset_log_context(tokens)

    assert records[-1].tenant_id == "explicit-tenant"
    assert records[-1].trace_id == "ctx-trace"


def test_outside_event_no_crash(captured):
    logger, records = captured
    logger.info("no context")
    assert records[-1].getMessage() == "no context"
    assert not hasattr(records[-1], "tenant_id")
    assert not hasattr(records[-1], "trace_id")
