"""
DLQ envelope contract test (dlq-replay.md Phase 2).

keep-ingestions' _send_to_dlq and this service's produce_to_dlq are two
producers of the same topic (KAFKA_DLQ_TOPIC), consumed by keep-reconciler.
The reconciler's contract is:
  - payload["alert"] is POSTed to POST {KEEP_URL}/alerts/event
  - payload["error"] carries a message
  - Unknown top-level fields are ignored — so the two producers may differ in
    debug metadata, but both must satisfy payload["alert"].

The other two services live in separate repos, so their side of the contract
is pinned here as literals. Update them together with those services.

Replay ordering is covered here too: a replayed alert is older than what
already landed, and must not become the current state.
"""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.core import dlq_producer
from src.core.db.db import _last_alert_is_newer

# keep-ingestion: src/services/producers/kafka_producer.py::_send_to_dlq
INGESTION_ENVELOPE_KEYS = {
    "alert",
    "event_type",
    "error",
    "tenant_id",
    "provider_type",
    "provider_id",
    "fingerprint",
    "api_key_name",
    "provider_name",
}


def reconciler_extract(payload: dict):
    """keep-reconciler: src/kafka_consumer.py::_extract_alert."""
    alert = payload.get("alert") or payload.get("event") or payload
    error = payload.get("error") or {}
    return alert, error


@pytest.fixture
def produced():
    dlq_producer._producer = None
    fake = MagicMock()
    fake.flush.return_value = 0
    with patch.object(dlq_producer, "Producer", return_value=fake):
        yield lambda: json.loads(fake.produce.call_args.kwargs["value"])
    dlq_producer._producer = None


def test_reconciler_gets_the_inner_event_and_error(produced):
    event = {"name": "cpu high", "status": "firing", "fingerprint": "fp-1"}
    payload = {"event": event, "tenant_id": "t1", "trace_id": "tr-1"}

    assert dlq_producer.produce_to_dlq(payload, ValueError("boom"), tenant_id="t1")

    alert, error = reconciler_extract(produced())
    assert alert == event
    assert error["message"] == "ValueError: boom"


def test_handler_envelope_covers_the_ingestion_envelope(produced):
    dlq_producer.produce_to_dlq({"event": {"a": 1}}, ValueError("x"))

    # Same routing fields as ingestion, so the reconciler sees one shape;
    # anything extra is debug metadata it ignores.
    assert INGESTION_ENVELOPE_KEYS <= set(produced())


def test_alert_is_always_an_object(produced):
    """The reconciler skips a non-object alert as undecodable."""
    dlq_producer.produce_to_dlq({"event": "just a string"}, ValueError("x"))

    alert, _ = reconciler_extract(produced())
    assert isinstance(alert, dict)


def test_batch_reaches_the_reconciler_as_a_list(produced):
    batch = [{"fingerprint": "a"}, {"fingerprint": "b"}]
    dlq_producer.produce_to_dlq({"event": batch}, ValueError("x"))

    alert, _ = reconciler_extract(produced())
    assert alert == batch


def test_replay_count_survives_the_round_trip(produced):
    """keep-ingestion puts the reconciler's replay number on the main-topic
    message; it must come back out on the DLQ so the reconciler can stop."""
    dlq_producer.produce_to_dlq(
        {"event": {"a": 1}, "dlq_replay_count": 4}, ValueError("x")
    )
    assert produced()["dlq_replay_count"] == 4


class TestReplayOrdering:
    NOW = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)

    def stored(self, last_received):
        return SimpleNamespace(last_received=last_received)

    def test_older_replay_is_stale(self):
        stored = self.stored(self.NOW)
        assert _last_alert_is_newer(stored, {"last_received": self.NOW - timedelta(minutes=5)})

    def test_same_time_still_applies(self):
        """A resolve stamped with its firing's time must not be dropped."""
        stored = self.stored(self.NOW)
        assert not _last_alert_is_newer(stored, {"last_received": self.NOW})

    def test_newer_occurrence_is_applied(self):
        stored = self.stored(self.NOW)
        assert not _last_alert_is_newer(stored, {"last_received": self.NOW + timedelta(seconds=1)})

    def test_iso_string_is_parsed(self):
        stored = self.stored(self.NOW)
        assert _last_alert_is_newer(stored, {"last_received": "2024-01-01T11:00:00Z"})

    def test_missing_values_never_drop(self):
        assert not _last_alert_is_newer(self.stored(None), {"last_received": self.NOW})
        assert not _last_alert_is_newer(self.stored(self.NOW), {})
