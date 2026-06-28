"""
Baseline test: with default (safe) config the consumer behaves exactly as the
current origin/dev baseline does.

Two properties are locked in here so later hardening subtasks can't silently
change default behavior:

1. Single-message poll -> process -> commit. At default KAFKA_CONSUMER_BATCH_SIZE
   the consume loop processes one message per poll and commits its offset after
   successful processing.

2. The notify path is the post-PR-#13 *async* baseline, NOT a serial inline
   path: _submit_notify hands work to a background pool and returns immediately;
   the notification is actually delivered once the pool is flushed.

These are unit-level (the confluent Consumer / poll / commit are mocked); no
docker / Kafka / Postgres is required.
"""
import json
import time
from unittest.mock import MagicMock, patch

from src.core.kafka_consumer import KafkaEventConsumer


def test_default_config_single_message_poll_process_commit():
    """Default config: exactly one process call and one commit for one message."""
    mock_msg = MagicMock()
    mock_msg.value.return_value = json.dumps(
        {
            "trace_id": "baseline-trace",
            "tenant_id": "test-tenant",
            "event": {"data": "test"},
        }
    ).encode("utf-8")
    mock_msg.error.return_value = None
    mock_msg.topic.return_value = "keep-events"
    mock_msg.partition.return_value = 0
    mock_msg.offset.return_value = 0

    mock_consumer_instance = MagicMock()
    consume_returns = [[mock_msg], []]
    consume_call_count = [0]

    def consume_side_effect(num_messages=1, timeout=None):
        idx = consume_call_count[0]
        result = consume_returns[idx] if idx < len(consume_returns) else []
        consume_call_count[0] += 1
        if consume_call_count[0] >= len(consume_returns):
            consumer._running = False
        return result

    mock_consumer_instance.consume.side_effect = consume_side_effect

    with patch("src.core.kafka_consumer.Consumer", return_value=mock_consumer_instance):
        with patch("src.core.kafka_consumer.process_event_sync") as mock_process:
            consumer = KafkaEventConsumer()
            consumer._consumer = mock_consumer_instance
            consumer._running = True

            consumer._consume_loop()

            # Exactly one event processed, exactly one offset committed.
            mock_process.assert_called_once()
            mock_consumer_instance.commit.assert_called_once_with(
                mock_msg, asynchronous=False
            )


def test_notify_baseline_is_async_and_still_delivers(notify_pool):
    """The default notify path is async (PR #13): submit returns immediately,
    delivery happens on flush. This is the baseline, not a serial inline path."""
    pet = notify_pool
    call_count = [0]

    def slow_post(*args, **kwargs):
        time.sleep(0.3)
        call_count[0] += 1
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        return resp

    with patch.object(pet._sse_session, "post", side_effect=slow_post) as mock_post:
        start = time.monotonic()
        pet._submit_notify(
            "http://localhost:8080", "t1", "poll-alerts", {"alerts": []}
        )
        pet._submit_notify(
            "http://localhost:8080", "t1", "incident-change", {"incident_ids": ["1"]}
        )
        elapsed = time.monotonic() - start

        # Non-blocking: nowhere near 2 * 0.3s.
        assert elapsed < 0.1, f"submission blocked the caller for {elapsed:.3f}s"

        # Flushing the pool delivers all queued notifications.
        pet.shutdown_sse_pool(wait=True)
        assert mock_post.call_count == 2
        assert call_count[0] == 2
