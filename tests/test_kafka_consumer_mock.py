import json
from unittest.mock import MagicMock, patch, call
from src.core.kafka_consumer import KafkaEventConsumer, RetryBudget


def test_consume_loop_success_commits():
    """
    Verify that if process_event_sync succeeds, commit() is called.
    """
    # Create a mock message
    mock_msg = MagicMock()
    mock_msg.value.return_value = json.dumps({
        "trace_id": "test-trace",
        "tenant_id": "test-tenant",
        "event": {"data": "test"}
    }).encode("utf-8")
    mock_msg.error.return_value = None

    # Create a mock consumer that returns one message then None (to exit loop)
    mock_consumer_instance = MagicMock()
    poll_returns = [mock_msg, None]
    poll_call_count = [0]

    def poll_side_effect(timeout=None):
        result = poll_returns[poll_call_count[0]] if poll_call_count[0] < len(poll_returns) else None
        poll_call_count[0] += 1
        # Stop the consumer after processing the message
        if poll_call_count[0] >= len(poll_returns):
            consumer._running = False
        return result

    mock_consumer_instance.poll.side_effect = poll_side_effect
    mock_consumer_instance.commit = MagicMock()

    with patch("src.core.kafka_consumer.Consumer", return_value=mock_consumer_instance):
        with patch("src.core.kafka_consumer.process_event_sync") as mock_process:
            consumer = KafkaEventConsumer()
            consumer._consumer = mock_consumer_instance
            consumer._running = True

            # Run the consume loop
            consumer._consume_loop()

            # Assertions
            mock_process.assert_called_once()
            mock_consumer_instance.commit.assert_called_once()


def test_consume_loop_retries_then_terminal_commit():
    """
    New behavior: a message that always fails with a transient error is retried
    MAX_PROCESSING_RETRIES times, then recorded via the terminal sink and the
    offset COMMITTED (replacing the old re-raise-forever behavior that froze the
    partition).
    """
    mock_msg = MagicMock()
    mock_msg.value.return_value = json.dumps({
        "trace_id": "fail-trace",
        "tenant_id": "test-tenant",
        "event": {"data": "fail"},
        "provider_type": "grafana",
    }).encode("utf-8")
    mock_msg.error.return_value = None

    mock_consumer_instance = MagicMock()
    poll_returns = [mock_msg, None]
    poll_call_count = [0]

    def poll_side_effect(timeout=None):
        result = poll_returns[poll_call_count[0]] if poll_call_count[0] < len(poll_returns) else None
        poll_call_count[0] += 1
        if poll_call_count[0] >= len(poll_returns):
            consumer._running = False
        return result

    mock_consumer_instance.poll.side_effect = poll_side_effect
    mock_consumer_instance.commit = MagicMock()

    with patch("src.core.kafka_consumer.Consumer", return_value=mock_consumer_instance):
        with patch("src.core.kafka_consumer.process_event_sync") as mock_process:
            # Always fail with a generic (transient-classified) error.
            mock_process.side_effect = Exception("Processing Error")

            with patch("src.core.kafka_consumer.MAX_PROCESSING_RETRIES", 3):
                with patch("src.core.kafka_consumer.record_terminal_error") as mock_terminal:
                    with patch("src.core.kafka_consumer.time.sleep"):
                        consumer = KafkaEventConsumer()
                        consumer._consumer = mock_consumer_instance
                        consumer._running = True

                        consumer._consume_loop()

                        # Retried up to the attempt cap.
                        assert mock_process.call_count == 3
                        # Terminal sink recorded the poison/exhausted message.
                        mock_terminal.assert_called_once()
                        # And the offset WAS committed (no partition freeze).
                        mock_consumer_instance.commit.assert_called_once()


def test_process_with_retries_success_on_second_attempt():
    """
    Verify that _process_with_retries succeeds if processing succeeds on retry.
    """
    with patch("src.core.kafka_consumer.process_event_sync") as mock_process:
        with patch("src.core.kafka_consumer.time.sleep"):  # Speed up test
            # Fail first, succeed second
            mock_process.side_effect = [Exception("Transient Error"), None]

            consumer = KafkaEventConsumer()
            mock_event_dto = MagicMock()
            budget = RetryBudget(max_poll_interval_ms=300000)

            # Should not raise
            consumer._process_with_retries(mock_event_dto, budget, {"tenant_id": "t1"})

            # Should have been called twice
            assert mock_process.call_count == 2


def test_process_message_json_decode_error():
    """
    Verify that malformed JSON messages are handled gracefully: recorded as
    terminal and committed (returns True), not re-raised.
    """
    mock_msg = MagicMock()
    mock_msg.value.return_value = b"not valid json"

    consumer = KafkaEventConsumer()
    budget = RetryBudget(max_poll_interval_ms=300000)

    with patch("src.core.kafka_consumer.events_error_counter") as mock_error_counter:
        with patch("src.core.kafka_consumer.record_terminal_error") as mock_terminal:
            # Should not raise - returns True (commit past malformed message).
            result = consumer._process_message(mock_msg, budget)
            assert result is True
            mock_error_counter.inc.assert_called_once()
            mock_terminal.assert_called_once()
