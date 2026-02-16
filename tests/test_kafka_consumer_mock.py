import json
from unittest.mock import MagicMock, patch, call
from core.kafka_consumer import KafkaEventConsumer


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

    with patch("keep.event_handler.core.kafka_consumer.Consumer", return_value=mock_consumer_instance):
        with patch("keep.event_handler.core.kafka_consumer.process_event_sync") as mock_process:
            consumer = KafkaEventConsumer()
            consumer._consumer = mock_consumer_instance
            consumer._running = True

            # Run the consume loop
            consumer._consume_loop()

            # Assertions
            mock_process.assert_called_once()
            mock_consumer_instance.commit.assert_called_once()


def test_consume_loop_retries_and_raises():
    """
    Verify that if process_event_sync fails continuously:
    1. It retries MAX_PROCESSING_RETRIES times.
    2. It does NOT commit.
    3. The error is propagated (but consume loop catches it and continues).
    """
    mock_msg = MagicMock()
    mock_msg.value.return_value = json.dumps({
        "trace_id": "fail-trace",
        "tenant_id": "test-tenant",
        "event": {"data": "fail"}
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

    with patch("keep.event_handler.core.kafka_consumer.Consumer", return_value=mock_consumer_instance):
        with patch("keep.event_handler.core.kafka_consumer.process_event_sync") as mock_process:
            # Configure process_event_sync to always fail
            mock_process.side_effect = Exception("Processing Error")

            with patch("keep.event_handler.core.kafka_consumer.MAX_PROCESSING_RETRIES", 3):
                consumer = KafkaEventConsumer()
                consumer._consumer = mock_consumer_instance
                consumer._running = True

                # The consume loop should catch the error and continue
                # (it logs the error and doesn't commit)
                consumer._consume_loop()

                # Assertions
                # Should have 3 retry attempts (MAX_PROCESSING_RETRIES)
                assert mock_process.call_count == 3
                # Should NOT commit because processing failed
                mock_consumer_instance.commit.assert_not_called()


def test_process_with_retries_success_on_second_attempt():
    """
    Verify that _process_with_retries succeeds if processing succeeds on retry.
    """
    with patch("keep.event_handler.core.kafka_consumer.process_event_sync") as mock_process:
        with patch("keep.event_handler.core.kafka_consumer.time.sleep"):  # Speed up test
            # Fail first, succeed second
            mock_process.side_effect = [Exception("Transient Error"), None]

            consumer = KafkaEventConsumer()
            mock_event_dto = MagicMock()

            # Should not raise
            consumer._process_with_retries(mock_event_dto)

            # Should have been called twice
            assert mock_process.call_count == 2


def test_process_message_json_decode_error():
    """
    Verify that malformed JSON messages are handled gracefully.
    """
    mock_msg = MagicMock()
    mock_msg.value.return_value = b"not valid json"

    consumer = KafkaEventConsumer()

    with patch("keep.event_handler.core.kafka_consumer.events_error_counter") as mock_error_counter:
        # Should not raise - allows commit to avoid getting stuck
        consumer._process_message(mock_msg)
        mock_error_counter.inc.assert_called_once()
