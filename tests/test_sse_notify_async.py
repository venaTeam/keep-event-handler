import time
from unittest.mock import MagicMock, patch

import event_management.process_event_task as pet


def test_submit_notify_is_non_blocking_and_still_delivers():
    """
    Issue #28: SSE notifications must not block the Kafka consumer thread.

    We patch the shared session's post() with a slow (0.5s) side effect. If
    _submit_notify were synchronous, three calls would take >= 1.5s. Because
    submission is offloaded to a background pool, the three submits must return
    in well under that time. After shutdown_sse_pool(wait=True) flushes the
    queue, all three notifications must have actually been delivered.
    """
    call_count = [0]

    def slow_post(*args, **kwargs):
        time.sleep(0.5)
        call_count[0] += 1
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        return resp

    with patch.object(pet._sse_session, "post", side_effect=slow_post) as mock_post:
        start = time.monotonic()
        pet._submit_notify("http://localhost:8080", "t1", "poll-alerts", {"alerts": []})
        pet._submit_notify(
            "http://localhost:8080", "t1", "incident-change", {"incident_ids": ["1"]}
        )
        pet._submit_notify(
            "http://localhost:8080", "t1", "poll-presets", {"preset_names": ["p"]}
        )
        elapsed = time.monotonic() - start

        # Submission must be non-blocking: nowhere near 3 * 0.5s.
        assert elapsed < 0.1, f"submission blocked the caller for {elapsed:.3f}s"

        # Flush the background pool so pending notifications are delivered.
        pet.shutdown_sse_pool(wait=True)

        # All three notifications were actually sent.
        assert mock_post.call_count == 3
        assert call_count[0] == 3
