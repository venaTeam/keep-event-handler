import threading
import time
from unittest.mock import MagicMock, patch

import src.event_management.process_event_task as pet


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


def test_coalescing_collapses_duplicate_tenant_event_notifications(notify_pool):
    """
    With coalescing enabled and a single worker, while the first poll-alerts
    delivery is in flight, many further poll-alerts submits for the same
    (tenant, event) collapse to a single pending payload — so total deliveries
    are far fewer than submissions, and the LAST payload wins (refresh-style).
    """
    pet = notify_pool
    delivered = []
    release = threading.Event()
    first_in_flight = threading.Event()

    def post(url, json=None, timeout=None, headers=None):
        # Hold the very first delivery so duplicates pile up behind it.
        if not first_in_flight.is_set():
            first_in_flight.set()
            release.wait(timeout=5)
        delivered.append(json["data"])
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        return resp

    assert pet._SSE_COALESCE_ENABLED is True

    with patch.object(pet._sse_session, "post", side_effect=post):
        # First submit starts a worker that blocks in post().
        pet._submit_notify("http://localhost:8080", "t1", "poll-alerts", {"n": 0})
        assert first_in_flight.wait(timeout=5)

        # Many duplicate (t1, poll-alerts) submits while the worker is busy.
        for i in range(1, 51):
            pet._submit_notify("http://localhost:8080", "t1", "poll-alerts", {"n": i})

        # Release the in-flight delivery and drain.
        release.set()
        pet.shutdown_sse_pool(wait=True)

    # 51 submissions, but coalesced to at most 2 deliveries (the first in-flight
    # one + one collapsed delivery of the latest payload).
    assert len(delivered) <= 2
    assert len(delivered) >= 1
    # The collapsed delivery carried the LATEST payload (refresh-style).
    assert delivered[-1] == {"n": 50}


def test_distinct_keys_are_not_coalesced(notify_pool):
    """Different (tenant, event) keys are independent — each is delivered."""
    pet = notify_pool
    delivered = []

    def post(url, json=None, timeout=None, headers=None):
        delivered.append((json.get("tenant_id"), json.get("event")))
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        return resp

    with patch.object(pet._sse_session, "post", side_effect=post):
        pet._submit_notify("http://localhost:8080", "t1", "poll-alerts", {})
        pet._submit_notify("http://localhost:8080", "t2", "poll-alerts", {})
        pet._submit_notify("http://localhost:8080", "t1", "poll-presets", {})
        pet.shutdown_sse_pool(wait=True)

    assert set(delivered) == {
        ("t1", "poll-alerts"),
        ("t2", "poll-alerts"),
        ("t1", "poll-presets"),
    }


def test_coalescing_merges_alert_lists_no_data_loss(notify_pool):
    """poll-alerts payloads carry {"alerts": [...]} that the UI injects into its
    cache WITHOUT a refetch, so coalescing must MERGE the alert lists, not drop
    intermediate ones. While the first delivery is in flight, submit several
    poll-alerts each carrying a distinct alert; the single collapsed delivery
    must contain EVERY alert (de-duped by fingerprint), not just the latest."""
    pet = notify_pool
    delivered = []
    release = threading.Event()
    first_in_flight = threading.Event()

    def post(url, json=None, timeout=None, headers=None):
        if not first_in_flight.is_set():
            first_in_flight.set()
            release.wait(timeout=5)
        delivered.append(json["data"])
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        return resp

    with patch.object(pet._sse_session, "post", side_effect=post):
        # First submit (fingerprint fp0) starts a worker that blocks in post().
        pet._submit_notify(
            "http://localhost:8080", "t1", "poll-alerts",
            {"alerts": [{"fingerprint": "fp0"}]},
        )
        assert first_in_flight.wait(timeout=5)

        # More poll-alerts pile up behind the in-flight delivery and coalesce.
        for i in range(1, 6):
            pet._submit_notify(
                "http://localhost:8080", "t1", "poll-alerts",
                {"alerts": [{"fingerprint": f"fp{i}"}]},
            )
        # A duplicate fingerprint must NOT double up (de-dup by fingerprint).
        pet._submit_notify(
            "http://localhost:8080", "t1", "poll-alerts",
            {"alerts": [{"fingerprint": "fp3"}]},
        )

        release.set()
        pet.shutdown_sse_pool(wait=True)

    # Every distinct fingerprint survived the collapse — no data loss.
    all_fps = {a["fingerprint"] for payload in delivered for a in payload["alerts"]}
    assert all_fps == {"fp0", "fp1", "fp2", "fp3", "fp4", "fp5"}
    # And the duplicate fingerprint appears exactly once across the merged payloads.
    merged_count = sum(
        1 for payload in delivered for a in payload["alerts"] if a["fingerprint"] == "fp3"
    )
    assert merged_count == 1


def test_notify_client_submits_only_poll_alerts_and_incident_change():
    """A processed batch notifies `poll-alerts`, plus `incident-change` when incidents
    were touched, and nothing else: no preset filtering is queued and no other
    event is sent, because the UI only reacts to those two."""
    captured = []
    pool = MagicMock()
    cache = MagicMock()
    cache.should_notify.return_value = True
    incident = MagicMock()
    incident.id = "i1"
    with patch.object(pet, "_submit_notify", side_effect=lambda *a: captured.append(a)), \
        patch.object(pet, "_sse_pool", pool):
        pet._notify_client(
            "http://localhost:8080", "t1", [{"fingerprint": "fp0"}], [incident], cache
        )

    assert [(event, data) for _, _, event, data in captured] == [
        ("poll-alerts", {"alerts": [{"fingerprint": "fp0"}]}),
        ("incident-change", {"incident_ids": ["i1"]}),
    ]
    pool.submit.assert_not_called()


def test_notify_sends_the_configured_token_header(monkeypatch):
    """The gateway's notify route can require a shared token; every
    notification must carry the configured header."""
    monkeypatch.setattr(pet, "SSE_NOTIFY_HEADERS", {"X-Keep-Notify-Token": "s3cret"})
    with patch.object(pet._sse_session, "post") as mock_post:
        pet._notify_api("http://localhost:8080", "t1", "poll-alerts", {})
    assert mock_post.call_args.kwargs["headers"] == {"X-Keep-Notify-Token": "s3cret"}
