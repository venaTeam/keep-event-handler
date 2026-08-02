"""
Tests for the probe HTTP endpoints served by the consumer entrypoint.

The old handler returned 200 for every path, which made the readiness probe a
lie and the liveness probe a check that the HTTP daemon thread was alive. These
tests pin the real contract: exactly two endpoints, /readyz reflecting "actually
consuming" and /livez the consume-loop heartbeat, with everything else a 404.
"""

import json
import socket
import urllib.error
import urllib.request

import pytest

from src import consumer_main
from src.consumer_main import create_health_server
from src.core.consumer_health import ConsumerHealth


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def probe_server(monkeypatch):
    """A live health server on a random port, backed by a fresh health object so
    tests don't inherit each other's phase/assignment state."""
    health = ConsumerHealth()
    # create_health_server resolves this global when called, so patch it here
    # rather than on src.core.consumer_health.
    monkeypatch.setattr(consumer_main, "consumer_health", health)

    port = _free_port()
    server = create_health_server(port)
    try:
        yield f"http://127.0.0.1:{port}", health
    finally:
        server.shutdown()
        server.server_close()


def _get(base: str, path: str):
    try:
        with urllib.request.urlopen(base + path, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def test_readyz_is_503_during_startup(probe_server):
    """The pod answers honestly while blocked in init_services (schema wait)
    instead of refusing connections — connection-refused for the whole boot is
    what let the ~90 s liveness probe kill booting pods."""
    base, _ = probe_server
    status, body = _get(base, "/readyz")
    assert status == 503
    assert body["status"] == "unavailable"
    assert body["phase"] == "starting"


def test_livez_is_200_during_startup(probe_server):
    base, _ = probe_server
    status, body = _get(base, "/livez")
    assert status == 200
    assert body["status"] == "ok"


def test_readyz_turns_200_once_assigned_and_polling(probe_server):
    base, health = probe_server
    health.mark_consuming()
    health.set_assignment([0, 1])
    health.record_poll()

    status, body = _get(base, "/readyz")
    assert status == 200
    assert body["assigned_partitions"] == [0, 1]


def test_readyz_503_when_consuming_without_assignment(probe_server):
    base, health = probe_server
    health.mark_consuming()
    health.record_poll()

    status, body = _get(base, "/readyz")
    assert status == 503
    assert "no partitions assigned" in body["reason"]


@pytest.mark.parametrize("path", ["/", "/health", "/healthz", "/ready", "/nope"])
def test_only_the_two_probe_paths_are_served(probe_server, path):
    """No aliases: a probe aimed at the wrong path must fail loudly rather than
    get a meaningless 200 back."""
    base, _ = probe_server
    try:
        with urllib.request.urlopen(base + path, timeout=5) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 404


def test_query_string_and_trailing_slash_are_tolerated(probe_server):
    base, health = probe_server
    health.mark_consuming()
    health.set_assignment([2])
    health.record_poll()

    assert _get(base, "/readyz/")[0] == 200
    assert _get(base, "/readyz?probe=k8s")[0] == 200
