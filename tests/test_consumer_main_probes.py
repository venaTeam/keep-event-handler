"""Probe-server tests: what each path answers, and the startup ordering that
makes the probes reachable during a slow boot.
"""
import json
import urllib.error
import urllib.request

import pytest

from src import consumer_main
from src.core.consumer_health import ConsumerPhase, consumer_health


class FakePartition:
    def __init__(self, topic="keep-events", partition=0):
        self.topic = topic
        self.partition = partition


@pytest.fixture
def probe_server():
    """Real HTTPServer on an ephemeral port — the handler is the unit here."""
    consumer_health.reset_for_tests()
    server = consumer_main.create_health_server(0)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    consumer_health.reset_for_tests()


def get(base: str, path: str):
    try:
        with urllib.request.urlopen(base + path, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def become_consuming():
    consumer_health.set_phase(ConsumerPhase.CONSUMING)
    consumer_health.set_assignment([FakePartition()])
    consumer_health.mark_poll()


# -- routing ------------------------------------------------------------


@pytest.mark.parametrize("path", ["/livez", "/", "/health", "/healthz"])
def test_legacy_aliases_are_liveness(probe_server, path):
    """Production probes target `/`. If these 404'd, landing this image would
    kill every consumer pod with no chart change to revert."""
    status, body = get(probe_server, path)

    assert status == 200
    assert body["probe"] == "liveness"


@pytest.mark.parametrize("path", ["/readyz", "/ready"])
def test_readiness_paths(probe_server, path):
    become_consuming()

    status, body = get(probe_server, path)

    assert status == 200
    assert body["probe"] == "readiness"


def test_unknown_path_still_404s(probe_server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(probe_server + "/nope", timeout=5)

    assert exc.value.code == 404


def test_query_string_is_ignored(probe_server):
    status, body = get(probe_server, "/livez?probe=1")

    assert status == 200
    assert body["probe"] == "liveness"


# -- semantics ----------------------------------------------------------


def test_booting_pod_is_live_but_not_ready(probe_server):
    """The whole reason the server binds before init_services()."""
    live_status, _ = get(probe_server, "/livez")
    ready_status, ready_body = get(probe_server, "/readyz")

    assert live_status == 200
    assert ready_status == 503
    assert ready_body["status"] == "unhealthy"
    assert ready_body["phase"] == "starting"


def test_ready_once_consuming(probe_server):
    become_consuming()

    status, body = get(probe_server, "/readyz")

    assert status == 200
    assert body["partitions"] == 1


def test_readiness_body_carries_the_reason(probe_server):
    consumer_health.set_phase(ConsumerPhase.CONSUMING)
    consumer_health.mark_poll()  # no partitions

    status, body = get(probe_server, "/readyz")

    assert status == 503
    assert body["reason"] == "no partitions assigned"


# -- startup ordering ---------------------------------------------------


def test_probe_server_binds_before_init_services(monkeypatch):
    """Regression guard for the CrashLoop: init_services() blocks on the schema
    wait, so anything bound after it is unreachable for that whole window."""
    calls = []

    monkeypatch.setattr(
        consumer_main, "start_metrics_server", lambda port: calls.append("metrics")
    )
    monkeypatch.setattr(
        consumer_main, "create_health_server", lambda port: calls.append("health")
    )
    monkeypatch.setattr(
        consumer_main, "init_services", lambda: calls.append("init_services")
    )
    monkeypatch.setattr(
        consumer_main, "_start_trigger_index_safely", lambda: calls.append("index")
    )
    monkeypatch.setattr(
        consumer_main, "_stop_trigger_index_safely", lambda: calls.append("index_stop")
    )

    import src.core.kafka_consumer as kafka_consumer_module

    class FakeConsumer:
        def start(self):
            calls.append("consume")

    monkeypatch.setattr(kafka_consumer_module, "KafkaEventConsumer", FakeConsumer)

    import src.event_management.process_event_task as process_event_task

    monkeypatch.setattr(process_event_task, "shutdown_sse_pool", lambda wait: None)

    consumer_main.main()

    assert calls.index("health") < calls.index("init_services")
    assert calls.index("metrics") < calls.index("init_services")
    # Hydration reads the shared schema, so the index still starts after init,
    # and the consume loop is last.
    assert calls.index("init_services") < calls.index("index") < calls.index("consume")
