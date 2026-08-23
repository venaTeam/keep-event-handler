"""Probe-server tests: what each path answers, and the startup ordering that
makes the probes reachable during a slow boot.
"""
import json
import threading
import urllib.error
import urllib.request
from unittest.mock import MagicMock

import pytest

from src import consumer_main
from src.bl.automations import producer as producer_module
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


@pytest.mark.parametrize("path", ["/livez", "/", "/health", "/healthz", "/ready"])
def test_legacy_aliases_are_liveness(probe_server, path):
    """Production probes target `/`. If these 404'd, landing this image would
    kill every consumer pod with no chart change to revert."""
    status, body = get(probe_server, path)

    assert status == 200
    assert body["probe"] == "liveness"


def test_legacy_ready_alias_keeps_its_always_200_meaning(probe_server):
    """`/ready` answered an unconditional 200 before this change. If an
    existing probe -- especially liveness -- points at it, giving it real
    readiness semantics would kill every pod during the schema wait on an
    image-only deploy."""
    status, body = get(probe_server, "/ready")  # still 'starting'

    assert status == 200
    assert body["phase"] == "starting"


def test_readiness_is_readyz_only(probe_server):
    become_consuming()

    status, body = get(probe_server, "/readyz")

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


def test_unhealthy_matched_producer_gates_readyz(probe_server, monkeypatch):
    become_consuming()
    fake = MagicMock()
    fake.health.return_value = (False, "producer unavailable")
    monkeypatch.setattr(producer_module, "_producer", fake)

    status, body = get(probe_server, "/readyz")

    assert status == 503
    assert body["reason"] == "producer unavailable"


def test_matched_producer_does_not_affect_liveness(probe_server, monkeypatch):
    fake = MagicMock()
    fake.health.return_value = (False, "producer unavailable")
    monkeypatch.setattr(producer_module, "_producer", fake)

    status, body = get(probe_server, "/livez")

    assert status == 200
    assert body["probe"] == "liveness"
    fake.health.assert_not_called()


# -- startup ordering ---------------------------------------------------


def test_probe_server_binds_before_init_services(monkeypatch):
    """Regression guard for the CrashLoop: init_services() blocks on the schema
    wait, so anything bound after it is unreachable for that whole window."""
    calls = []

    # Without this the real handlers are installed into the pytest process and
    # never removed -- Ctrl-C stops interrupting the run.
    monkeypatch.setattr(
        consumer_main,
        "_install_startup_signal_handlers",
        lambda: calls.append("signals"),
    )
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
        def __init__(self, shutdown_event=None):
            calls.append("consumer_built")

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


# -- startup shutdown ---------------------------------------------------


@pytest.fixture
def startup_harness(monkeypatch):
    """main() with everything stubbed except the shutdown wiring."""
    calls = []
    monkeypatch.setattr(consumer_main, "start_metrics_server", lambda port: None)
    monkeypatch.setattr(consumer_main, "create_health_server", lambda port: None)
    monkeypatch.setattr(
        consumer_main, "_start_trigger_index_safely", lambda: calls.append("index")
    )
    monkeypatch.setattr(consumer_main, "_stop_trigger_index_safely", lambda: None)

    import src.core.kafka_consumer as kafka_consumer_module

    class FakeConsumer:
        def __init__(self, shutdown_event=None):
            calls.append(("built", shutdown_event))

        def start(self):
            calls.append("consume")

    monkeypatch.setattr(kafka_consumer_module, "KafkaEventConsumer", FakeConsumer)

    import src.event_management.process_event_task as process_event_task

    monkeypatch.setattr(process_event_task, "shutdown_sse_pool", lambda wait: None)

    monkeypatch.setattr(consumer_main, "_startup_shutdown", threading.Event())
    return calls


def test_signal_handlers_are_installed_before_the_blocking_init(monkeypatch):
    installed = {}
    monkeypatch.setattr(
        consumer_main.signal,
        "signal",
        lambda sig, handler: installed.setdefault(sig, handler),
    )

    consumer_main._install_startup_signal_handlers()

    assert consumer_main.signal.SIGTERM in installed
    assert consumer_main.signal.SIGINT in installed


def test_the_startup_handler_aborts_the_schema_wait(monkeypatch):
    monkeypatch.setattr(consumer_main, "_startup_shutdown", threading.Event())
    handlers = {}
    monkeypatch.setattr(
        consumer_main.signal, "signal", lambda sig, h: handlers.setdefault(sig, h)
    )
    consumer_main._install_startup_signal_handlers()

    from src.core.db import db_on_start

    monkeypatch.setattr(db_on_start, "_abort_event", threading.Event())

    handlers[consumer_main.signal.SIGTERM](15, None)

    assert consumer_main._startup_shutdown.is_set()
    assert db_on_start.schema_wait_aborted() is True


def test_sigterm_during_startup_exits_before_the_consume_loop(
    monkeypatch, startup_harness
):
    def init_and_terminate():
        consumer_main._startup_shutdown.set()

    monkeypatch.setattr(consumer_main, "init_services", init_and_terminate)

    consumer_main.main()  # must not sys.exit

    assert startup_harness == []  # no index start, no consumer, no consume loop


def test_an_aborted_schema_wait_exits_cleanly_rather_than_crashing(
    monkeypatch, startup_harness
):
    """SchemaWaitAborted propagates out of init_services on purpose, so nothing
    runs against an unverified schema — but a deliberate terminate must still
    exit 0, not look like a crash."""
    from src.core.db.db_on_start import SchemaWaitAborted

    def init_and_abort():
        consumer_main._startup_shutdown.set()
        raise SchemaWaitAborted("aborted")

    monkeypatch.setattr(consumer_main, "init_services", init_and_abort)

    consumer_main.main()  # no SystemExit

    assert startup_harness == []


def test_a_real_startup_failure_still_exits_nonzero(monkeypatch, startup_harness):
    monkeypatch.setattr(
        consumer_main,
        "init_services",
        MagicMock(side_effect=RuntimeError("bad provider")),
    )

    with pytest.raises(SystemExit) as exc:
        consumer_main.main()

    assert exc.value.code == 1


def test_the_consumer_inherits_the_startup_shutdown_event(
    monkeypatch, startup_harness
):
    """Closes the handover window: a SIGTERM landing after the startup check
    but before the consumer installs its own handlers must not be lost."""
    monkeypatch.setattr(consumer_main, "init_services", lambda: None)

    consumer_main.main()

    built = [c for c in startup_harness if isinstance(c, tuple)]
    assert built[0][1] is consumer_main._startup_shutdown
