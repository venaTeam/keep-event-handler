"""Entrypoint wiring.

These exist because the failure they guard is not hypothetical: the platform
has already shipped a background component that never started in the deployed
environment, and separately a bare import inside main()'s try/except is enough
to crashloop the whole alert-ingestion consumer.
"""

import sys
import types

import pytest

import src.consumer_main as consumer_main


def test_start_is_called_between_health_server_and_consume_loop():
    """Order matters: metrics and health are already up so the first hydrate
    attempt is scrapable, and it is before the blocking consume loop."""
    source = consumer_main.__loader__.get_source("src.consumer_main")
    # rindex: the first occurrence is the `def`, the last is the call in main().
    start_at = source.rindex("_start_trigger_index_safely()")
    health_at = source.index("create_health_server(health_port)")
    consumer_at = source.index("consumer = KafkaEventConsumer()")
    assert health_at < start_at < consumer_at


def test_stop_runs_before_the_unbounded_sse_flush():
    """shutdown_sse_pool wraps ThreadPoolExecutor.shutdown, which takes no
    timeout on 3.11. The bounded stop has to go first or it may never run
    inside the grace period."""
    source = consumer_main.__loader__.get_source("src.consumer_main")
    stop_at = source.rindex("_stop_trigger_index_safely()")
    flush_at = source.index("shutdown_sse_pool(wait=True)")
    assert stop_at < flush_at


def test_a_failing_start_does_not_propagate(monkeypatch, caplog):
    fake = types.ModuleType("src.bl.automations.reloader")

    def boom():
        raise RuntimeError("index is broken")

    fake.start_trigger_index = boom
    monkeypatch.setitem(sys.modules, "src.bl.automations.reloader", fake)

    consumer_main._start_trigger_index_safely()  # must not raise


def test_an_import_error_does_not_propagate(monkeypatch):
    """The import is inside the try, not just the call.

    Without this, any import-time error in the new package reaches main()'s
    `except Exception`, which calls sys.exit(1) -- crashlooping the consumer
    over a degraded optional subsystem.
    """
    import builtins

    real_import = builtins.__import__

    def exploding_import(name, *args, **kwargs):
        if name == "src.bl.automations.reloader":
            raise ImportError("no redis wheel for you")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", exploding_import)
    monkeypatch.delitem(sys.modules, "src.bl.automations.reloader", raising=False)

    consumer_main._start_trigger_index_safely()  # must not raise


def test_a_failing_stop_cannot_mask_the_sse_flush(monkeypatch):
    fake = types.ModuleType("src.bl.automations.reloader")

    def boom():
        raise RuntimeError("stop is broken")

    fake.stop_trigger_index = boom
    monkeypatch.setitem(sys.modules, "src.bl.automations.reloader", fake)

    consumer_main._stop_trigger_index_safely()  # must not raise


def test_the_index_is_not_started_in_the_fastapi_process():
    """The FastAPI app never calls match(). Starting it there would mean one
    Redis subscription and one reload worker PER gunicorn worker, every one of
    them hydrating the shared pool, for an index nothing in that process reads.
    """
    from pathlib import Path

    for module in ("src/main.py", "src/core/lifespan.py"):
        source = Path(module).read_text(encoding="utf-8")
        assert "start_trigger_index" not in source, f"{module} must not start the index"
