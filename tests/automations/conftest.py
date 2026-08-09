"""Shared fixtures for the trigger-index tests.

Two things here are load-bearing rather than convenience:

1. **Metric assertions must be deltas.** The instruments in `src/core/metrics.py`
   are module-level singletons in the global prometheus REGISTRY and are never
   reset between tests. An absolute assertion (`== 1`) is order-dependent across
   the whole session and breaks the first time a second test touches the same
   counter.

2. **Dependency probes skip, they do not mark.** `tests/conftest.py` only skips
   `integration`-marked tests when a CLI flag is passed, and neither CI
   (`.github/workflows/test-pr-e2e.yml` runs a bare `pytest tests/`) nor the Stop
   hook passes one. A marker alone would turn CI red on any machine without
   Redis. The probe is a raw socket connect with a short timeout rather than a
   client call, so it cannot hang, and it keys on the connection failing rather
   than on an error message -- Windows says "actively refused it" where the Stop
   hook's infra-down pattern looks for "Connection refused".
"""

import os
import socket
from urllib.parse import urlparse

import pytest
from prometheus_client import REGISTRY

_PROBE_TIMEOUT_SECONDS = 0.25


@pytest.fixture(autouse=True)
def automations_enabled(monkeypatch):
    """These tests exercise the feature switched ON.

    AUTOMATION_INDEX_ENABLED defaults to OFF so the code can ship without
    running (deployment gate), which would otherwise turn every behavioural
    test in this package into an assertion about a no-op. Patched on the
    settings module rather than via the environment because
    `src/config/consts.py` reads the variable once at import.

    The tests for the gate itself re-patch this to False -- an autouse fixture
    runs first, so a test-level monkeypatch still wins.
    """
    from src.bl.automations import settings

    monkeypatch.setattr(settings, "AUTOMATION_INDEX_ENABLED", True)


def _host_port(url: str, default_port: int = 5432) -> tuple[str, int]:
    parsed = urlparse(url)
    return (parsed.hostname or "localhost", parsed.port or default_port)


def metric_value(name: str, labels: dict | None = None) -> float:
    """Current value of a metric sample, 0.0 when it has never been observed."""
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


class MetricDelta:
    """Captures a metric before a block and reports how far it moved."""

    def __init__(self, name: str, labels: dict | None = None):
        self._name = name
        self._labels = labels or {}
        self._before = metric_value(name, self._labels)

    @property
    def delta(self) -> float:
        return metric_value(self._name, self._labels) - self._before


@pytest.fixture
def metric_delta():
    return MetricDelta


def _port_open(host: str, port: int) -> bool:
    probe = socket.socket()
    probe.settimeout(_PROBE_TIMEOUT_SECONDS)
    try:
        probe.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


@pytest.fixture(scope="session")
def redis_url_or_skip() -> str:
    """A reachable Redis, or skip. Session-scoped: one probe, not one per test.

    Honours REDIS_URL so the suite can be pointed at a throwaway instance.
    """
    url = os.environ.get("REDIS_URL") or "redis://localhost:6379/0"
    host, port = _host_port(url, default_port=6379)
    if not _port_open(host, port):
        pytest.skip(f"redis not reachable on {host}:{port}")
    return url


@pytest.fixture(scope="session")
def automations_db_or_skip() -> str:
    """A USABLE local `keep` database, or skip.

    An open port is not enough, and this is not a hypothetical: another
    project's container has been observed holding 5432 without the `keep`
    role (recorded in VAULT). A port-only probe passes there and every test
    then fails on `password authentication failed` -- reported as a code
    failure, which is exactly wrong.

    So the probe actually connects. Skipping on any connection error also
    covers the Windows/POSIX message difference the Stop hook's infra-down
    pattern trips over.
    """
    # Honour the DSN this service actually reads, so the integration tests can
    # be pointed at a throwaway instance without editing them. Hydration uses
    # the shared engine built from this same variable.
    url = os.environ.get(
        "DATABASE_CONNECTION_STRING", "postgresql://keep:keep@localhost:5432/keep"
    )
    host, port = _host_port(url)
    if not _port_open(host, port):
        pytest.skip(f"postgres not reachable on {host}:{port}")

    try:
        from sqlalchemy import create_engine, text

        probe_engine = create_engine(url, connect_args={"connect_timeout": 2})
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        probe_engine.dispose()
    except Exception as error:  # noqa: BLE001 - any failure means "not usable"
        pytest.skip(f"the keep database is not usable at {host}:{port}: {error}")
    return url
