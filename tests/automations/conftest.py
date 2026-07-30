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

import socket

import pytest
from prometheus_client import REGISTRY

_PROBE_TIMEOUT_SECONDS = 0.25


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
    """A reachable local Redis, or skip. Session-scoped: one probe, not one per test."""
    if not _port_open("localhost", 6379):
        pytest.skip("redis not reachable on localhost:6379")
    return "redis://localhost:6379/0"


@pytest.fixture(scope="session")
def automations_db_or_skip() -> str:
    """A reachable local Postgres carrying the gateway schema, or skip."""
    if not _port_open("localhost", 5432):
        pytest.skip("postgres not reachable on localhost:5432")
    return "postgresql://keep:keep@localhost:5432/keep"
