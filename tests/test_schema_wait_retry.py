"""Schema wait: retries instead of exiting, and refuses to call a stale head
'ready'.
"""
import threading
from unittest.mock import MagicMock, patch

import pytest

from src.core.db import db_on_start as dbos


@pytest.fixture(autouse=True)
def fast_and_clean(monkeypatch):
    monkeypatch.setattr(dbos, "_SCHEMA_WAIT_INTERVAL", 0)
    monkeypatch.setattr(dbos, "_SCHEMA_RETRY_BACKOFF_START", 0)
    monkeypatch.setattr(dbos, "_SCHEMA_RETRY_BACKOFF_MAX", 0)
    monkeypatch.setattr(dbos, "_abort_event", threading.Event())
    yield


@pytest.fixture
def postgres_engine(monkeypatch):
    """migrate_db short-circuits on sqlite; the wait path is postgres-only."""
    engine = MagicMock()
    engine.dialect.name = "postgresql"
    monkeypatch.setattr(dbos, "engine", engine)
    return engine


def heads(*values):
    """Successive _gateway_alembic_head() return values, last one repeating."""
    seq = list(values)

    def _head():
        return seq.pop(0) if len(seq) > 1 else seq[0]

    return _head


# -- required tables ----------------------------------------------------


def test_missing_core_tables_never_counts_as_ready(monkeypatch):
    """An empty/half-built DB must not pass just because its head is quiet."""
    monkeypatch.setattr(dbos, "_SCHEMA_WAIT_TIMEOUT", 0)
    monkeypatch.setattr(dbos, "_missing_required_tables", lambda inspector: ["alert"])
    monkeypatch.setattr(dbos, "_gateway_alembic_head", lambda: "abc123")

    with patch.object(dbos, "sa_inspect"):
        with pytest.raises(dbos.SchemaWaitTimeout):
            dbos._wait_for_schema()


def test_ready_when_tables_present_and_head_settles(monkeypatch):
    monkeypatch.setattr(dbos, "_SCHEMA_WAIT_TIMEOUT", 30)
    monkeypatch.setattr(dbos, "_missing_required_tables", lambda inspector: [])
    monkeypatch.setattr(dbos, "_gateway_alembic_head", heads("aaa", "bbb", "bbb", "bbb", "bbb"))

    with patch.object(dbos, "sa_inspect"):
        dbos._wait_for_schema()  # returns = ready


# -- expected revision --------------------------------------------------


def test_stale_head_is_not_ready_when_a_revision_is_pinned(monkeypatch):
    """The false-early hole: a DOWN gateway leaves yesterday's revision in
    place, and a stale head is perfectly quiescent."""
    monkeypatch.setattr(dbos, "_SCHEMA_WAIT_TIMEOUT", 0)
    monkeypatch.setattr(dbos, "_SCHEMA_EXPECTED_REVISION", "target-rev")
    monkeypatch.setattr(dbos, "_missing_required_tables", lambda inspector: [])
    monkeypatch.setattr(dbos, "_gateway_alembic_head", lambda: "yesterdays-rev")

    with patch.object(dbos, "sa_inspect"):
        with pytest.raises(dbos.SchemaWaitTimeout):
            dbos._wait_for_schema()


def test_expected_revision_match_is_ready_immediately(monkeypatch):
    """An exact match is stronger evidence than quiescence — no stability
    counter needed."""
    monkeypatch.setattr(dbos, "_SCHEMA_WAIT_TIMEOUT", 30)
    monkeypatch.setattr(dbos, "_SCHEMA_EXPECTED_REVISION", "target-rev")
    monkeypatch.setattr(dbos, "_missing_required_tables", lambda inspector: [])
    calls = {"n": 0}

    def head():
        calls["n"] += 1
        return "target-rev"

    monkeypatch.setattr(dbos, "_gateway_alembic_head", head)

    with patch.object(dbos, "sa_inspect"):
        dbos._wait_for_schema()

    assert calls["n"] == 1


# -- retry instead of exit ----------------------------------------------


def test_migrate_db_retries_a_timeout_instead_of_raising(monkeypatch, postgres_engine):
    """The old behaviour raised, which reached consumer_main and sys.exit(1) —
    killing the pod exactly when the gateway was slowest."""
    attempts = {"n": 0}

    def wait():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise dbos.SchemaWaitTimeout("still migrating")

    monkeypatch.setattr(dbos, "_wait_for_schema", wait)

    dbos.migrate_db()

    assert attempts["n"] == 3


def test_migrate_db_backs_off_between_attempts(monkeypatch, postgres_engine):
    monkeypatch.setattr(dbos, "_SCHEMA_RETRY_BACKOFF_START", 5)
    monkeypatch.setattr(dbos, "_SCHEMA_RETRY_BACKOFF_MAX", 60)
    waits = []

    event = MagicMock()
    event.is_set.return_value = False
    event.wait.side_effect = lambda seconds: waits.append(seconds) or False
    monkeypatch.setattr(dbos, "_abort_event", event)

    attempts = {"n": 0}

    def wait():
        attempts["n"] += 1
        if attempts["n"] < 4:
            raise dbos.SchemaWaitTimeout("still migrating")

    monkeypatch.setattr(dbos, "_wait_for_schema", wait)

    dbos.migrate_db()

    assert waits == [5, 10, 20]  # doubling, capped at 60


def test_migrate_db_never_propagates_the_timeout(monkeypatch, postgres_engine):
    """Regression guard: nothing from the schema wait may reach main()'s
    except-clause, which calls sys.exit(1)."""
    monkeypatch.setattr(
        dbos,
        "_wait_for_schema",
        MagicMock(side_effect=[dbos.SchemaWaitTimeout("x"), None]),
    )

    assert dbos.migrate_db() is None


# -- shutdown -----------------------------------------------------------


def test_abort_stops_the_wait_promptly(monkeypatch):
    monkeypatch.setattr(dbos, "_SCHEMA_WAIT_TIMEOUT", 3600)
    monkeypatch.setattr(dbos, "_missing_required_tables", lambda inspector: ["alert"])
    monkeypatch.setattr(dbos, "_gateway_alembic_head", lambda: None)
    dbos.request_schema_wait_abort()

    with patch.object(dbos, "sa_inspect"):
        dbos._wait_for_schema()  # returns instead of blocking for an hour

    assert dbos.schema_wait_aborted() is True


def test_abort_stops_the_retry_loop(monkeypatch, postgres_engine):
    monkeypatch.setattr(
        dbos, "_wait_for_schema", MagicMock(side_effect=dbos.SchemaWaitTimeout("x"))
    )
    dbos.request_schema_wait_abort()

    dbos.migrate_db()  # must not loop forever

    assert dbos.schema_wait_aborted() is True
