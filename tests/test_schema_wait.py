"""
Tests for the schema-wait startup dependency.

keep-api-gateway owns the shared schema, so a new consumer pod waits for the
gateway's `alembic upgrade head` to settle. On a *full* ArgoCD sync the gateway
is rolling at the same time, so this wait can be long — and the old code turned a
long wait into `sys.exit(1)`, i.e. a crash exactly when the cluster needed the
pod to come up. It now retries with capped backoff, tolerates transient DB
errors, and refuses to accept a "stable" head that clearly isn't provisioned.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.core.db import db_on_start


@pytest.fixture(autouse=True)
def fast_and_bounded(monkeypatch):
    """Shrink the wait knobs and make sleeps instant."""
    monkeypatch.setattr(db_on_start, "_SCHEMA_WAIT_TIMEOUT", 1)
    monkeypatch.setattr(db_on_start, "_SCHEMA_WAIT_INTERVAL", 0)
    monkeypatch.setattr(db_on_start, "_SCHEMA_STABLE_CHECKS", 2)
    monkeypatch.setattr(db_on_start, "_SCHEMA_EXPECTED_REVISION", "")
    monkeypatch.setattr(db_on_start, "_SCHEMA_RETRY_BACKOFF_START", 0)
    monkeypatch.setattr(db_on_start, "_SCHEMA_RETRY_BACKOFF_MAX", 0)
    monkeypatch.setattr(db_on_start, "_missing_required_tables", lambda: [])
    db_on_start.reset_schema_wait_abort()
    yield
    db_on_start.reset_schema_wait_abort()


def test_stable_head_is_accepted():
    with patch.object(db_on_start, "_gateway_alembic_head", return_value="abc123"):
        db_on_start._wait_for_schema()  # returns without raising


def test_transient_db_errors_do_not_fail_the_attempt():
    """Connection-pool saturation during a ~20-pod restart storm is expected;
    it must only reset the stability counter, never fail the wait."""
    heads = [
        OSError("connection refused"),
        OSError("too many clients already"),
        "abc123",
        "abc123",
        "abc123",
    ]

    def fake_head():
        value = heads.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    with patch.object(db_on_start, "_gateway_alembic_head", side_effect=fake_head):
        db_on_start._wait_for_schema()


def test_advancing_head_waits_for_it_to_settle():
    heads = ["rev1", "rev2", "rev3", "rev3", "rev3"]
    with patch.object(db_on_start, "_gateway_alembic_head", side_effect=heads):
        db_on_start._wait_for_schema()


def test_timeout_raises_the_retryable_error():
    """Never stamped -> SchemaWaitTimeout, which callers retry (it is explicitly
    not a fatal error any more)."""
    with patch.object(db_on_start, "_gateway_alembic_head", return_value=None):
        with pytest.raises(db_on_start.SchemaWaitTimeout):
            db_on_start._wait_for_schema()


def test_missing_required_tables_blocks_a_trivially_stable_head(monkeypatch):
    """The false-early case: if the gateway is *down*, whatever head is stamped
    is trivially 'stable'. Core tables must exist before we accept it."""
    monkeypatch.setattr(db_on_start, "_missing_required_tables", lambda: ["lastalert"])
    with patch.object(db_on_start, "_gateway_alembic_head", return_value="abc123"):
        with pytest.raises(db_on_start.SchemaWaitTimeout):
            db_on_start._wait_for_schema()


def test_expected_revision_must_match(monkeypatch):
    monkeypatch.setattr(db_on_start, "_SCHEMA_EXPECTED_REVISION", "target-rev")
    with patch.object(db_on_start, "_gateway_alembic_head", return_value="old-rev"):
        with pytest.raises(db_on_start.SchemaWaitTimeout):
            db_on_start._wait_for_schema()

    with patch.object(db_on_start, "_gateway_alembic_head", return_value="target-rev"):
        db_on_start._wait_for_schema()


def test_abort_interrupts_the_wait():
    """A SIGTERM during the schema wait exits promptly instead of blocking for
    the rest of the window."""
    db_on_start.abort_schema_wait()
    with patch.object(db_on_start, "_gateway_alembic_head", return_value=None):
        with pytest.raises(db_on_start.SchemaWaitAborted):
            db_on_start._wait_for_schema()


def _postgres_engine():
    engine = MagicMock()
    engine.dialect.name = "postgresql"
    return engine


def test_migrate_db_retries_instead_of_raising(monkeypatch):
    """The regression this guards: a timed-out wait used to bubble out of
    init_services into `sys.exit(1)`, crashlooping every new consumer pod during
    a full sync. Now it retries and the pod stays up (reporting not-ready)."""
    monkeypatch.setattr(db_on_start, "engine", _postgres_engine())
    monkeypatch.delenv("SKIP_DB_CREATION", raising=False)

    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) < 3:
            raise db_on_start.SchemaWaitTimeout("still waiting")

    with patch.object(db_on_start, "_wait_for_schema", side_effect=flaky):
        db_on_start.migrate_db()

    assert len(attempts) == 3


def test_migrate_db_honors_max_attempts(monkeypatch):
    monkeypatch.setattr(db_on_start, "engine", _postgres_engine())
    monkeypatch.delenv("SKIP_DB_CREATION", raising=False)

    with patch.object(
        db_on_start,
        "_wait_for_schema",
        side_effect=db_on_start.SchemaWaitTimeout("nope"),
    ) as waiter:
        with pytest.raises(db_on_start.SchemaWaitTimeout):
            db_on_start.migrate_db(max_attempts=2)

    assert waiter.call_count == 2


def test_migrate_db_abort_propagates(monkeypatch):
    """Shutdown during the retry backoff exits cleanly rather than looping."""
    monkeypatch.setattr(db_on_start, "engine", _postgres_engine())
    monkeypatch.delenv("SKIP_DB_CREATION", raising=False)

    def timeout_then_abort():
        db_on_start.abort_schema_wait()
        raise db_on_start.SchemaWaitTimeout("timed out")

    with patch.object(db_on_start, "_wait_for_schema", side_effect=timeout_then_abort):
        with pytest.raises(db_on_start.SchemaWaitAborted):
            db_on_start.migrate_db()
