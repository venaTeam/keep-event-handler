"""End-to-end reload coverage against real Redis and real Postgres.

**These self-skip when the dependency is absent, and that is deliberate.**
`tests/conftest.py` only honours an `integration` marker when a CLI flag is
passed, and neither CI (`.github/workflows/test-pr-e2e.yml` runs a bare
`pytest tests/`) nor the Stop hook passes one -- so a marker alone would turn
CI red on every machine without Redis. The probes live in `conftest.py` and key
on the connection failing rather than on an error message, because Windows says
"actively refused it" where the hook's infra-down pattern looks for "Connection
refused".

The consequence, stated rather than discovered: on a machine without the stack
up, this file contributes nothing. That is why the driver-shape divergence and
the read-only *code* path are covered by dep-free tests in test_hydration.py --
those run everywhere. What only these can prove is that the per-transaction
read-only actually holds on a live Postgres, and that a real publish converges.
"""

import json
import threading
import time
import uuid

import pytest
from sqlalchemy import create_engine, text

from src.bl.automations import hydration, settings
from src.bl.automations.pubsub import ReloadSubscriber
from src.bl.automations.reloader import TriggerIndexService

pytestmark = pytest.mark.integration

TENANT = "keep"


@pytest.fixture(scope="module")
def engine(automations_db_or_skip):
    created = create_engine(automations_db_or_skip)
    with created.connect() as conn:
        present = conn.execute(
            text("SELECT to_regclass('public.automations')")
        ).scalar()
    if present is None:
        pytest.skip(
            "the automations table is absent -- apply keep-api-gateway's "
            "migrations to the keep database first (this service is not a "
            "schema author)"
        )
    return created


@pytest.fixture
def seeded(engine):
    """Insert an automation, and clean up after. Uses its OWN write engine --
    the hydration path is read-only by construction and cannot seed."""
    made = []

    def insert(field="site", value="dc1", tenant_id=TENANT):
        automation_id = uuid.uuid4()
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO automations (
                        id, tenant_id, name, namespace, triggers, script_path,
                        grace_seconds, matching_state, build_state,
                        index_generation, created_by, updated_by
                    ) VALUES (
                        :id, :tenant_id, :name, 'wallet-a', CAST(:triggers AS jsonb),
                        :script_path, 300, 'active', 'idle', 1, 'test', 'test'
                    )
                    """
                ),
                {
                    "id": automation_id,
                    "tenant_id": tenant_id,
                    "name": f"test-{automation_id}",
                    "script_path": f"{automation_id}/script.py",
                    "triggers": json.dumps(
                        [
                            {"field": field, "value": value},
                            {"field": "status", "value": "firing"},
                        ]
                    ),
                },
            )
        made.append(automation_id)
        return automation_id

    yield insert

    with engine.begin() as conn:
        for automation_id in made:
            conn.execute(
                text("DELETE FROM automations WHERE id = :id"), {"id": automation_id}
            )


@pytest.mark.timeout(60)
def test_the_hydration_transaction_is_actually_read_only(engine, seeded):
    """The claim the whole read-only story rests on, verified on a live server.

    Everything else about the boundary is convention plus a statement-log
    allowlist. This is the only test that proves Postgres itself refuses.
    """
    seeded()
    from src.core.db.db import existed_or_new_session

    with existed_or_new_session() as session:
        if session.get_bind().dialect.name != "postgresql":
            pytest.skip("the configured engine is not postgresql")
        conn = session.connection(execution_options={"postgresql_readonly": True})
        assert str(conn.exec_driver_sql("SHOW transaction_read_only").scalar()) == "on"
        with pytest.raises(Exception) as excinfo:
            conn.exec_driver_sql(
                "UPDATE automations SET name = 'nope' WHERE 1 = 0"
            )
        assert "read-only" in str(excinfo.value).lower()


@pytest.mark.timeout(60)
def test_the_connection_returns_to_the_pool_write_capable(engine, seeded):
    """The destructive failure mode this design exists to avoid.

    A session- or connect-level read-only would hand the connection back still
    read-only, and the next checkout -- an alert insert, an enrichment write --
    would fail. That is not a degraded index, that is ingestion down for every
    tenant.
    """
    from src.core.db.db import existed_or_new_session

    with existed_or_new_session() as session:
        if session.get_bind().dialect.name != "postgresql":
            pytest.skip("the configured engine is not postgresql")
        conn = session.connection(execution_options={"postgresql_readonly": True})
        conn.exec_driver_sql("SELECT 1")

    # A fresh checkout from the same pool must be writable again.
    with existed_or_new_session() as session:
        conn = session.connection()
        assert str(conn.exec_driver_sql("SHOW transaction_read_only").scalar()) == "off"


@pytest.mark.timeout(60)
def test_live_row_types_match_the_pure_fixture_assumptions(engine, seeded):
    """Settles the psycopg2-vs-sqlite assumption the pure tests encode."""
    seeded()
    rows = hydration.fetch_rows()
    assert rows
    row = rows[0]
    # The ::text casts mean triggers arrives as a string on both drivers.
    assert isinstance(row["triggers"], str)
    assert isinstance(row["tenant_id"], str)
    # And the pure half handles whatever `id` really is.
    definitions = hydration.rows_to_definitions(rows)
    assert all(isinstance(d[2].automation_id, str) for d in definitions)


@pytest.mark.timeout(60)
def test_periodic_reload_converges_without_any_pubsub(engine, seeded):
    """The mandated 'pub/sub disabled -> periodic reload catches it' case.

    Uses a service-level interval override, not the clamped default: the point
    is the timer path, not how long it waits.
    """
    service = TriggerIndexService(reload_seconds=0.05)
    original = settings.read_min_hydrate_interval_seconds
    settings.read_min_hydrate_interval_seconds = lambda: 0
    try:
        service.start()
        deadline = time.time() + 20
        while time.time() < deadline and not service.ready:
            time.sleep(0.05)
        assert service.ready, "the index never became ready"
        before = service.index.size

        seeded(field="site", value="dc-integration")

        deadline = time.time() + 20
        while time.time() < deadline and service.index.size <= before:
            time.sleep(0.05)
        assert service.index.size > before, "the periodic reload never saw the change"
    finally:
        settings.read_min_hydrate_interval_seconds = original
        service.stop(deadline=5)


@pytest.mark.timeout(60)
def test_a_real_publish_signals_the_service(redis_url_or_skip):
    """The fast path: a publish on the contract channel reaches the worker."""
    import redis

    class Recording:
        def __init__(self):
            self.event = threading.Event()

        def signal(self):
            self.event.set()

    service = Recording()
    subscriber = ReloadSubscriber(service, url=redis_url_or_skip)
    subscriber.start()
    try:
        # Give the subscription a moment to establish before publishing --
        # pub/sub is at-most-once, so a publish before SUBSCRIBE is simply gone.
        time.sleep(1.0)
        publisher = redis.Redis.from_url(redis_url_or_skip)
        for _ in range(5):
            publisher.publish("reload", b"")
            if service.event.wait(timeout=1.0):
                break
        assert service.event.is_set(), "a real publish never reached the subscriber"
    finally:
        subscriber.stop(deadline=5)
