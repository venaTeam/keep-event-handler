"""first_resolved / last_resolved evaluation, exercised on SQLite and Postgres.

The legacy edge strategies of `Incident.resolve_on` must keep auto-resolving
incidents that already exist. The query behind them used to group by one column
while selecting others and to filter with a bare `HAVING max(...)`, which
SQLite accepts and Postgres rejects, so these cases run against both engines.

Edge semantics (live links only, `deleted_at == NULL_FOR_DELETED_AT`):

* first = the linked alert with the earliest `LastAlert.first_timestamp`,
  ties broken by `fingerprint` ascending.
* last  = the latest `LastAlert.first_timestamp`, ties broken by `fingerprint`
  descending.
* That alert is resolved when `LastAlert.status` (the enriched status), or, if
  that is NULL, the `Alert.status` of `LastAlert.alert_id`, is "resolved".

The Postgres case needs a database already migrated by `keep-migrate`. It is
skipped when none is reachable; point it elsewhere with
`KEEP_TEST_POSTGRES_URL`.
"""

import os
from datetime import datetime, timedelta
from typing import NamedTuple
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, inspect
from sqlmodel import Session

from src.core.db.db import (
    is_first_incident_alert_resolved,
    is_last_incident_alert_resolved,
)
from src.core.db.helpers import NULL_FOR_DELETED_AT
from src.models.alert import AlertStatus
from src.models.db.alert import Alert, LastAlert, LastAlertToIncident
from src.models.db.incident import Incident
from src.models.db.tenant import Tenant

POSTGRES_URL_ENV = "KEEP_TEST_POSTGRES_URL"
DEFAULT_POSTGRES_URL = "postgresql://keep:keep@localhost:5432/keep"

T0 = datetime(2026, 1, 1, 12, 0, 0)
R, F = AlertStatus.RESOLVED.value, AlertStatus.FIRING.value


class SeedAlert(NamedTuple):
    fingerprint: str
    first_timestamp: datetime
    status: str
    enriched_status: str | None = None


@pytest.fixture(params=["sqlite", "postgres"])
def edge_session(request):
    if request.param == "sqlite":
        yield request.getfixturevalue("db_session")
        return

    url = os.environ.get(POSTGRES_URL_ENV, DEFAULT_POSTGRES_URL)
    engine = create_engine(url, connect_args={"connect_timeout": 2})
    where = engine.url.render_as_string(hide_password=True)
    # Probe on the engine, not on the connection used below: on SQLAlchemy 2.0
    # running SQL on a connection autobegins a transaction, and `begin()` then
    # raises. The probe's own connection goes back to the pool before we open ours.
    try:
        has_schema = inspect(engine).has_table("lastalerttoincident")
    except Exception as error:  # noqa: BLE001 - any failure means "not usable"
        engine.dispose()
        pytest.skip(f"the keep database is not usable at {where}: {error}")
    if not has_schema:
        engine.dispose()
        pytest.skip(f"no keep schema at {where}: run keep-migrate first")

    # Everything the test seeds lives in one outer transaction that is rolled
    # back at the end, so the shared database is left untouched. The seeding
    # only flushes, it never commits.
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()
        engine.dispose()


def seed_incident(
    session, alerts: list[SeedAlert], unlinked: frozenset[str] = frozenset()
) -> Incident:
    """Insert a tenant, one alert/lastalert per `SeedAlert`, and an incident.

    Every fingerprint in `unlinked` gets a soft-deleted link instead of a live
    one. Only flushes: each step is flushed on its own so a foreign key never
    points at a row that is not written yet.
    """
    tenant = Tenant(id=f"edge-{uuid4().hex[:8]}", name=f"edge-{uuid4().hex}")
    session.add(tenant)
    session.flush()

    alert_ids = {}
    for seed in alerts:
        alert = Alert(
            tenant_id=tenant.id,
            timestamp=seed.first_timestamp,
            provider_type="test",
            provider_id="test",
            fingerprint=seed.fingerprint,
            status=seed.status,
        )
        session.add(alert)
        alert_ids[seed.fingerprint] = alert.id
    session.flush()

    for seed in alerts:
        session.add(
            LastAlert(
                tenant_id=tenant.id,
                fingerprint=seed.fingerprint,
                alert_id=alert_ids[seed.fingerprint],
                timestamp=seed.first_timestamp,
                first_timestamp=seed.first_timestamp,
                status=seed.enriched_status,
            )
        )
    session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        alerts_count=sum(1 for seed in alerts if seed.fingerprint not in unlinked),
    )
    session.add(incident)
    session.flush()

    for seed in alerts:
        session.add(
            LastAlertToIncident(
                tenant_id=tenant.id,
                fingerprint=seed.fingerprint,
                incident_id=incident.id,
                deleted_at=(
                    datetime.utcnow()
                    if seed.fingerprint in unlinked
                    else NULL_FOR_DELETED_AT
                ),
            )
        )
    session.flush()
    return incident


@pytest.mark.parametrize(
    "a_status,b_status,first,last", [(F, R, False, True), (R, F, True, False)]
)
def test_edge_follows_first_timestamp(edge_session, a_status, b_status, first, last):
    inc = seed_incident(
        edge_session,
        [
            SeedAlert("a", T0, a_status),
            SeedAlert("b", T0 + timedelta(minutes=1), b_status),
        ],
    )
    assert is_first_incident_alert_resolved(inc, session=edge_session) is first
    assert is_last_incident_alert_resolved(inc, session=edge_session) is last


def test_enriched_status_overrides_alert_status(edge_session):
    inc = seed_incident(edge_session, [SeedAlert("a", T0, F, enriched_status=R)])
    assert is_first_incident_alert_resolved(inc, session=edge_session) is True
    inc2 = seed_incident(
        edge_session,
        [SeedAlert("b", T0, R, enriched_status=AlertStatus.ACKNOWLEDGED.value)],
    )
    assert is_first_incident_alert_resolved(inc2, session=edge_session) is False


def test_unlinked_alert_is_ignored(edge_session):
    inc = seed_incident(
        edge_session,
        [
            SeedAlert("a", T0, F),
            SeedAlert("b", T0 + timedelta(minutes=1), R),
            SeedAlert("c", T0 + timedelta(minutes=2), F),
        ],
        unlinked=frozenset({"a"}),
    )
    assert is_first_incident_alert_resolved(inc, session=edge_session) is True
    assert is_last_incident_alert_resolved(inc, session=edge_session) is False


def test_tie_breaks_on_fingerprint(edge_session):
    inc = seed_incident(edge_session, [SeedAlert("a", T0, R), SeedAlert("b", T0, F)])
    assert is_first_incident_alert_resolved(inc, session=edge_session) is True
    assert is_last_incident_alert_resolved(inc, session=edge_session) is False


def test_incident_without_alerts_is_not_resolved(edge_session):
    inc = seed_incident(edge_session, [])
    assert is_first_incident_alert_resolved(inc, session=edge_session) is False
    assert is_last_incident_alert_resolved(inc, session=edge_session) is False
