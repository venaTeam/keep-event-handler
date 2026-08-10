"""What `fetch_rows()` actually executes, and the caps it actually enforces.

The spec calls the statement allowlist "the enforcement of record" for
"the event handler never writes automations" and "a required test, not a
nice-to-have". It was missing, and a review proved the consequence: five
separate mutations to `hydration.py` -- removing the `postgresql_readonly`
execution option, downgrading `SET LOCAL` to a bare `SET`, stubbing out the
read-only verification, dropping the `+1` from the row cap, and disabling the
cap check -- all survived the entire suite.

The `SET LOCAL` -> `SET` mutation is the one the spec calls "not merely wrong,
it is destructive": a bare SET outlives the transaction on a pooled connection
that alert ingestion also draws from.

These run on sqlite, with no infra, by attaching a `before_cursor_execute`
listener. That is the point -- the live-Postgres tests self-skip nearly
everywhere, so the code path needs a guard that always runs.
"""

import json

import pytest
from sqlalchemy import event, text

from src.bl.automations import hydration, settings
from src.bl.automations.hydration import HydrationRejected

TENANT = "keep"


@pytest.fixture
def automations_table(db_session):
    """A minimal `automations` table on the suite's sqlite engine.

    Hand-built with text() rather than an ORM model on purpose: registering an
    `Automation(table=True)` in this repo's SQLModel.metadata is exactly what
    the design forbids, because db_on_start and the shared conftest both
    create_all() it.
    """
    bind = db_session.get_bind()
    with bind.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS automations (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    triggers TEXT NOT NULL,
                    cooldown_seconds INTEGER,
                    cooldown_fields TEXT,
                    grace_seconds INTEGER NOT NULL DEFAULT 300,
                    index_generation INTEGER NOT NULL DEFAULT 0,
                    matching_state TEXT NOT NULL DEFAULT 'active'
                )
                """
            )
        )
    yield bind
    with bind.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS automations"))


def _insert(bind, automation_id, state="active", tenant_id=TENANT):
    with bind.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO automations
                    (id, tenant_id, triggers, grace_seconds,
                     index_generation, matching_state)
                VALUES (:id, :tenant_id, :triggers, 300, 1, :state)
                """
            ),
            {
                "id": automation_id,
                "tenant_id": tenant_id,
                "triggers": json.dumps(
                    [
                        {"field": "site", "value": "dc1"},
                        {"field": "status", "value": "firing"},
                    ]
                ),
                "state": state,
            },
        )


class StatementLog:
    def __init__(self):
        self.statements = []

    def __call__(self, conn, cursor, statement, params, context, executemany):
        self.statements.append(" ".join(statement.split()))


@pytest.fixture
def statement_log(automations_table):
    log = StatementLog()
    event.listen(automations_table, "before_cursor_execute", log)
    yield log
    event.remove(automations_table, "before_cursor_execute", log)


def test_a_full_hydrate_issues_only_allowlisted_statements(statement_log, automations_table):
    """The enforcement of record: this service never writes automations."""
    _insert(automations_table, "a-1")
    statement_log.statements.clear()

    hydration.fetch_rows()

    assert statement_log.statements, "the listener captured nothing"
    for statement in statement_log.statements:
        upper = statement.upper()
        allowed = (
            upper.startswith("SELECT")
            or upper.startswith("SET LOCAL ")
            or upper.startswith("SHOW ")
        )
        assert allowed, f"non-allowlisted statement issued: {statement!r}"


@pytest.mark.parametrize(
    "verb", ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE"]
)
def test_a_full_hydrate_issues_no_write_verb(statement_log, automations_table, verb):
    _insert(automations_table, "a-1")
    statement_log.statements.clear()
    hydration.fetch_rows()
    assert not any(s.upper().startswith(verb) for s in statement_log.statements)


def test_a_bare_set_is_never_issued(statement_log, automations_table):
    """`SET LOCAL`, never `SET`.

    A bare SET outlives the transaction on a pooled connection shared with the
    write path -- the destructive failure this design exists to avoid.
    """
    _insert(automations_table, "a-1")
    statement_log.statements.clear()
    hydration.fetch_rows()
    for statement in statement_log.statements:
        upper = statement.upper()
        if upper.startswith("SET"):
            assert upper.startswith("SET LOCAL "), f"bare SET issued: {statement!r}"


def test_only_active_rows_are_returned(automations_table):
    _insert(automations_table, "active-1", state="active")
    _insert(automations_table, "inactive-1", state="inactive")
    _insert(automations_table, "deleting-1", state="deleting")

    rows = hydration.fetch_rows()

    assert sorted(str(r["id"]) for r in rows) == ["active-1"]


def test_rows_from_every_tenant_come_back_in_one_pass(automations_table):
    """No tenant predicate: the compiler buckets, the query does not filter.

    One query per reload regardless of tenant count.
    """
    _insert(automations_table, "a-1", tenant_id="keep")
    _insert(automations_table, "b-1", tenant_id="other-tenant")

    rows = hydration.fetch_rows()

    assert {r["tenant_id"] for r in rows} == {"keep", "other-tenant"}


def test_the_row_cap_refuses_the_whole_set_rather_than_truncating(
    automations_table, monkeypatch, metric_delta
):
    """Silently serving a subset would be automations that stop firing with no
    signal, so a breach must raise -- and the query must fetch n+1 to notice."""
    monkeypatch.setattr(settings, "read_max_rows", lambda: 2)
    for i in range(5):
        _insert(automations_table, f"a-{i}")

    with pytest.raises(HydrationRejected) as excinfo:
        hydration.fetch_rows()
    assert excinfo.value.reason == "row_cap"


def test_exactly_the_cap_is_accepted(automations_table, monkeypatch):
    """The boundary: n rows is fine, n+1 is a breach. Guards the off-by-one in
    `LIMIT cap + 1`."""
    monkeypatch.setattr(settings, "read_max_rows", lambda: 3)
    for i in range(3):
        _insert(automations_table, f"a-{i}")

    rows = hydration.fetch_rows()
    assert len(rows) == 3


def test_one_over_the_cap_is_a_breach(automations_table, monkeypatch):
    monkeypatch.setattr(settings, "read_max_rows", lambda: 3)
    for i in range(4):
        _insert(automations_table, f"a-{i}")

    with pytest.raises(HydrationRejected):
        hydration.fetch_rows()


def test_read_only_verification_fails_closed(monkeypatch, metric_delta):
    """A transaction that is not actually read-only must abort the hydrate.

    This is the guard against SQLAlchemy's warn-and-proceed path: if the
    session already holds a connection it ignores the execution option and
    proceeds READ-WRITE, silently downgrading the only enforcement there is.
    """
    tracked = metric_delta("keep_automation_index_readonly_verification_failures_total")

    class FakeConn:
        def exec_driver_sql(self, statement):
            class Result:
                @staticmethod
                def scalar():
                    return "off"

            return Result()

    with pytest.raises(HydrationRejected) as excinfo:
        hydration._verify_read_only(FakeConn())

    assert excinfo.value.reason == "readonly_verification"
    assert tracked.delta == 1.0


def test_read_only_verification_passes_when_actually_read_only():
    class FakeConn:
        def exec_driver_sql(self, statement):
            class Result:
                @staticmethod
                def scalar():
                    return "on"

            return Result()

    hydration._verify_read_only(FakeConn())  # must not raise


# --------------------------------------------------------------------------
# The Postgres-only branch, driven without Postgres
# --------------------------------------------------------------------------
#
# `postgresql_readonly`, `SET LOCAL statement_timeout` and the `SHOW`
# verification only execute when the bind reports the postgresql dialect, so on
# the sqlite test engine they are dead code -- which is exactly why mutations to
# all three survived the suite. A fake bind exercises them everywhere.


class _FakeDialect:
    name = "postgresql"


class _FakeResult:
    def __init__(self, rows=(), scalar_value="on"):
        self._rows = rows
        self._scalar = scalar_value

    def scalar(self):
        return self._scalar

    def mappings(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeConnection:
    def __init__(self, recorder, readonly_value="on"):
        self.recorder = recorder
        self._readonly_value = readonly_value

    def exec_driver_sql(self, statement):
        self.recorder["driver_sql"].append(" ".join(statement.split()))
        return _FakeResult(scalar_value=self._readonly_value)

    def execute(self, statement, params=None):
        self.recorder["executed"].append((str(statement), params))
        return _FakeResult(rows=self.recorder["rows"])


class _FakeSession:
    def __init__(self, recorder, readonly_value="on"):
        self.recorder = recorder
        self._readonly_value = readonly_value

    def get_bind(self):
        return _FakeDialect  # only .dialect.name is consulted

    def connection(self, execution_options=None):
        self.recorder["execution_options"].append(execution_options)
        return _FakeConnection(self.recorder, self._readonly_value)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeBindHolder:
    dialect = _FakeDialect


def _drive_postgres_branch(monkeypatch, readonly_value="on", rows=()):
    recorder = {
        "driver_sql": [],
        "executed": [],
        "execution_options": [],
        "rows": list(rows),
    }

    class _Ctx:
        def __enter__(self):
            return _FakeSession(recorder, readonly_value)

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(hydration, "existed_or_new_session", lambda *a, **k: _Ctx())
    monkeypatch.setattr(hydration, "_is_postgres", lambda bind: True)
    return recorder


def test_postgres_branch_requests_a_read_only_transaction(monkeypatch):
    recorder = _drive_postgres_branch(monkeypatch)
    hydration.fetch_rows()
    assert recorder["execution_options"] == [{"postgresql_readonly": True}]


def test_postgres_branch_scopes_the_timeout_to_the_transaction(monkeypatch):
    """SET LOCAL, never a bare SET.

    A bare SET outlives the transaction on a pooled connection that alert
    ingestion also draws from -- the destructive failure this design exists to
    avoid.
    """
    recorder = _drive_postgres_branch(monkeypatch)
    hydration.fetch_rows()
    timeouts = [s for s in recorder["driver_sql"] if "statement_timeout" in s.lower()]
    assert timeouts, "no statement_timeout was set"
    for statement in timeouts:
        assert statement.upper().startswith("SET LOCAL "), statement


def test_postgres_branch_verifies_read_only_before_reading(monkeypatch):
    recorder = _drive_postgres_branch(monkeypatch)
    hydration.fetch_rows()
    assert any("transaction_read_only" in s.lower() for s in recorder["driver_sql"])
    # ...and it happens before the SELECT is issued.
    assert recorder["executed"], "the hydration SELECT never ran"


def test_postgres_branch_aborts_when_the_transaction_is_not_read_only(monkeypatch):
    recorder = _drive_postgres_branch(monkeypatch, readonly_value="off")
    with pytest.raises(HydrationRejected) as excinfo:
        hydration.fetch_rows()
    assert excinfo.value.reason == "readonly_verification"
    # The SELECT must NOT have been issued after a failed verification.
    assert recorder["executed"] == []


def test_postgres_branch_uses_the_cast_flavoured_sql(monkeypatch):
    recorder = _drive_postgres_branch(monkeypatch)
    hydration.fetch_rows()
    (statement, params), = recorder["executed"]
    assert "::text" in statement
    assert params["cap"] == settings.read_max_rows() + 1


def test_statement_timeout_is_integer_coerced(monkeypatch):
    """SET cannot take a bind parameter, so the value is interpolated -- it
    must be an int at the interpolation site."""
    monkeypatch.setattr(settings, "read_statement_timeout_ms", lambda: 4321)
    recorder = _drive_postgres_branch(monkeypatch)
    hydration.fetch_rows()
    timeout = next(s for s in recorder["driver_sql"] if "statement_timeout" in s.lower())
    assert "4321" in timeout
    assert "'" not in timeout and '"' not in timeout
