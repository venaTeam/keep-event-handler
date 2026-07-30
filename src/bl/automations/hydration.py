"""Read the gateway-owned `automations` table, in a read-only transaction.

This module is the entire cross-repo read surface of the trigger index. The two
`text()` statements below are the coupling: a rename or drop of
`automations.{id, tenant_id, triggers, cooldown_seconds, cooldown_fields,
grace_seconds, index_generation}`, or a change to the `automation_matching_state`
enum values, is a three-repo change even though this service never writes --
keep-api-gateway owns the migration, keep-automation-api owns the models and is
the sole writer, and this is the reader. The reader deploys first.

**No ORM model is vendored here, deliberately.** This service is not a schema
author: `migrate_db()` builds tables only on sqlite and otherwise blocks on
`_wait_for_schema()` because keep-api-gateway owns the schema on the shared DB.
Registering an `Automation(table=True)` would put the table and its native
Postgres enum types into `SQLModel.metadata`, which `db_on_start.py` and
`tests/conftest.py` then `create_all(...)` on sqlite -- producing a second,
hand-built definition of a gateway-owned table that drifts with no signal.

**⚠️ Read-only must be per-transaction.** The engine here is the one alert
ingestion uses. `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` or a
connect-time listener would return the connection to the pool still read-only,
and the next checkout -- an alert insert, an enrichment write, an incident
update -- would fail. That is not a degraded index, that is ingestion down for
every tenant. Only `postgresql_readonly` on the transaction, and `SET LOCAL`
for the timeout, are safe here.
"""

import json
import logging

from sqlalchemy import text

from src.bl.automations import settings
from src.bl.automations.models import AutomationMatch, CooldownSpec
from src.core.db.db import existed_or_new_session
from src.core.metrics import (
    automation_index_readonly_verification_failures_total,
    automation_index_rows_skipped_total,
)

logger = logging.getLogger(__name__)


class HydrationRejected(Exception):
    """The result set as a whole is unusable -- refuse the swap, keep last-good.

    Distinct from a row-level defect, which is skipped. Never truncate: a
    silently truncated index is a set of automations that stop firing with no
    signal.
    """

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


# No tenant predicate on purpose: one pass loads every tenant's active rows and
# the compiler buckets them, so the hydrate count stays at one query per reload
# interval regardless of tenant count. This is also why the hydration index is
# (matching_state, tenant_id) and not the other way round.
#
# The `::text` casts make the digest and the byte accounting driver-independent.
# The column list is itself a guardrail: not selecting namespace, secret_name,
# active_digest or timeout_seconds makes it structurally impossible for
# submit-time data to reach B5's message.
#
# LIMIT :cap is n+1 so overflow is DETECTABLE. A bare LIMIT with no ORDER BY
# would silently serve an arbitrary subset.
HYDRATION_SQL = """
SELECT id, tenant_id, triggers::text AS triggers,
       cooldown_seconds, cooldown_fields::text AS cooldown_fields,
       grace_seconds, index_generation
FROM automations
WHERE matching_state = 'active'
LIMIT :cap
"""

_READONLY_CHECK_SQL = "SHOW transaction_read_only"


def _is_postgres(bind) -> bool:
    return bind.dialect.name == "postgresql"


def fetch_rows() -> list[dict]:
    """One read-only transaction, one statement, fully materialized.

    Owns its session and never accepts a caller-supplied one. That is a hard
    requirement of the mechanism, not tidiness: if the session already holds a
    connection, SQLAlchemy warns "Connection is already established for the
    given bind; execution_options ignored" and proceeds READ-WRITE. A silent
    downgrade of the only enforcement layer there is.
    """
    cap = settings.read_max_rows() + 1
    with existed_or_new_session() as session:
        bind = session.get_bind()
        if _is_postgres(bind):
            conn = session.connection(
                execution_options={"postgresql_readonly": True}
            )
            # SET LOCAL, not SET: a bare SET would outlive the transaction on a
            # pooled connection shared with the write path.
            conn.exec_driver_sql(
                f"SET LOCAL statement_timeout = {int(settings.read_statement_timeout_ms())}"
            )
            _verify_read_only(conn)
        else:
            # sqlite in tests: the execution option and SHOW do not exist there.
            # Layer 2 (statement-log allowlist, text() only, no session.add)
            # is what covers this path.
            conn = session.connection()
        result = conn.execute(text(HYDRATION_SQL), {"cap": cap})
        rows = [dict(row) for row in result.mappings().all()]

    if len(rows) > settings.read_max_rows():
        raise HydrationRejected(
            "row_cap",
            f"more than {settings.read_max_rows()} active automations",
        )
    return rows


def _verify_read_only(conn) -> None:
    """Fail closed.

    This exists specifically to catch the warn-and-ignore path above. A failed
    verification raises, the hydrate fails into the fail-open path, and the
    session's context manager rolls back -- returning the connection to the pool
    with SQLAlchemy's reset_characteristic having restored readonly=False.
    """
    value = conn.exec_driver_sql(_READONLY_CHECK_SQL).scalar()
    if str(value).lower() != "on":
        automation_index_readonly_verification_failures_total.inc()
        raise HydrationRejected(
            "readonly_verification",
            f"transaction_read_only={value!r}, refusing to read",
        )


def _coerce_json(value):
    """psycopg2 may hand back a parsed list; sqlite hands back text."""
    if value is None:
        return None
    if isinstance(value, (str, bytes)):
        return json.loads(value)
    return value


def rows_to_definitions(rows) -> list[tuple]:
    """Pure. Row mappings -> compiler input. No I/O, no clock.

    Split from the fetch because psycopg2 and sqlite return different Python
    types for the same row, and the only test that would catch a divergence is
    one that self-skips wherever the infra is absent. This half runs everywhere
    and is table-driven over both driver shapes.

    A row-level defect skips that row and is counted -- one bad row must not
    blank the index for every other automation, let alone every other tenant.
    The API validated these at authoring, so a skip is a should-never-happen
    alarm, not a control path.
    """
    max_value_bytes = settings.read_max_value_bytes()
    max_total_bytes = settings.read_max_total_bytes()

    total_bytes = 0
    definitions = []
    for row in rows:
        raw_triggers = row.get("triggers")
        if isinstance(raw_triggers, str):
            total_bytes += len(raw_triggers.encode("utf-8"))
        elif isinstance(raw_triggers, bytes):
            total_bytes += len(raw_triggers)
        if total_bytes > max_total_bytes:
            raise HydrationRejected(
                "total_bytes", f"trigger payload exceeded {max_total_bytes} bytes"
            )

        tenant_id = row.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            # NOT NULL in the migration, so this is defence against a hydrate
            # against a half-applied schema -- never bucket under a placeholder.
            _skip("missing_tenant_id")
            continue

        conditions = _parse_conditions(raw_triggers, max_value_bytes)
        if conditions is None:
            continue

        cooldown = _parse_cooldown(row)
        if cooldown is False:
            continue

        definitions.append(
            (
                tenant_id,
                conditions,
                AutomationMatch(
                    automation_id=str(row.get("id")),
                    grace_seconds=_as_int(row.get("grace_seconds"), 300),
                    cooldown=cooldown,
                ),
                _as_int(row.get("index_generation"), 0),
            )
        )
    return definitions


def _parse_conditions(raw_triggers, max_value_bytes):
    try:
        triggers = _coerce_json(raw_triggers)
    except (ValueError, TypeError):
        _skip("unparseable_triggers")
        return None
    if not isinstance(triggers, list) or not triggers:
        _skip("malformed_triggers")
        return None

    conditions = []
    for condition in triggers:
        if not isinstance(condition, dict):
            _skip("malformed_condition")
            return None
        field = condition.get("field")
        value = condition.get("value")
        if not isinstance(field, str) or not isinstance(value, str):
            _skip("non_string_condition")
            return None
        if len(value.encode("utf-8")) > max_value_bytes:
            _skip("value_too_long")
            return None
        conditions.append((field, value))
    return tuple(conditions)


def _parse_cooldown(row):
    """Returns a CooldownSpec, None (cooldown off), or False (skip the row)."""
    seconds = row.get("cooldown_seconds")
    if seconds is None:
        return None
    try:
        fields_raw = _coerce_json(row.get("cooldown_fields"))
    except (ValueError, TypeError):
        _skip("unparseable_cooldown_fields")
        return False
    if fields_raw is None:
        fields_raw = []
    if not isinstance(fields_raw, list) or any(
        not isinstance(f, str) for f in fields_raw
    ):
        _skip("malformed_cooldown_fields")
        return False
    # Empty fields is a whole-automation cooldown, not "off"; `cooldown_seconds
    # IS NULL` is what means off.
    return CooldownSpec(fields=tuple(fields_raw), seconds=_as_int(seconds, 0))


def _as_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _skip(reason: str) -> None:
    automation_index_rows_skipped_total.labels(reason=reason).inc()
    logger.debug("automations: skipped a row during compile (reason=%s)", reason)


def rows_digest(rows) -> str:
    """Cheap change signal over rows the reload already fetched.

    Not a reinstatement of the deleted `index_generation` probe: this costs no
    extra query, and unlike that probe it DOES detect a `matching_state` UPDATE,
    because a disabled row simply leaves the result set.
    """
    import hashlib

    digest = hashlib.blake2b(digest_size=16)
    for row in sorted(rows, key=lambda r: str(r.get("id"))):
        digest.update(
            "\x1f".join(
                str(row.get(column))
                for column in (
                    "id",
                    "tenant_id",
                    "triggers",
                    "cooldown_seconds",
                    "cooldown_fields",
                    "grace_seconds",
                )
            ).encode("utf-8")
        )
        digest.update(b"\x1e")
    return digest.hexdigest()
