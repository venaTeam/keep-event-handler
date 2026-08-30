"""Cross-occurrence tracking (firing/unresolved counters + start times).

These fields used to be derived in the ingestion hot path from a
``SELECT ... FROM alert WHERE tenant_id AND fingerprint ORDER BY timestamp
DESC LIMIT 1`` per ingested alert. That read cannot prune the timestamp
partitions of ``alert`` and dominated database CPU at volume. They are now
derived inside ``set_last_alert`` from the previous LastAlert row, under the
lock it already holds.

Covered here: the derivation itself, the values persisted across an occurrence
sequence, self-heal of rows written while the old calculation was disabled,
and a regression guard that the path never reads the ``alert`` table.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event

from src.core.db.db import get_last_alert_by_fingerprint, set_last_alert
from src.core.dependencies import SINGLE_TENANT_UUID
from src.models.alert import AlertStatus
from src.models.db.alert import Alert, LastAlert
from src.utils.enrichment_helpers import derive_tracking_fields

FIRING = AlertStatus.FIRING.value
RESOLVED = AlertStatus.RESOLVED.value
ACKNOWLEDGED = AlertStatus.ACKNOWLEDGED.value

T0 = "2026-08-30T10:00:00.000Z"
T1 = "2026-08-30T10:05:00.000Z"


def _prev(**kwargs):
    """A LastAlert row standing in for the previous occurrence's state."""
    defaults = dict(
        tenant_id=SINGLE_TENANT_UUID,
        fingerprint="fp",
        alert_id=uuid.uuid4(),
        timestamp=datetime.now(tz=timezone.utc),
        first_timestamp=datetime.now(tz=timezone.utc),
        status=FIRING,
        firing_counter=1,
        unresolved_counter=1,
        firing_start_time=T0,
        firing_start_time_since_last_resolved=T0,
    )
    defaults.update(kwargs)
    return LastAlert(**defaults)


# --------------------------------------------------------------------------- #
# derive_tracking_fields
# --------------------------------------------------------------------------- #


def test_first_occurrence_firing_starts_the_clock():
    got = derive_tracking_fields(FIRING, T0, None)
    assert got == {
        "firing_start_time": T0,
        "firing_start_time_since_last_resolved": T0,
        "firing_counter": 1,
        "unresolved_counter": 1,
    }


def test_first_occurrence_resolved_has_no_start_times():
    got = derive_tracking_fields(RESOLVED, T0, None)
    assert got["firing_start_time"] is None
    assert got["firing_start_time_since_last_resolved"] is None
    assert got["firing_counter"] == 1
    assert got["unresolved_counter"] == 0


def test_refire_keeps_the_original_start_and_increments():
    got = derive_tracking_fields(FIRING, T1, _prev())
    assert got["firing_start_time"] == T0
    assert got["firing_start_time_since_last_resolved"] == T0
    assert got["firing_counter"] == 2
    assert got["unresolved_counter"] == 2


def test_resolve_zeroes_unresolved_and_clears_start_times():
    got = derive_tracking_fields(RESOLVED, T1, _prev())
    assert got["firing_start_time"] is None
    assert got["firing_start_time_since_last_resolved"] is None
    assert got["unresolved_counter"] == 0
    assert got["firing_counter"] == 2


def test_fire_after_resolve_restarts_the_clock():
    previous = _prev(
        status=RESOLVED,
        unresolved_counter=0,
        firing_start_time=None,
        firing_start_time_since_last_resolved=None,
    )
    got = derive_tracking_fields(FIRING, T1, previous)
    assert got["firing_start_time"] == T1
    assert got["firing_start_time_since_last_resolved"] == T1
    assert got["unresolved_counter"] == 1
    assert got["firing_counter"] == 2


def test_acknowledged_zeroes_firing_counter():
    assert derive_tracking_fields(ACKNOWLEDGED, T1, _prev())["firing_counter"] == 0


def test_fire_after_acknowledge_restarts_firing_counter():
    previous = _prev(status=ACKNOWLEDGED, firing_counter=0)
    got = derive_tracking_fields(FIRING, T1, previous)
    assert got["firing_counter"] == 1


def test_dismissed_previous_status_is_neither_resolved_nor_acknowledged():
    """A dismissed alert carries status='suppressed' on LastAlert."""
    got = derive_tracking_fields(FIRING, T1, _prev(status="suppressed"))
    assert got["firing_counter"] == 2
    assert got["unresolved_counter"] == 2
    # not firing previously -> this occurrence starts the firing clock
    assert got["firing_start_time"] == T1


def test_null_status_row_reads_as_firing():
    """NULL status = never resolved/acknowledged/dismissed (pre-typed-column row)."""
    got = derive_tracking_fields(FIRING, T1, _prev(status=None))
    assert got["firing_start_time"] == T0
    assert got["firing_counter"] == 2
    assert got["unresolved_counter"] == 2


def test_row_written_while_calculation_disabled_self_heals():
    """Rows written with the old flag off carry 0/None; the next occurrence
    restarts them instead of leaving them empty forever."""
    zeroed = _prev(
        firing_counter=0,
        unresolved_counter=0,
        firing_start_time=None,
        firing_start_time_since_last_resolved=None,
    )
    got = derive_tracking_fields(FIRING, T1, zeroed)
    assert got["firing_start_time"] == T1
    assert got["firing_start_time_since_last_resolved"] == T1
    assert got["firing_counter"] == 1
    assert got["unresolved_counter"] == 1


# --------------------------------------------------------------------------- #
# set_last_alert integration
# --------------------------------------------------------------------------- #


def _record(db_session, fingerprint, status, ts, last_received=None):
    alert = Alert(
        id=uuid.uuid4(),
        tenant_id=SINGLE_TENANT_UUID,
        timestamp=ts,
        provider_type="test",
        provider_id="test",
        status=status,
        fingerprint=fingerprint,
        alert_hash="hash",
    )
    db_session.add(alert)
    db_session.commit()
    return set_last_alert(
        SINGLE_TENANT_UUID,
        alert,
        session=db_session,
        tracking={"last_received": last_received or ts},
    )


def test_occurrence_sequence_persists_expected_tracking(db_session):
    fp = "fp-seq"
    base = datetime(2026, 8, 30, 10, 0, tzinfo=timezone.utc)

    row = _record(db_session, fp, FIRING, base)
    assert (row.firing_counter, row.unresolved_counter) == (1, 1)
    first_start = row.firing_start_time
    assert first_start is not None

    row = _record(db_session, fp, FIRING, base + timedelta(minutes=5))
    assert (row.firing_counter, row.unresolved_counter) == (2, 2)
    assert row.firing_start_time == first_start

    row = _record(db_session, fp, RESOLVED, base + timedelta(minutes=10))
    assert row.unresolved_counter == 0
    assert row.firing_start_time is None
    assert row.firing_start_time_since_last_resolved is None

    row = _record(db_session, fp, FIRING, base + timedelta(minutes=15))
    assert row.unresolved_counter == 1
    assert row.firing_counter == 4
    assert row.firing_start_time != first_start

    persisted = get_last_alert_by_fingerprint(SINGLE_TENANT_UUID, fp, session=db_session)
    assert persisted.firing_counter == row.firing_counter
    assert persisted.firing_start_time == row.firing_start_time


def test_out_of_order_occurrence_does_not_change_tracking(db_session):
    fp = "fp-ooo"
    base = datetime(2026, 8, 30, 10, 0, tzinfo=timezone.utc)
    _record(db_session, fp, FIRING, base)
    row = _record(db_session, fp, FIRING, base + timedelta(minutes=5))
    assert row.firing_counter == 2

    stale = _record(db_session, fp, FIRING, base + timedelta(minutes=1))
    assert stale.firing_counter == 2


def test_start_time_is_canonical_utc_string(db_session):
    row = _record(
        db_session,
        "fp-fmt",
        FIRING,
        datetime(2026, 8, 30, 10, 0, tzinfo=timezone.utc),
    )
    assert row.firing_start_time == "2026-08-30T10:00:00.000Z"


def test_set_last_alert_never_reads_the_alert_table(db_session):
    """Regression guard for the query that caused the CPU spike.

    ``expire_on_commit`` is disabled to match __save_to_db: without it
    SQLAlchemy re-fetches the just-committed Alert row by primary key on the
    first attribute access inside set_last_alert, which is a second (much
    cheaper, partition-prunable) read of the same table.
    """
    db_session.expire_on_commit = False
    fp = "fp-noread"
    base = datetime(2026, 8, 30, 10, 0, tzinfo=timezone.utc)
    _record(db_session, fp, FIRING, base)

    seen = []

    @event.listens_for(db_session.bind, "before_cursor_execute")
    def _capture(conn, cursor, statement, parameters, context, executemany):
        seen.append(" ".join(statement.split()).lower())

    try:
        alert = Alert(
            id=uuid.uuid4(),
            tenant_id=SINGLE_TENANT_UUID,
            timestamp=base + timedelta(minutes=5),
            provider_type="test",
            provider_id="test",
            status=FIRING,
            fingerprint=fp,
            alert_hash="hash",
        )
        db_session.add(alert)
        db_session.commit()
        seen.clear()
        set_last_alert(
            SINGLE_TENANT_UUID,
            alert,
            session=db_session,
            tracking={"last_received": alert.timestamp},
        )
    finally:
        event.remove(db_session.bind, "before_cursor_execute", _capture)

    reads = [s for s in seen if s.startswith("select") and " from alert" in s]
    assert reads == [], f"set_last_alert read the alert table: {reads}"
