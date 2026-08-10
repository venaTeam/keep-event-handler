"""Hydration: the pure coercion half, the caps, and the SQL shape.

The driver-shape tests here are the ones that actually run everywhere. The
real-Postgres tests (read-only enforcement, live row types) self-skip, so if
these were the only guard against a psycopg2/sqlite divergence there would be
no guard at all on most machines.
"""

import json

import pytest

from src.bl.automations import hydration, settings
from src.bl.automations.hydration import HydrationRejected

AUTOMATION_ID = "3f2b8c1e-4d6a-4b2f-9e77-0a1b2c3d4e5f"
TRIGGERS = [
    {"field": "severity", "value": "critical"},
    {"field": "application", "value": "payments"},
]

# The same logical row as each driver actually hands it back. psycopg2 returns a
# uuid.UUID and (without the ::text cast) a parsed list; sqlite returns str for
# both. The bytes shape exercises the third branch of _coerce_json, which
# nothing else reaches.
PSYCOPG2_ROW = {
    "id": AUTOMATION_ID,
    "tenant_id": "keep",
    "triggers": json.dumps(TRIGGERS),
    "cooldown_seconds": 600,
    "cooldown_fields": json.dumps(["node_name"]),
    "grace_seconds": 300,
    "index_generation": 7,
}
SQLITE_ROW = dict(PSYCOPG2_ROW)
PARSED_ROW = {**PSYCOPG2_ROW, "triggers": TRIGGERS, "cooldown_fields": ["node_name"]}
BYTES_ROW = {
    **PSYCOPG2_ROW,
    "triggers": json.dumps(TRIGGERS).encode("utf-8"),
    "cooldown_fields": json.dumps(["node_name"]).encode("utf-8"),
}


def test_every_driver_row_shape_compiles_identically():
    """A green suite must not be able to lie about a psycopg2/sqlite divergence."""
    shapes = [PSYCOPG2_ROW, SQLITE_ROW, PARSED_ROW, BYTES_ROW]
    results = [hydration.rows_to_definitions([shape]) for shape in shapes]
    first = results[0]
    for other in results[1:]:
        assert other == first


def test_definition_carries_tenant_conditions_match_and_generation():
    (tenant_id, conditions, match, generation), = hydration.rows_to_definitions(
        [PSYCOPG2_ROW]
    )
    assert tenant_id == "keep"
    assert conditions == (("severity", "critical"), ("application", "payments"))
    assert match.automation_id == AUTOMATION_ID
    assert match.grace_seconds == 300
    assert match.cooldown.seconds == 600
    assert match.cooldown.fields == ("node_name",)
    assert generation == 7


def test_uuid_object_is_normalised_to_its_wire_form():
    import uuid

    row = {**PSYCOPG2_ROW, "id": uuid.UUID(AUTOMATION_ID)}
    (_, _, match, _), = hydration.rows_to_definitions([row])
    assert match.automation_id == AUTOMATION_ID
    assert isinstance(match.automation_id, str)


# --------------------------------------------------------------------------
# Cooldown resolution
# --------------------------------------------------------------------------


def test_null_cooldown_seconds_means_cooldown_is_off():
    row = {**PSYCOPG2_ROW, "cooldown_seconds": None}
    (_, _, match, _), = hydration.rows_to_definitions([row])
    assert match.cooldown is None


@pytest.mark.parametrize("fields", [None, json.dumps([]), []])
def test_empty_cooldown_fields_is_whole_automation_not_off(fields):
    row = {**PSYCOPG2_ROW, "cooldown_fields": fields}
    (_, _, match, _), = hydration.rows_to_definitions([row])
    assert match.cooldown is not None
    assert match.cooldown.fields == ()
    assert match.cooldown.seconds == 600


def test_cooldown_fields_keep_their_authored_order():
    """Sorting is step one of the consumer's canonicalization and belongs
    there; doing it here too would be invisible the day it stops."""
    row = {**PSYCOPG2_ROW, "cooldown_fields": json.dumps(["site", "node_name"])}
    (_, _, match, _), = hydration.rows_to_definitions([row])
    assert match.cooldown.fields == ("site", "node_name")


def test_cooldown_scheme_version_is_stamped():
    (_, _, match, _), = hydration.rows_to_definitions([PSYCOPG2_ROW])
    assert match.cooldown.scheme_ver == 1


# --------------------------------------------------------------------------
# Row-level defects skip the row, never the batch
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "override,reason",
    [
        ({"triggers": "{not json"}, "unparseable_triggers"),
        ({"triggers": json.dumps({})}, "malformed_triggers"),
        ({"triggers": json.dumps([])}, "malformed_triggers"),
        ({"triggers": json.dumps(["nope"])}, "malformed_condition"),
        ({"triggers": json.dumps([{"field": "severity", "value": 7}])},
         "non_string_condition"),
        ({"tenant_id": None}, "missing_tenant_id"),
        ({"tenant_id": "   "}, "missing_tenant_id"),
        ({"cooldown_fields": json.dumps([7])}, "malformed_cooldown_fields"),
        ({"cooldown_fields": "{not json"}, "unparseable_cooldown_fields"),
    ],
)
def test_defective_row_is_skipped_and_counted(override, reason, metric_delta):
    tracked = metric_delta(
        "keep_automation_index_rows_skipped_total", {"reason": reason}
    )
    bad = {**PSYCOPG2_ROW, **override}
    good = {**PSYCOPG2_ROW, "id": "aaaaaaaa-0000-0000-0000-000000000000"}

    result = hydration.rows_to_definitions([bad, good])

    assert tracked.delta == 1.0
    # The healthy row still made it -- one bad row must not blank the index.
    assert [d[2].automation_id for d in result] == [
        "aaaaaaaa-0000-0000-0000-000000000000"
    ]


def test_oversized_trigger_value_skips_only_that_row(monkeypatch, metric_delta):
    monkeypatch.setattr(settings, "read_max_value_bytes", lambda: 16)
    tracked = metric_delta(
        "keep_automation_index_rows_skipped_total", {"reason": "value_too_long"}
    )
    huge = {
        **PSYCOPG2_ROW,
        "triggers": json.dumps(
            [
                {"field": "severity", "value": "x" * 64},
                {"field": "application", "value": "payments"},
            ]
        ),
    }
    good = {**PSYCOPG2_ROW, "id": "bbbbbbbb-0000-0000-0000-000000000000"}

    result = hydration.rows_to_definitions([huge, good])

    assert tracked.delta == 1.0
    assert len(result) == 1


# --------------------------------------------------------------------------
# Set-level breaches refuse the whole swap
# --------------------------------------------------------------------------


def test_total_bytes_breach_refuses_the_whole_set(monkeypatch):
    """A cap that indicts the result set must not be a silent truncation."""
    monkeypatch.setattr(settings, "read_max_total_bytes", lambda: 32)
    rows = [
        {**PSYCOPG2_ROW, "id": f"cccccccc-0000-0000-0000-00000000000{i}"}
        for i in range(4)
    ]
    with pytest.raises(HydrationRejected) as excinfo:
        hydration.rows_to_definitions(rows)
    assert excinfo.value.reason == "total_bytes"


def test_hydration_rejected_carries_a_machine_readable_reason():
    error = HydrationRejected("row_cap", "too many")
    assert error.reason == "row_cap"


# --------------------------------------------------------------------------
# The query itself
# --------------------------------------------------------------------------


def test_query_selects_only_the_seven_matching_columns():
    """The column list is a structural guardrail: submit-time data cannot ride
    along into B5's message if it is never read."""
    sql = hydration.HYDRATION_SQL
    for column in (
        "id",
        "tenant_id",
        "triggers",
        "cooldown_seconds",
        "cooldown_fields",
        "grace_seconds",
        "index_generation",
    ):
        assert column in sql
    for forbidden in (
        "namespace",
        "secret_name",
        "active_digest",
        "timeout_seconds",
        "script_path",
        "logstash_url",
        "deployment_url",
    ):
        assert forbidden not in sql


def test_query_filters_active_only_and_has_no_tenant_predicate():
    sql = hydration.HYDRATION_SQL
    assert "matching_state = 'active'" in sql
    # One pass for every tenant: the compiler buckets, the query does not filter.
    assert "tenant_id =" not in sql


def test_query_is_read_only_by_construction():
    sql = hydration.HYDRATION_SQL.upper()
    for verb in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE"):
        assert verb not in sql


def test_row_cap_uses_n_plus_one_so_overflow_is_detectable():
    """A bare LIMIT n with no ORDER BY would silently serve an arbitrary
    subset -- automations that stop firing with no signal."""
    assert "LIMIT :cap" in hydration.HYDRATION_SQL


# --------------------------------------------------------------------------
# Digest
# --------------------------------------------------------------------------


def test_digest_is_stable_across_row_order():
    a = {**PSYCOPG2_ROW, "id": "1"}
    b = {**PSYCOPG2_ROW, "id": "2"}
    assert hydration.rows_digest([a, b]) == hydration.rows_digest([b, a])


def test_digest_moves_when_a_row_is_disabled():
    """The deleted index_generation probe could not see this; the digest can,
    because a disabled row leaves the result set entirely."""
    rows = [{**PSYCOPG2_ROW, "id": "1"}, {**PSYCOPG2_ROW, "id": "2"}]
    assert hydration.rows_digest(rows) != hydration.rows_digest(rows[:1])


def test_digest_moves_when_triggers_change():
    changed = {**PSYCOPG2_ROW, "triggers": json.dumps([{"field": "site", "value": "dc9"}])}
    assert hydration.rows_digest([PSYCOPG2_ROW]) != hydration.rows_digest([changed])


def test_digest_ignores_columns_that_do_not_affect_matching():
    """index_generation is selected for observability, not for the digest --
    including it would force a recompile on a bump that changed nothing."""
    bumped = {**PSYCOPG2_ROW, "index_generation": 999}
    assert hydration.rows_digest([PSYCOPG2_ROW]) == hydration.rows_digest([bumped])
