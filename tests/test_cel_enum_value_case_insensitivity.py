"""Enum literal case-folding in this service's copy of properties_mapper.py.

`cel_to_sql/properties_mapper.py` is duplicated across keep-api-gateway,
keep-event-handler and keep-workflows. The facets panel renders enum values
capitalized while the database stores them lowercase, so a literal compared
against a property that declares `enum_values` must be resolved to its canonical
member case-insensitively. This test pins that behavior locally so the copies
cannot drift apart again.
"""

import pytest

from src.core.cel_to_sql.ast_nodes import DataType
from src.core.cel_to_sql.properties_metadata import (
    FieldMappingConfiguration,
    PropertiesMetadata,
)
from src.core.cel_to_sql.sql_providers.get_cel_to_sql_provider_for_dialect import (
    get_cel_to_sql_provider_for_dialect,
)

DIALECTS = ["sqlite", "mysql", "postgresql"]

properties_metadata = PropertiesMetadata(
    [
        FieldMappingConfiguration(
            map_from_pattern="status",
            map_to="alert.status",
            data_type=DataType.STRING,
            enum_values=["acknowledged", "resolved", "firing"],
        ),
        FieldMappingConfiguration(
            map_from_pattern="severity",
            map_to="alert.severity",
            data_type=DataType.STRING,
            enum_values=["low", "info", "warning", "high", "critical"],
        ),
        FieldMappingConfiguration(
            map_from_pattern="name",
            map_to="alert.name",
            data_type=DataType.STRING,
        ),
    ]
)


def _all_dialects(expected_sql):
    return {dialect: expected_sql for dialect in DIALECTS}


TEST_CASES = {
    "eq folds to the canonical member": (
        "status == 'Firing'",
        _all_dialects("alert.status = 'firing'"),
    ),
    "ne folds to the canonical member": (
        "status != 'FIRING'",
        _all_dialects("alert.status != 'firing'"),
    ),
    "in folds every element": (
        "status in ['Firing', 'Resolved']",
        _all_dialects("alert.status in ('firing', 'resolved')"),
    ),
    "gt on the highest member matches nothing": (
        "severity > 'Critical'",
        {"sqlite": "false", "mysql": "FALSE", "postgresql": "false"},
    ),
    "ge excludes lower ranks": (
        "severity >= 'Info'",
        _all_dialects("alert.severity in ('info', 'warning', 'high', 'critical')"),
    ),
    "free text keeps its casing": (
        "name == 'Firing'",
        _all_dialects("alert.name = 'Firing'"),
    ),
    "unknown enum literal passes through": (
        "status == 'flapping'",
        _all_dialects("alert.status = 'flapping'"),
    ),
}


@pytest.mark.parametrize("dialect", DIALECTS)
@pytest.mark.parametrize("case_name", list(TEST_CASES.keys()))
def test_enum_literal_case_insensitivity(case_name, dialect):
    cel, expected_by_dialect = TEST_CASES[case_name]
    actual_sql = get_cel_to_sql_provider_for_dialect(
        dialect, properties_metadata
    ).convert_to_sql_str(cel)
    assert actual_sql == expected_by_dialect[dialect]
