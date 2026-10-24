from unittest.mock import patch

from src.core.tenant_resolution import (
    _extract_operator,
    _resolve_ingestion_tenant,
    GENERIC_TENANT_UUID,
)


class FakeOperator:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id


def test_extract_operator_from_dict():
    assert _extract_operator({"operator": "acme"}) == "acme"


def test_extract_operator_from_list():
    assert _extract_operator([{"operator": "acme"}, {"operator": "other"}]) == "acme"


def test_extract_operator_missing_returns_none():
    assert _extract_operator({"name": "no operator"}) is None


def test_extract_operator_none_event_returns_none():
    assert _extract_operator(None) is None


def test_extract_operator_non_dict_returns_none():
    class NotADict:
        operator = "should-be-ignored"

    assert _extract_operator(NotADict()) is None


def test_resolve_no_operator_routes_to_general():
    with patch(
        "src.core.tenant_resolution.get_operator_by_name"
    ) as lookup:
        resolved = _resolve_ingestion_tenant({"name": "no operator"})
        assert resolved == GENERIC_TENANT_UUID
        lookup.assert_not_called()


def test_resolve_unknown_operator_routes_to_general():
    with patch(
        "src.core.tenant_resolution.get_operator_by_name", return_value=None
    ) as lookup:
        resolved = _resolve_ingestion_tenant({"operator": "unknown"})
        assert resolved == GENERIC_TENANT_UUID
        lookup.assert_called_once_with("unknown")


def test_resolve_known_operator_routes_to_operators_tenant():
    operator = FakeOperator(tenant_id="tenant-acme")
    with patch(
        "src.core.tenant_resolution.get_operator_by_name", return_value=operator
    ) as lookup:
        resolved = _resolve_ingestion_tenant({"operator": "acme"})
        assert resolved == "tenant-acme"
        lookup.assert_called_once_with("acme")