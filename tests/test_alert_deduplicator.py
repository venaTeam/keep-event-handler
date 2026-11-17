from types import SimpleNamespace

import pytest

from src.alert_deduplicator.alert_deduplicator import AlertDeduplicator
from src.models.alert import AlertDto


def _alert(time_created):
    return AlertDto(
        id="alert-id",
        name="same-alert",
        status="firing",
        severity="warning",
        fingerprint="stable-fingerprint",
        time_created=time_created,
        last_received="2026-01-01T00:00:00Z",
    )


@pytest.mark.parametrize("ignore_fields", [[], ["time_created"]])
def test_custom_rule_controls_whether_time_created_changes_dedup_hash(ignore_fields):
    deduplicator = AlertDeduplicator("tenant")
    rule = SimpleNamespace(ignore_fields=ignore_fields, id="rule-id")

    first = deduplicator._apply_deduplication_rule(
        _alert("2026-01-01T00:00:00Z"), rule, {"other-fingerprint": "other-hash"}
    )
    second = deduplicator._apply_deduplication_rule(
        _alert("2026-01-01T01:00:00Z"),
        rule,
        {"stable-fingerprint": first.alert_hash},
    )

    if "time_created" in ignore_fields:
        assert first.alert_hash == second.alert_hash
        assert second.is_full_duplicate is True
    else:
        assert first.alert_hash != second.alert_hash
        assert second.is_partial_duplicate is True


def test_default_rule_documents_time_created_as_ignored():
    rule = AlertDeduplicator("tenant")._get_default_full_deduplication_rule(
        provider_id=None, provider_type=None
    )

    assert set(rule.ignore_fields) >= {"last_received", "time_created"}
