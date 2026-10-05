from types import SimpleNamespace

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


def test_time_created_does_not_change_dedup_hash_for_custom_rule():
    deduplicator = AlertDeduplicator("tenant")
    rule = SimpleNamespace(ignore_fields=[], id="rule-id")

    first = deduplicator._apply_deduplication_rule(
        _alert("2026-01-01T00:00:00Z"), rule, {"other-fingerprint": "other-hash"}
    )
    second = deduplicator._apply_deduplication_rule(
        _alert("2026-01-01T01:00:00Z"),
        rule,
        {"stable-fingerprint": first.alert_hash},
    )

    assert first.alert_hash == second.alert_hash
    assert second.is_full_duplicate is True


def test_default_rule_documents_time_created_as_ignored():
    rule = AlertDeduplicator("tenant")._get_default_full_deduplication_rule(
        provider_id=None, provider_type=None
    )

    assert set(rule.ignore_fields) >= {"last_received", "time_created"}
