"""Every failure mode this design has must be separately visible.

This is not a smoke test for the prometheus library -- it is the guard that the
detection story the spec leans on actually exists. A metric that was never
registered cannot be alerted on, and the failure is silent.
"""

import pytest
from prometheus_client import REGISTRY

from src.core import metrics

# name -> label names it must carry. Each entry corresponds to a distinct state
# the runbooks have to tell apart.
REQUIRED_INSTRUMENTS = {
    "keep_automation_index_ready": (),
    "keep_automation_index_config_missing": ("setting",),
    "keep_automation_index_worker_alive": (),
    "keep_automation_index_last_successful_reload_timestamp": (),
    "keep_automation_index_size": (),
    "keep_automation_index_tenants": (),
    "keep_automation_index_generation": (),
    "keep_automation_index_reloads_total": ("trigger", "result"),
    "keep_automation_index_reload_duration_seconds": (),
    "keep_automation_index_rows_skipped_total": ("reason",),
    "keep_automation_index_rows_rejected_total": ("reason",),
    "keep_automation_index_readonly_verification_failures_total": (),
    "keep_automation_index_hydrate_rate_limited_total": (),
    "keep_automation_pubsub_connected": (),
    "keep_automation_pubsub_reconnects_total": (),
    "keep_automation_index_matches_skipped_total": ("reason",),
    "keep_automation_match_duration_seconds": (),
}


def _collector_names() -> dict:
    found = {}
    for collector in list(REGISTRY._collector_to_names):  # noqa: SLF001
        for metric in collector.collect():
            found[metric.name] = tuple(getattr(collector, "_labelnames", ()))
    return found


@pytest.mark.parametrize("name", sorted(REQUIRED_INSTRUMENTS))
def test_instrument_is_registered(name):
    # Counters register as `<name>_total`; collect() reports the base name.
    base = name[: -len("_total")] if name.endswith("_total") else name
    assert base in _collector_names(), f"{name} is not registered"


@pytest.mark.parametrize("name,labels", sorted(REQUIRED_INSTRUMENTS.items()))
def test_instrument_carries_the_expected_labels(name, labels):
    base = name[: -len("_total")] if name.endswith("_total") else name
    assert _collector_names()[base] == labels


def test_no_instrument_carries_a_tenant_label():
    """A tenant label on a per-replica metric is unbounded cardinality.

    The spec pins index_size/index_tenants as unlabelled totals for exactly
    this reason; the per-tenant question is query-time and belongs to B5.
    """
    for labels in REQUIRED_INSTRUMENTS.values():
        assert "tenant" not in labels
        assert "tenant_id" not in labels
        assert "automation_id" not in labels


def test_match_duration_buckets_straddle_the_slo():
    """The story's bar is p99 < 1ms; a histogram with no bucket near 1ms
    cannot answer whether it is met."""
    buckets = metrics.automation_match_duration_seconds._upper_bounds  # noqa: SLF001
    assert 1e-3 in buckets
    assert min(buckets) < 1e-3 < max(buckets)


def test_metric_delta_helper_reports_movement(metric_delta):
    """The helper the rest of the suite relies on to stay order-independent."""
    labels = {"reason": "delta_self_test"}
    tracked = metric_delta("keep_automation_index_rows_skipped_total", labels)
    metrics.automation_index_rows_skipped_total.labels(**labels).inc()
    assert tracked.delta == 1.0
