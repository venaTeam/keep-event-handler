"""Metric definitions for the event handler.

prometheus_client is imported via `prometheus_multiproc`, never directly: the
multiprocess directory has to be settled before that library first loads, and
that ordering is isolated in the one module whose job it is.
"""

from src.core.prometheus_multiproc import Counter, Gauge, Histogram, Summary

METRIC_PREFIX = "keep_"

### INCIDENTS
INCIDENT_METRIC_PREFIX = "keep_incident_"

incidents_opened_total = Counter(
    f"{INCIDENT_METRIC_PREFIX}opened_total",
    "Total number of incidents opened",
    labelnames=["tenant_id", "rule_id", "rule_name"],
)

### MAINTENANCE
MAINTENANCE_METRIC_PREFIX = "keep_maintenance_"

alerts_maintenance_silenced_total = Counter(
    f"{MAINTENANCE_METRIC_PREFIX}silenced_total",
    "Total number of alerts silenced by maintenance window",
    labelnames=["tenant_id", "maintenance_window_id", "maintenance_window_name"],
)

# Process event metrics
#
# Both carry `event_type` (alert | incident | enrich | batch_enrich | delete, plus
# the two sentinels below). Without it these count all five types together, so
# they cannot be reconciled against the producer's `alert_ingestion_total`, which
# counts alerts only — and that reconciliation is how a cutover proves no alert
# was dropped. Aggregate queries want `sum(keep_events_in_total)`; a bare
# `keep_events_in_total` still selects every series, but any rule that assumed a
# single unlabelled series needs updating.
#
# Incremented exactly once per Kafka message, in `_process_message`. They used to
# be incremented there AND again inside `process_event`, which is on the alert
# path only — so alerts counted double and the other four types counted single,
# making the total a number that matched nothing.
EVENT_TYPE_UNDECODABLE = "undecodable"  # message body was not valid JSON
EVENT_TYPE_UNKNOWN = "unknown"  # decoded, but carried no event_type

events_in_counter = Counter(
    f"{METRIC_PREFIX}events_in_total",
    "Total number of events received",
    labelnames=["event_type"],
)
events_out_counter = Counter(
    f"{METRIC_PREFIX}events_processed_total",
    "Total number of events processed",
    labelnames=["event_type"],
)
events_error_counter = Counter(
    f"{METRIC_PREFIX}events_error_total",
    "Total number of events with error",
)
processing_time_summary = Summary(
    f"{METRIC_PREFIX}processing_time_seconds",
    "Average time spent processing events",
)
# Number of records returned by a single Kafka poll (i.e. the batch size).
# A distribution skewed toward 1 means batches are not forming (light traffic
# or KAFKA_CONSUMER_BATCH_SIZE=1); higher buckets confirm batch consumption.
consume_batch_size = Histogram(
    f"{METRIC_PREFIX}consume_batch_size",
    "Number of records processed per Kafka poll",
    buckets=(1, 2, 5, 10, 25, 50, 100, 250),
)

### ALERTS
ALERT_METRIC_PREFIX = "keep_alert_"

alert_enrichment_duration_seconds = Histogram(
    f"{ALERT_METRIC_PREFIX}enrichment_duration_seconds",
    "Time spent enriching alerts",
    labelnames=["source"],
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30),
)

deduplication_events_total = Counter(
    f"{ALERT_METRIC_PREFIX}deduplication_events_total",
    "Total number of deduplicated events",
    labelnames=["provider_type", "status"],
)

deduplication_duration_seconds = Histogram(
    f"{ALERT_METRIC_PREFIX}deduplication_duration_seconds",
    "Time spent deduplicating events",
    labelnames=["provider_type"],
)

rules_engine_duration_seconds = Histogram(
    f"{ALERT_METRIC_PREFIX}rules_engine_duration_seconds",
    "Time spent in rules engine",
    labelnames=["provider_type"],
)


### AUTOMATIONS TRIGGER INDEX (B4)
AUTOMATION_METRIC_PREFIX = "keep_automation_"

# Boot signal only. A dead reload worker leaves this at 1 -- the alert for that
# is staleness on index_last_successful_reload_timestamp, not this gauge.
automation_index_ready = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_ready",
    "1 once a hydrate has succeeded and an index is published",
)
# The deployment gate (AUTOMATION_INDEX_ENABLED), reported so that "off on
# purpose" and "should be running but isn't" are different observations.
#
# Without this, index_worker_alive == 0 is ambiguous the moment a gate exists,
# and the alert that catches a dead worker would fire on every pod that is
# correctly switched off -- which is how a real alert gets muted. Every
# automations alert should be qualified with `index_enabled == 1`.
automation_index_enabled = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_enabled",
    "1 when AUTOMATION_INDEX_ENABLED is set; 0 when the feature is switched off",
)
# Distinct from index_ready on purpose: two states, two runbooks. ready==0 means
# "no usable index, matching is silently doing nothing"; config_missing means
# "the index is fine, convergence is slower than advertised".
automation_index_config_missing = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_config_missing",
    "1 when an optional setting is unset and a capability is degraded",
    labelnames=["setting"],
)
# Set to 1 from inside the worker loop, and to 0 on a clean stop.
#
# Read it honestly: nothing resets this if the thread DIES, so a 1 does not
# prove liveness. What it does prove is that the loop ran at least once -- so a
# scrape showing 0 means the index never started, which is the "watcher never
# starts in deployment" failure class this platform has already shipped once.
# The detector for a worker that started and then died is staleness on
# index_last_successful_reload_timestamp.
automation_index_worker_alive = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_worker_alive",
    "1 once the reload worker loop has run; 0 before start and after a clean stop",
)
automation_index_last_successful_reload_timestamp = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_last_successful_reload_timestamp",
    "Unix seconds of the last hydrate that completed without error",
)
# Unlabelled totals. A `tenant` label here would be unbounded cardinality on a
# metric scraped from every replica; the per-tenant question is query-time, B5's.
automation_index_size = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_size",
    "Active automations in the published index, all tenants",
)
automation_index_tenants = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_tenants",
    "Tenants with at least one active automation in the published index",
)
# The probe is linear in candidates-per-posting-list, and MEASURED p99 crosses
# the 1ms SLO at roughly 1400 automations sharing one pivot. The row cap is
# fleet-wide (a different dimension) and defaults above that, so it cannot
# bound this. Exporting the largest list is what makes the SLO risk visible
# before a probe is slow rather than after.
automation_index_largest_posting_list = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_largest_posting_list",
    "Automations sharing a single (field, value) pivot in the published index",
)
automation_index_generation = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}index_generation",
    "max(index_generation) observed in the applied index",
)
automation_index_reloads_total = Counter(
    f"{AUTOMATION_METRIC_PREFIX}index_reloads_total",
    "Reload attempts by what triggered them and how they ended",
    labelnames=["trigger", "result"],
)
automation_index_reload_duration_seconds = Histogram(
    f"{AUTOMATION_METRIC_PREFIX}index_reload_duration_seconds",
    "Wall time of a hydrate + compile + swap cycle",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
# Both of these are security signals, not debug counters: nonzero means the
# control plane wrote something this service refuses to index.
automation_index_rows_skipped_total = Counter(
    f"{AUTOMATION_METRIC_PREFIX}index_rows_skipped_total",
    "Rows skipped at compile, by reason",
    labelnames=["reason"],
)
automation_index_rows_rejected_total = Counter(
    f"{AUTOMATION_METRIC_PREFIX}index_rows_rejected_total",
    "Hydrates refused wholesale because the result set breached a cap",
    labelnames=["reason"],
)
automation_index_readonly_verification_failures_total = Counter(
    f"{AUTOMATION_METRIC_PREFIX}index_readonly_verification_failures_total",
    "Hydrate transactions that were not actually read-only",
)
automation_index_hydrate_rate_limited_total = Counter(
    f"{AUTOMATION_METRIC_PREFIX}index_hydrate_rate_limited_total",
    "Reload signals dropped by the minimum-hydrate-interval floor",
)
# Derived from last message / last successful health check, NOT from socket
# state: an idle-timeout device can drop the connection while the socket looks
# alive and get_message() returns None forever with no exception.
automation_pubsub_connected = Gauge(
    f"{AUTOMATION_METRIC_PREFIX}pubsub_connected",
    "1 while the reload subscriber is believed live",
)
automation_pubsub_reconnects_total = Counter(
    f"{AUTOMATION_METRIC_PREFIX}pubsub_reconnects_total",
    "Reload subscriber reconnect attempts",
)
automation_index_matches_skipped_total = Counter(
    f"{AUTOMATION_METRIC_PREFIX}index_matches_skipped_total",
    "match() calls that returned empty for a reason other than no match",
    labelnames=["reason"],
)
# The p99 < 1ms SLO instrument. Observed with a bare perf_counter delta rather
# than the .time() context manager, which allocates a Timer per call -- the
# instrument would otherwise cost more than the probe it measures.
automation_match_duration_seconds = Histogram(
    f"{AUTOMATION_METRIC_PREFIX}match_duration_seconds",
    "Wall time of a match() probe on the consumer thread",
    buckets=(5e-5, 1e-4, 2.5e-4, 5e-4, 1e-3, 2.5e-3, 5e-3, 1e-2),
)
