# B5 Matched-Topic Implementation

## Purpose and ordering guarantee

B5 connects the existing in-memory automation index to Kafka. Each accepted alert is matched within its tenant and produces one `matched-alerts` record per matching automation.

Matched records must be acknowledged before the raw Kafka offset is committed. A publish failure leaves the raw record unresolved, allowing Kafka to redeliver it. A crash after matched delivery but before the raw commit can produce duplicates, which downstream idempotency must absorb, but it cannot lose a matched execution.

## Processing flow

1. Format and normalize accepted inbound alerts.
2. Preserve the alert occurrences before persistence deduplication removes full duplicates.
3. Complete the existing persistence flow.
4. Call `publish_matches(tenant_id, automation_events)` before optional notifications and before raw-offset resolution.
5. Pass the original alert object to B4's `match(tenant_id, alert)` function.
6. Compute and observe `matched_m` for each alert.
7. If `matched_m > 0`, validate and serialize the alert, then build one message per match.
8. Enqueue the complete fan-out and wait for every Kafka delivery callback under one shared deadline.
9. Return normally only after every matched record is acknowledged.

B4 reads the Pydantic alert object's `__dict__` directly, so matching must receive the original object. The dictionary snapshot is only for Kafka message construction. Alerts with `M=0` are neither serialized nor contract-validated and make no producer call.

## Message contract

Each matched record contains:

```json
{
  "tenant_id": "tenant-id",
  "alert": {
    "id": "upstream-alert-id",
    "fingerprint": "alert-fingerprint",
    "started_at": "2026-01-01T00:00:00Z"
  },
  "automation_id": "automation-id",
  "matched_m": 2,
  "cooldown": {
    "fields": ["site", "node_name"],
    "seconds": 600,
    "scheme_ver": 1
  }
}
```

The actual `alert` member is the complete JSON-compatible alert snapshot. Before publishing a matched message, B5 requires non-empty `id`, `fingerprint`, and `started_at` fields.

The gateway-provided `id` is preserved. B5 does not create `history_id` and does not substitute the database-generated `event_id`. Every Kafka record uses the UTF-8 `automation_id` as its partition key. All messages for one alert carry the same `matched_m`.

## Cooldown

Cooldown is resolved when B4 hydrates an automation and is carried in `AutomationMatch`. B5 does not enforce cooldown and performs no Redis or database lookup for it; it copies the resolved configuration for the downstream consumer.

- `cooldown: null` means cooldown is disabled.
- `seconds` is the cooldown duration.
- `fields` identifies alert fields used downstream to build the cooldown key.
- Empty `fields` means one cooldown gate for the whole automation.
- Field order is preserved as authored; downstream canonicalization owns sorting.
- `scheme_ver` is currently `1` and versions the downstream key algorithm.

## Producer

`src/bl/automations/producer.py` adds a synchronous, process-local `confluent_kafka.Producer` with:

- `enable.idempotence=true` and `acks=all`.
- Complete fan-out enqueue before acknowledgement waiting.
- Delivery callbacks required for success; local queueing is not success.
- Bounded queue-full polling and retry without spinning.
- One deadline for the whole per-alert batch.
- Unhealthy state and `MatchedPublishError` on partial or failed delivery.
- Bounded shutdown flush with an undelivered-record log.
- No payload or credential logging.

The producer uses independent Kafka settings rather than the raw consumer's environment:

```text
MATCHED_KAFKA_BOOTSTRAP_SERVERS        default: localhost:29092
MATCHED_KAFKA_SECURITY_PROTOCOL       default: PLAINTEXT
MATCHED_KAFKA_SASL_MECHANISM          default: PLAIN
MATCHED_KAFKA_SASL_USERNAME
MATCHED_KAFKA_SASL_PASSWORD
MATCHED_KAFKA_SSL_CAFILE
MATCHED_KAFKA_SSL_CERTFILE
MATCHED_KAFKA_SSL_KEYFILE
```

Publishing controls are:

```text
AUTOMATION_MATCHED_PUBLISH_ENABLED            default: false
MATCHED_ALERTS_TOPIC                           default: matched-alerts
AUTOMATION_MATCHED_PUBLISH_TIMEOUT_SECONDS     default: 5.0
AUTOMATION_MATCHED_QUEUE_RETRY_SECONDS         default: 0.01
AUTOMATION_MATCHED_SHUTDOWN_TIMEOUT_SECONDS    default: 3.0
```

Timeout and retry settings are clamped to positive minimums.

## Readiness and lifecycle

The producer starts beside the trigger index before consumption and flushes during shutdown. When publishing is enabled, `/readyz` requires producer health. Startup checks broker metadata and confirms that `MATCHED_ALERTS_TOPIC` exists. An unhealthy result is logged safely and returns HTTP 503; later readiness checks attempt recovery.

Producer health does not affect `/livez`. When publishing is disabled, readiness is neutral and no Kafka client is constructed.

The repository Docker Compose file runs infrastructure only. A handler on the host can use `localhost:29092`; one inside the Compose network should use `MATCHED_KAFKA_BOOTSTRAP_SERVERS=kafka:9092`. A0 owns topic provisioning, so B5 does not create `matched-alerts` in Compose.

## Raw-offset failure handling

`MatchedPublishError` propagates through `process_event_sync` into the raw consumer. Existing bounded retries still apply, but exhaustion returns the raw record as unresolved rather than routing it through the terminal poison-record path. Consequently, the failing raw offset and later contiguous offsets are not committed, and redelivery republishes the complete fan-out.

## Metrics

The following bounded-cardinality Prometheus metrics were added:

- `keep_automation_alerts_probed_total`
- `keep_automation_alerts_matched_total`
- `keep_automation_matched_m`, including `M=0`
- `keep_automation_matched_publish_total{result="acknowledged|failed"}`
- `keep_automation_matched_publish_duration_seconds`
- `keep_automation_matched_producer_ready`

Match rate is derived from the matched and probed counters; the histogram exposes the M distribution.

## Files changed

- `src/bl/automations/producer.py`: producer, acknowledgements, health, and shutdown.
- `src/bl/automations/publish_matches.py`: matching orchestration, contract construction, metrics, and publishing.
- `src/bl/automations/settings.py` and `src/config/consts.py`: rollout and timeout configuration.
- `src/consumer_main.py`: producer lifecycle and readiness.
- `src/core/kafka_consumer.py`: unresolved failure handling that prevents raw commits.
- `src/core/metrics.py`: B5 metrics.
- `src/event_management/process_event_task.py`: hot-path integration before optional notification behavior.
- `src/models/alert.py`: existing upstream `id` and `started_at`; no `history_id` addition.
- Tests cover contracts, dedicated Kafka settings, fan-out, delivery failure, readiness, original-object matching, and raw-offset behavior.

## Verification

The latest focused run passed 98 tests. It covered matched publishing, the real index contract, readiness/liveness, and retry-budget behavior. Two pre-existing warnings remain: SQLAlchemy's deprecated `utcfromtimestamp()` usage and an unavailable pytest `timeout` configuration plugin.
