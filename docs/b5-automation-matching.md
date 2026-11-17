# B5: automation matching and matched delivery

The event handler probes the B4 in-memory trigger index after normal alert
processing and publishes one message for every `(alert, automation)` match.
Matching is tenant-scoped: the alert's `tenant_id` selects the tenant bucket
before any trigger candidates are evaluated. The hot path does not query the
automation database.

`AUTOMATION_MATCHING_ENABLED` is the single feature gate for index hydration,
matching, the matched producer, and its readiness checks. It defaults to false
and requires a restart when changed. When disabled, no automation Kafka client
or reload worker is created and matching returns no results.

## Matched-message contract

Each message contains:

```json
{
  "tenant_id": "keep",
  "alert": {
    "id": "evt-789",
    "fingerprint": "abc123",
    "time_created": "2026-07-12T14:03:00Z"
  },
  "automation_id": "3f2b...",
  "matched_m": 2,
  "cooldown": {
    "fields": ["node_name", "site"],
    "seconds": 300,
    "scheme_ver": 1
  }
}
```

The `alert` value is the complete alert snapshot; the example only shows the
required identity fields. `cooldown` is null when cooldown is disabled. The
Kafka partition key is `automation_id`. `matched_m` is the number of matches for
that alert and is repeated on every message in its fan-out.

The canonical wire identity is `alert.id`. Downstream API and database fields
may retain the historical name `history_id`, but they must carry this same
value. Consumers that still read only `alert.history_id` are not compatible
with this producer.

Before sending any message for an alert, the publisher validates the alert's
complete fan-out. `id`, `fingerprint`, and `time_created` must be non-empty
strings, automation IDs must be non-empty strings, and the payload must encode
as strict JSON. Contract-invalid alerts are written to the matched DLQ as
bounded `contract_rejection` envelopes with `replayable=false`; valid alerts in
the same raw record continue normally.

## Processing and delivery order

For each raw record, the event handler:

1. snapshots alerts for automation processing before full duplicates are
   removed, so a raw redelivery can repair an interrupted matched delivery;
2. completes alert persistence, Elasticsearch indexing, correlation, and
   notification scheduling;
3. stamps B6 fingerprint coverage for matched alerts;
4. publishes the matched fan-out and waits for acknowledgements; and
5. allows the raw offset to commit only after every required message is
   acknowledged by the matched topic or the matched DLQ.

Publishing is at-least-once. A crash after an acknowledgement but before the
raw commit can republish a message, so downstream Redis and database
idempotency remain required. Notification delivery is best-effort and does not
gate the raw offset.

The matched producer uses a single bounded deadline, acknowledgement-bearing
delivery, idempotent Kafka production, and `automation_id` as the partition
key. Confirmed siblings are not resent within the same publish call. Failed or
unconfirmed messages fall back to a separately configured, acknowledged DLQ.

## Offset and DLQ rules

| Result for one raw record | Raw offset |
|---|---|
| No matches | Commit |
| Every message acknowledged by the matched topic | Commit |
| Failed or invalid messages acknowledged by the matched DLQ | Commit |
| Any required matched or DLQ acknowledgement is missing | Do not commit |
| Shutdown during unresolved delivery | Do not commit |

When both destinations fail, the consumer rewinds and pauses the affected raw
partition, then retries with bounded backoff. A contiguous-offset barrier stops
later records in that partition from committing past the unresolved record;
other partitions continue. Rebalance or shutdown never commits through the
barrier.

DLQ recovery must publish repaired matched messages directly. It must not
re-ingest raw alerts, because persistence, incident correlation, enrichment,
and SSE work have already happened. Contract-rejection envelopes require manual
repair before redrive. This repository does not include an automatic redrive
worker, transactional outbox, database migration, or in-memory replay cache.

Provision `MATCHED_KAFKA_DLQ_TOPIC` and its describe/write ACLs before enabling
matching. The DLQ connection inherits `MATCHED_KAFKA_*` settings unless
`MATCHED_KAFKA_DLQ_*` overrides are supplied. A DLQ on the same Kafka cluster
does not protect against a cluster-wide outage.

## Readiness and operations

When matching is enabled, readiness reports the matched producer and DLQ
producer independently. Metadata recovery does not erase a recorded delivery
failure, and DLQ success does not mark the main producer healthy. Liveness stays
independent so a broker outage does not create a restart loop.

Operators should monitor:

- `keep_automation_index_enabled`, `keep_automation_index_ready`, and the last
  successful reload timestamp;
- `keep_automation_index_largest_posting_list` for match-probe latency;
- match rate, `matched_m`, and contract-rejection metrics;
- matched publish acknowledgement/failure metrics; and
- matched-DLQ delivery, readiness, and unresolved-partition metrics.

The full environment-variable reference and recovery notes remain in the
repository README. The authoritative cross-service schema is maintained in the
workspace `automation-contracts.md` document.

## Verification

Coverage lives primarily in `tests/automations/` and includes tenant isolation,
index reload and failure behavior, message validation, partial delivery,
producer deadlines, DLQ fallback, readiness, and processing order. Consumer
tests cover the contiguous commit barrier, rewind/pause/resume behavior,
rebalance, and shutdown. Tests requiring live Postgres, Redis, or Kafka skip
when those services are unavailable.
