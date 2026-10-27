# Log observability — shared Elasticsearch mapping

Both `keep-api-gateway` and `keep-event-handler` ship JSON logs (via Fluent Bit)
to the same Elasticsearch. This directory holds the **shared index template** that
keeps that index organized.

## Why this is needed

The Python JSON formatter (`python-json-logger`) promotes **every** `extra={...}`
key on a log record to a top-level JSON field. Across both services that is
hundreds of distinct keys, and several of them (`alert`, `event`, `payload`,
`incident_dto`, `tags`, `context`, `status`, ...) appear **sometimes as a string
and sometimes as an object/number** depending on the call site.

With Elasticsearch's default **dynamic mapping**, the first document fixes each
field's type; a later document with a different shape for the same field is
**rejected** with `document_mapping_exception`. That is the usual cause of "logs
are not ingested properly" — a subset of records silently fails to index — and it
also produces the per-rule field sprawl.

## What the template does

`elasticsearch-index-template.json` sets:

- **`dynamic: false`** — unknown fields are still stored in `_source` (you see them
  when you open a document in Discover) but are **not** added to the mapping and
  **not** indexed. No mapping growth, and — because unknown fields are never
  type-checked — **no more conflict rejections**.
- **Explicit mappings** for the stable formatter fields and the high-value
  correlation keys (`tenant_id`, `provider_id`, `incident_id`, `rule_id`,
  `alert_id`, `execution_id`, `fingerprint`, `event_type`, `otelServiceName`, ...)
  so those stay searchable/aggregatable.
- **Exception / error fields are first-classed** so error logs stay debuggable:
  `exc_info` (the traceback string emitted by `python-json-logger` for
  `logger.exception(...)` / `exc_info=True`), `stack_info`, `exception`, `error`,
  `error_type`, `error_message`, `error_msg`. Without these in the mapping,
  `dynamic:false` would keep the traceback in `_source` but leave it unindexed —
  invisible in Kibana's field list and unsearchable.
- **`index.mapping.ignore_malformed: true`** — safety net: if an explicitly-mapped
  scalar field ever receives a bad value, that one field is skipped instead of the
  whole document being rejected.

Service identity lives in **`otelServiceName`** (gateway = its OTel service name,
default `keep-api`; event-handler = `keep-event-handler`) — the same field in both,
so they share one mapping and are told apart by value. Filter by `otelServiceName`
in Kibana. (The event-handler previously emitted a separate `service` field; that
was removed so the two schemas match.)

## Apply it

Set `index_patterns` to the index your Fluent Bit `OUTPUT` actually writes to
(keep both services on one `keep-*` index if you want a single view), then:

```bash
# Against Elasticsearch directly (adjust host/auth for your ECK):
curl -X PUT "http://<es-host>:9200/_index_template/keep-logs" \
  -H 'Content-Type: application/json' \
  --data-binary @observability/elasticsearch-index-template.json
```

Or paste the body into **Kibana → Dev Tools**:
`PUT _index_template/keep-logs` followed by the JSON.

The template applies to **newly created** indices. If the current index already has
a broken/conflicting mapping, roll it over (or reindex) after applying:

```bash
# simplest for a fixed-name index: create the next index so the template takes effect
curl -X POST "http://<es-host>:9200/<index>/_rollover"
```

> Local dev: the `observability` profile in `docker-compose.infra.yml` runs
> Elasticsearch with dynamic mapping (low volume, no template needed). Apply this
> template to your **dev/prod ECK**, where the field variety causes the conflicts.
