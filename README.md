# keep-event-handler

Asynchronous event processing for the Keep platform. Consumes the raw alert
topic from Kafka and updates the database: deduplication, enrichment,
maintenance windows, incident correlation via the rules engine, and SSE notify.

Two entrypoints:

| Entrypoint | What it is | Command |
|---|---|---|
| `src/consumer_main.py` | the standalone Kafka consumer — this is what the container runs | `poetry run python -m src.consumer_main` |
| `src/main.py` | a FastAPI app serving health + metrics only | runs under gunicorn |

## Ports

| Port | Server |
|---|---|
| 8092 | health check |
| 8094 | Prometheus metrics |

### Probes

The health server binds **before** the blocking startup work, so a pod waiting
on the gateway's schema reports "alive, not ready" instead of refusing
connections.

| Path | Probe | Green when |
|---|---|---|
| `/readyz`, `/ready` | readiness | consuming **and** partitions assigned (or revoked inside the grace window) **and** last poll recent |
| `/livez`, `/`, `/health`, `/healthz` | liveness | the consume loop is polling; always green while starting or draining |

`/`, `/health`, `/healthz` and `/ready` are legacy aliases kept so the image and
the chart's probe paths can ship independently. Deployment details, required
chart changes and the full-group restart runbook:
[`docs/deploy/ingestion-resilience.md`](docs/deploy/ingestion-resilience.md).

These are the code defaults *and* the container `ENV`, and they must stay in
agreement — `config()` reads `os.environ` first, so a Docker `ENV` silently wins
over the code default. `tests/automations/test_container_ports.py` guards this.

> The consumer's metrics come from `prometheus_client.start_http_server` on
> 8094 (in-process registry). The FastAPI app's `/v1/metrics` route uses a
> `MultiProcessCollector` and **shares no data with it** — scrape the consumer.

## Running locally

```bash
docker compose -f docker-compose.infra.yml up -d   # kafka, postgres, redis, soketi
poetry install

# Optional: the reload pub/sub channel. Without it the index still reloads on
# its timer -- see "two degraded states" below. This stack maps redis to 6380
# so it cannot collide with the keepHQ root stack's 6379.
export REDIS_URL=redis://localhost:6380/0

poetry run python -m src.consumer_main
```

If you are running the **keepHQ root stack** instead (the one that serves all six
services), redis is on the usual `redis://localhost:6379/0`.

`keep-api-gateway` owns the schema on the shared `keep` database — this service
waits for it rather than building it (`src/core/db/db_on_start.py`). Apply the
gateway's Alembic migrations before starting the consumer against a fresh
database.

## Configuration

Only the variables that are not self-explanatory are listed. Everything is read
through `src/config/consts.py`.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_CONNECTION_STRING` | `postgresql://keep:keep@localhost:5432/keep` | The shared `keep` database. The automations trigger index reads through this same engine — there is no second DSN. |
| `MESSAGING_TYPE` | `KAFKA` | The consumer hard-exits on anything else. |
| `HEALTH_CHECK_PORT` / `PROMETHEUS_METRICS_PORT` | `8092` / `8094` | See Ports above. |
| `KAFKA_PARTITION_ASSIGNMENT_STRATEGY` | `cooperative-sticky` | Eager and cooperative members cannot coexist in one group, so **changing this needs a full-group restart** (scale to 0, then up) — never a rolling update. `range,roundrobin` is the rollback lever. |
| `KEEP_CONSUMER_*_MAX_POLL_GAP_SECONDS` | `90` (ready) / `300` (live) | Probe thresholds. The liveness gap must stay above the retry budget (`0.8 × max.poll.interval.ms`) or Kubernetes kills pods that are retrying as designed. |
| `KEEP_CONSUMER_READY_REQUIRE_PARTITIONS` | `true` | Set `false` when the topic has fewer partitions than replicas — otherwise a surge pod Kafka gives nothing never goes Ready and the rollout stalls. |
| `KEEP_SCHEMA_EXPECTED_REVISION` | *(unset)* | Exact alembic revision to wait for. Without it the wait accepts a *quiescent* head, and a **down** gateway's stale head is perfectly quiescent. |
| `KEEP_PROVISIONING_FATAL` | `false` | Provisioning failures are logged and stepped over. `true` restores fail-fast for CI, where a bad provider file should fail loudly. |

The remaining resilience knobs (`KEEP_SCHEMA_REQUIRED_TABLES`,
`KEEP_SCHEMA_RETRY_BACKOFF_*`, `KEEP_CONSUMER_REVOKE_GRACE_SECONDS`,
`KAFKA_HEARTBEAT_INTERVAL_MS`) are documented in
[`docs/deploy/ingestion-resilience.md`](docs/deploy/ingestion-resilience.md).

### Automations trigger index

An in-memory, per-tenant index of active automations, used to decide which
automations an alert matches. It reads the gateway-owned `automations` table and
**never writes to it**; the hydration transaction is explicitly read-only, and
that read-only scope is the transaction alone — it must never reach the
connection, the session or the engine, all of which are shared with every write
this service performs.

| Variable | Default | Purpose |
|---|---|---|
| `AUTOMATION_INDEX_ENABLED` | `false` | **Deployment gate for this whole surface.** Off means no reload worker, no `reload` subscriber, no hydrate query, and `match()` returns nothing for every alert. The automations feature spans several stories and repos, so the code ships before it is ready to run. |
| `REDIS_URL` | *(empty)* | The `reload` pub/sub channel. See the degradation note below. |
| `AUTOMATION_RELOAD_CHANNEL` | `reload` | Channel name, pinned by `automation-contracts.md`. |
| `AUTOMATION_INDEX_RELOAD_SECONDS` | `30` | Unconditional full reload interval. This is the staleness bound. |
| `AUTOMATION_INDEX_MIN_HYDRATE_INTERVAL_SECONDS` | `5` | Wall-clock floor between any two hydrates. |
| `AUTOMATION_INDEX_MAX_ROWS` | `2000` | Fleet-wide. A breach refuses the swap and keeps the last good index — it never truncates. |
| `AUTOMATION_INDEX_MAX_VALUE_BYTES` | `512` | Per trigger value. A breach skips that one row. |
| `AUTOMATION_INDEX_STATEMENT_TIMEOUT_MS` | `2000` | Bounds a hung hydrate. Deliberately well below `DATABASE_POOL_TIMEOUT` — the hydrate borrows a connection from the pool alert ingestion uses. |

**Watch `keep_automation_index_largest_posting_list`, not `index_size`.** The probe
is linear in how many automations share a single pivot, not in the total. Measured,
p99 crosses the 1 ms SLO at roughly **1400 candidates in one posting list** — which
the fleet-wide row cap does not bound, because it is a different dimension. The
shape that gets there is one tenant onboarding many automations from a single
template, so they share every trigger value. Alert on this gauge above ~1000.

Every interval is clamped at read time: `config()` accepts a literal `"0"`,
which would turn the reload timer into a hot loop stealing GIL from the single
synchronous consumer thread.

**Three states, deliberately distinguishable.** They mean different things and
have different runbooks:

| Signal | Meaning |
|---|---|
| `keep_automation_index_enabled == 0` | Switched off on purpose. Nothing is running and nothing is wrong. |
| `keep_automation_index_ready == 0` | Enabled, but no usable index. Matching is silently doing nothing. |
| `keep_automation_index_config_missing{setting="redis_url"} == 1` | The index is fine; only sub-second convergence is lost. Reloads still happen every `AUTOMATION_INDEX_RELOAD_SECONDS`. |

An unset `REDIS_URL` is the third, not the second — the one setting that can be
forgotten costs latency, not correctness. Only `AUTOMATION_INDEX_ENABLED`
switches the feature off.

**Qualify every automations alert with `keep_automation_index_enabled == 1`.**
That gauge exists so "off on purpose" and "should be running but isn't" are
different observations; without it, any alert below fires on every correctly
switched-off pod, and an alert that cries wolf gets muted.

**The alert that catches a dead reload worker** is staleness, not `index_ready`:

```
keep_automation_index_enabled == 1
  and time() - keep_automation_index_last_successful_reload_timestamp > 3 * AUTOMATION_INDEX_RELOAD_SECONDS
```

A worker thread that died leaves `index_ready` at 1. Write `index_ready` alerts
as `absent(...) or == 0` — a bare `== 0` is *no data* when the scrape port is
wrong, which is the same failure one layer up. Note this is the one case the
`index_enabled == 1` qualifier does not cover: if the whole scrape is missing,
that gauge is absent too, so `absent()` is still doing the work.

Log budget: steady-state reloads at DEBUG, state transitions at INFO once per
transition, repeated failures at ERROR for the first few then WARN. On a
database that predates the gateway's migration you would otherwise get an ERROR
every 30s forever, and training the one error that means "production index is
dead" into noise is how a detection story dies.

## Tests

```bash
poetry run pytest                      # everything
poetry run pytest tests/automations    # the trigger index
```

Tests needing real Postgres or Redis **skip themselves** when the dependency is
absent rather than failing — CI runs a bare `pytest tests/` with no service
containers. To actually run them, bring the infra up first; they honour
`DATABASE_CONNECTION_STRING` and `REDIS_URL`, so they can be pointed at a
throwaway instance without editing anything.
