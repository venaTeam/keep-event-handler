# Deriving firing tracking from `lastalert`

Why the per-alert `alert`-history read was removed, what it was actually paying
for, and how every claim here was verified. Written to be **argued with** — the
challengeable decisions are collected at the bottom, with the case against each.

Companion to PR #56. Incident: 2026-08-27 Postgres CPU ~99%.

---

## 1. The incident

One query dominated the database:

```sql
SELECT alert.* FROM alert
WHERE alert.tenant_id = ? AND alert.fingerprint = ?
ORDER BY alert.timestamp DESC LIMIT 1;
```

~88% of total I/O time, ~19k executions per sample window. `EXPLAIN ANALYZE`
shows it is **fast in isolation** — ~0.18 ms, 34 buffer hits, using the
`(tenant_id, fingerprint, timestamp)` index correctly. The cost is frequency
times partition fanout: it carries no timestamp bound, so it cannot prune the
timestamp partitions of `alert` and must plan, lock and probe every one, then
MergeAppend. That gets worse as partitions accumulate.

It was emitted once per ingested alert by `get_alerts_by_fingerprint()`, called
from `process_event_task.py` to derive four fields: `firing_start_time`,
`firing_start_time_since_last_resolved`, `firing_counter`, `unresolved_counter`.

Mitigation was `KEEP_CALCULATE_START_FIRING_TIME_ENABLED=false`. It worked.

## 2. Why the query was unnecessary

The four fields need only the **previous occurrence's state**. Since the
alertenrichment removal (phase 2), all of that state already lives on the
per-fingerprint `lastalert` row — as typed columns — and `set_last_alert`
**already reads that row `FOR UPDATE` and writes it** on every occurrence.

The old path therefore did three reads where one already-held row would do:

1. `get_alerts_by_fingerprint()` → the partitioned `alert` scan.
2. `convert_db_alerts_to_dto_alerts()` → a `lastalert` read, which is where the
   counters and start-times *actually* came from. The `alert` row contributed
   exactly one thing: the previous **provider** status, used only when
   `lastalert.status IS NULL`.
3. `set_last_alert()` → `SELECT … FOR UPDATE` on the same `lastalert` row.

The fix derives the fields inside `set_last_alert` from the row it already
holds, and returns that row so the caller needs no further read.

### Bonus: a lost-update race closed

Deriving outside the lock meant two concurrent occurrences of one fingerprint
could both read the same previous counter and both write `counter + 1`. The
derivation now happens under the `FOR UPDATE` that repoints the row.

## 3. What the mitigation was actually costing

With the calculation disabled the columns are still written — as `0`/`NULL`.
Consumers, in descending order of how much they matter:

| Consumer | Effect while disabled |
|---|---|
| **Correlation threshold gate** (`rulesengine.py:155-162`) | `firing_count` sums `unresolved_counter` over `incident.alerts`; zeros collapse it to `max(incident.alerts_count, 0)`. Repeat firings stop counting toward `rule.threshold`. |
| **`keep.get_firing_time()`** (workflows) | Falls back to `last_received`, so firing-duration gates measure time since the last occurrence and keep resetting. No crash — the keep-workflows copy is hardened. |
| UI firing-time columns | Render blank. |
| `firing_counter` / `unresolved_counter` CEL fields | Match on 0 — presets, and any correlation rule whose CEL references them. |

**Correlation does not stop working.** Rule matching, incident creation,
grouping and alert→incident assignment never read these fields. `Rule.threshold`
defaults to **1**, where the gate is unaffected. Only rules explicitly set to
`threshold >= 2` change: they need that many *distinct* alerts instead of being
satisfiable by one alert re-firing.

Confirmed unaffected either way: deduplication, enrichment, maintenance windows,
dismiss/undismiss lifecycle, incident resolution, audit records, SSE/Pusher,
persistence.

## 4. Measured query load

Postgres index scans per ingested alert, from `pg_stat_user_indexes` deltas over
10 fresh fingerprints, with a no-ingest control window subtracted as background
noise (the running UI and the dismissal watcher both poll).

| config | `alert` | `lastalert` | combined |
|---|---|---|---|
| `dev`, calculation on (pre-incident) | 4.0 | 5.0 | 9.0 |
| `dev`, calculation off (**prod today**) | 3.0 | 5.0 | 8.0 |
| **this branch** | **1.0** | **4.0** | **5.0** |

**3 fewer scans per alert than prod runs today**, 4 fewer than pre-incident. The
single remaining `alert` touch is a primary-key point lookup present in all
three configurations.

Note the middle row: disabling the flag only ever removed the history read. The
two post-commit ORM refreshes of the just-written `Alert` row stayed. Those are
`ix_alert_timestamp` scans, caused by `expire_on_commit` defaulting to true;
this branch disables it for all of `__save_to_db` (which it already did for its
incident section) and they disappear.

> ⚠️ **Read this measurement for its scan *counts*, not its wall-clock.** It was
> taken on a local Postgres where `alert` is a **plain 381-row table**. Prod's is
> partitioned with millions of rows, so the removed query costs *more* there than
> here — partition fanout is the entire reason it hurt. The count reduction
> transfers; the per-scan saving is understated.

### Reproducing it

The stack must be up (`sanity-check/scripts/deploy.sh --root <keep-namespace>`).
Produce `EventDTO` payloads straight to Kafka — this bypasses the gateway, so it
works regardless of `AUTH_TYPE`:

- topic `keep-events` on `localhost:29092`, payload shape per
  `keep-api-gateway/src/services/producers/kafka_producer.py:_build_payload`
  (`provider_type: null` is fine)
- snapshot `pg_stat_user_indexes` for `alert` + `lastalert`, ingest N fresh
  fingerprints, settle ~18s, snapshot again, subtract a no-ingest control window
- A/B by checking out `dev`, restarting only the consumer
  (`poetry run python -m src.consumer_main` with the repo `.env` loaded), and
  repeating

`pg_stat_statements` is available in the image but **not loaded**; enabling it
needs a Postgres restart, hence the index-counter method.

## 5. Correctness

### NULL `status` reads as firing

`apply_dismiss_lifecycle` writes `lastalert.status` only when it *clears* a
status — on a resolved occurrence, or a disposable one. A plain firing→firing
sequence therefore leaves `status` NULL indefinitely, and the create branch never
sets it.

Reading NULL as firing reproduces the old results **exactly**, because the
counters themselves carry the state:

- an acknowledged occurrence writes `firing_counter = 0`, so the next firing
  occurrence computes `0 + 1 = 1` — the same reset the old code produced by
  reading the previous `Alert` row's `acknowledged` status
- a resolved occurrence writes `unresolved_counter = 0` **and** `status =
  'resolved'`, so that case never relies on the NULL reading at all

### Self-heal

Rows written while the calculation was disabled carry `0`/`NULL`. The next
occurrence restarts them — counter → 1, firing clock → that occurrence — rather
than staying blank forever. Deliberate: the old code returned
`previous.firing_start_time` unconditionally, which would have propagated NULL
indefinitely.

### Verified lifecycle

Six occurrences on one fingerprint through Kafka → event-handler → Postgres,
reading `lastalert` after each:

| occurrence | `firing_counter` | `unresolved_counter` | `firing_start_time` | `since_last_resolved` |
|---|---|---|---|---|
| firing d1 | 1 | 1 | t1 | t1 |
| firing d2 | 2 | 2 | **t1 (held)** | t1 |
| resolved d3 | 3 | **0** | NULL | NULL |
| firing d4 | 4 | **1** | **t4 (restart)** | t4 |
| acknowledged d5 | **0** | 2 | NULL | **t4 (held)** |
| firing d6 | **1** | 3 | **t6 (restart)** | **t4 (held)** |

d6 is the sharpest case: the firing clock restarts after the acknowledge while
`since_last_resolved` correctly stays at d4 — an acknowledge is not a resolve.
Rows d1–d2 have `status` NULL, exercising the legacy reading above.

### Tests

Full suite **656 passed, 55 skipped**. 14 new tests in
`tests/test_firing_tracking.py`: derivation semantics, persisted lifecycle,
out-of-order guard, canonical `...Z` timestamp format, and a regression guard
asserting `set_last_alert` never reads the `alert` table.

## 6. Not verified

- **The keep-ui 12-check E2E suite did not run.** Its `global-setup` requires
  `AUTH_TYPE=noauth`; the local stack is deliberately on Keycloak. It exits **0**
  with `checks.json` at `{total:0,passed:0,failed:0}` — a green exit code that is
  not a pass. None of the 12 exercise this code path, but they are unverified.
- No load test at prod volume or on a partitioned `alert`.
- No verification of which tenant workflows actually call `get_firing_time()` —
  that lives in `workflow_raw` in the prod DB, not in any repo.

---

## 7. Challenge these

Each of these is a judgment call, not a fact. The case against is given honestly.

**a. Deploying this changes correlation behaviour — on purpose.**
Restoring re-fire weighting means correlation rules with `threshold >= 2` that
have been dormant since 2026-08-27 may start creating visible incidents again.
That is a *restoration*, but it will look like a regression to whoever is on
call. Counter-argument: gate the restore, or audit `threshold >= 2` rules first.
Nothing here does that.

**b. The flag is removed, leaving no kill switch.**
If the derivation is wrong in a way testing missed, there is no env var to turn
it off — only a revert. Counter-argument: keep it as a flag. The case for removal
is that the flag no longer trades cost for function; it now only trades *function
for nothing*, and leaving it invites someone to "mitigate" with it again and
silently re-break correlation thresholds.

**c. `expire_on_commit = False` for the whole of `__save_to_db`.**
This is the widest-blast-radius line in the diff. It means every ORM object in
that function keeps its in-memory values after a commit instead of re-reading.
That is what makes the returned `lastalert` row reusable, but it also changes
behaviour for every other object in the function. Counter-argument: scope it
narrowly, or drop the reuse and accept one extra read. Mitigating fact: the
function already did exactly this for its incident section.

**d. NULL status → firing.**
Argued above as exactly equivalent. The way it breaks is if some path writes a
non-firing provider status to `lastalert` while leaving `status` NULL *and*
leaves the counters untouched. No such path was found; that is an absence-of-
evidence argument, not a proof.

**e. keep-workflows is not mirrored.**
It carries its own copy of this ingestion path and keeps the old `alert` read.
Deliberate — no user traffic routes through it today — but the two repos'
`set_last_alert` / `enrichment_helpers` now diverge, which is a trap for whoever
next edits either. Counter-argument: mirror it now while the change is fresh.

**f. Counters reset for fingerprints that fired through the mitigation window.**
Their `firing_start_time` restarts at the first post-deploy occurrence. Small,
self-correcting, but it means "firing since" will briefly under-report for
long-running alerts. Counter-argument: backfill from `alert` history. That was
rejected as a large one-off read of exactly the table this change exists to stop
reading.
