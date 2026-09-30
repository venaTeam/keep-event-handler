# B6: fingerprint coverage

`lastalert.automation_matched` is a non-null Boolean defaulting to false.
`lastalert.grace_seconds` is a nullable Integer defaulting to NULL. Both are
enrichable, never generic ingestion tracking fields or per-event Alert columns.
Current-alert readback preserves native types and omits NULL grace.

The existing B5 match tuple feeds
`src.bl.automations.grace.resolve_grace_seconds(matches: Sequence[AutomationMatch]) -> int`.
This pure function requires nonempty input and provisionally takes the minimum:
120 and 600 seconds resolve to 120 in either order. H33 owns the final decision.
Changing the strategy affects subsequent stamps, without historical backfill.

`EnrichmentsBl.stamp_automation_match(fingerprint, grace_seconds)` writes both
fields through the existing enrichment path, under its tenant/fingerprint row
lock, with strict existing-row checking and no repeated audit entry. It preserves
status, dismissal, notes, assignee, tickets, and firing timestamps.

Stamping precedes matched publication, including when the publisher is disabled.
No match performs no write. Resolve and cooldown suppression retain coverage;
later matching events refresh grace. Matching retains its upstream feature gate.
Enrichment disabled while matching is active produces an explicit stamp failure.

Persistence and propagation failures become `AutomationStampError`; the task and
Kafka consumer leave the raw offset unresolved for replay. A committed stamp
survives later publish failure. Existing Elasticsearch handling logs a missing
indexed document; other errors propagate. No cross-system transaction is claimed.

## Coordinated rollout

1. Deploy keep-migrations revision `automation_coverage`, based on
   `merge_automations_preset_tag`, before services declare the new columns.
2. Deploy event-handler plus gateway and workflows shared models/readers.
3. Verify B6 tests and the platform sanity suite before release.

All four local review branches are named `feat/b6-enrichment-stamping`.
Event-handler starts at `feat/alert-matching-matched-topic`; migrations starts at
`origin/dev`. Gateway and workflows start at their existing checked-out branches.
No branches have been pushed or merged by this implementation.

The workspace-level `automation-contracts.md` B6 section is updated separately;
the workspace root is not a service repository. Distribute that contract with
the existing workspace documents. This tracked document carries the H33 seam
and rollout instructions into event-handler review.

For application rollback, retain the additive columns. Migration downgrade
drops coverage and requires the migration runner's destructive-change opt-in.
H32 failure flags/dashboard queries and the final H33 policy remain out of scope.

## Verification (2026-09-22)

- Event-handler automation/enrichment regressions: 404 passed, 16 skipped.
- Migration suite: 71 passed; Alembic has one head, `automation_coverage`.
- Gateway enrichment/readback: 27 passed; workflows: 21 passed.
- Real ingestion/replay, SQL write boundary, strict failure/raw offset behavior,
  tenant isolation, preservation, defaults, and native readback are covered.
- Local Postgres TEMP-table probe ran the real migration and BL with no public
  table writes: 100 forced updates after warmup, median 4.47 ms, p99 8.00 ms.
  Elasticsearch was mocked; this measures stamp DB cost, not full ingestion
  throughput or production latency. Existing matcher benchmark median p99:
  miss 0.6 microseconds, spread 1.1 microseconds, single-pivot 187.8 microseconds.
- Full platform sanity is blocked: local `keep.alembic_version` is
  `24745b8fd562`, absent from the requested migration lineage, and the public
  `lastalert` table lacks both columns. No migration history was restamped and
  no public schema was altered. Resolve that pre-existing lineage mismatch,
  apply the migration, and restart the coordinated services before sanity E2E.
