# Deploying the ingestion-resilience consumer

The Kubernetes half of this change set. None of it lives in this repository —
these are the Deployment, probe and env changes the chart must carry, plus the
runbook for the one deploy that cannot be a rolling update.

**Three of these are required.** Without them the code either does nothing or
actively breaks.

---

## 1. Probe paths — ship the image FIRST, the chart with it or after it

⚠️ **Never the chart first.** The image running today serves only `/`,
`/health`, `/healthz` and `/ready`; `/readyz` and `/livez` **404**. A chart
pointing a startupProbe at `/readyz` against the old image never passes, so
kubelet kills every pod at `failureThreshold × periodSeconds` — all 15
CrashLoopBackOff, ingestion down.

The new image satisfies the *old* chart (all four legacy paths still answer, and
`/ready` keeps its unconditional-200 meaning), so image-first is always safe.

```yaml
startupProbe:                              # THE fix for the startup CrashLoop
  httpGet: {path: /readyz, port: health}   # must be /readyz: the health server
  periodSeconds: 10                        # now binds early, so / or /livez
  failureThreshold: 90                     # would pass in ~1s and gate nothing
readinessProbe:
  httpGet: {path: /readyz, port: health}
  periodSeconds: 10
  failureThreshold: 3
livenessProbe:
  httpGet: {path: /livez, port: health}
  periodSeconds: 30
  failureThreshold: 6                      # loose on purpose — see below
```

Today's liveness kills at ≈ 90 s (`initialDelay 60` + `failureThreshold 3` ×
`period 10`) while a schema wait can legitimately run far longer. The
startupProbe is what suspends liveness until startup finishes.

**The startupProbe budget is the real give-up point.** The schema wait retries
forever in code, but `failureThreshold × periodSeconds` caps it from outside:
90 × 10 s = **15 minutes**, then the pod is restarted (and tries again). Size
this above the worst full-sync migration you are willing to wait through — at
the old `failureThreshold: 30` the cap was 5 minutes, which re-creates the
CrashLoop at a later threshold on any sync whose migrations run longer.

`KEEP_SCHEMA_WAIT_TIMEOUT` (180 s) also changed meaning: it is now a
**per-attempt** deadline, not a fatal one.

**Liveness stays loose by construction.** `/livez` fails after
`KEEP_CONSUMER_LIVE_MAX_POLL_GAP_SECONDS`, whose **default is derived**:
`max(300, 0.8 × max.poll.interval.ms + 60s)` — i.e. never below the retry
budget, which is how long a batch may legitimately stay off the poll loop. At
production's `KAFKA_MAX_POLL_INTERVAL_MS=6000000` the budget is 4800 s, so the
default lands at 4860 s rather than a fixed 300 s that would kill the pod at ~8
minutes for working as designed.

Consequences for the chart:

- **Nothing must be set for this to be safe.** An explicit override is still
  honoured, and one *below* the budget logs a startup warning.
- **Lowering `KAFKA_MAX_POLL_INTERVAL_MS` tightens liveness automatically** —
  the correct order of operations (poll interval first, liveness second, never
  the reverse). At 300000 the threshold becomes 300 s.
- Until that happens, liveness is deliberately near-useless as a wedge
  detector: it catches a hung loop in ~81 minutes, not 8. Readiness (90 s) is
  the fast signal, and it costs only rollout credit, never a restart.

## 2. Group migration for cooperative-sticky

`KAFKA_PARTITION_ASSIGNMENT_STRATEGY` defaults to `cooperative-sticky` in the
image, and eager and cooperative members **cannot coexist in one consumer
group**. Deploying the image *is* the migration:

```
scale consumer Deployment to 0  →  sync image + chart  →  scale back up
```

A rolling update produces a mixed group whose members consume nothing. Rollback
is the same operation with
`KAFKA_PARTITION_ASSIGNMENT_STRATEGY: "range,roundrobin"` pinned in the chart.
Set the strategy explicitly in values even though it matches the code default,
so the rollback lever is visible.

## 3. Rollout settings

```yaml
spec:
  strategy:
    rollingUpdate: {maxUnavailable: 0, maxSurge: 1}
  template:
    spec:
      terminationGracePeriodSeconds: 120   # was 30
```

plus `PodDisruptionBudget(minAvailable: 14)`.

All of it is **inert for this deploy** — scale-to-0 bypasses rolling update, and
PDBs do not block scale-down — and armed for every deploy after it.
`terminationGracePeriodSeconds` is the one that pairs with the code: shutdown is
prompt now, but a worst-case batch still needs room to finish, and a pod that
overruns is SIGKILLed, skips LeaveGroup, and strands its partitions for
`session.timeout.ms`.

---

## Recommended env changes

| Variable | From → to | Why |
|---|---|---|
| `KAFKA_SESSION_TIMEOUT_MS` | 600000 → **45000** | How long a hard-killed pod's partitions stay unowned. Largest single config win; the heartbeat now follows it automatically |
| `KAFKA_MAX_POLL_INTERVAL_MS` | 6000000 → a few × p99 batch time | 100 minutes means a wedged consumer is never evicted — and it is what forces liveness to stay loose (see §1) |
| `DATABASE_POOL_SIZE` / `DATABASE_MAX_OVERFLOW` | right-size | 15 pods × (5 + 10) ≈ 225 connections from consumers alone; check against Postgres `max_connections` |

## New environment variables

Every one has a default that reproduces the intended behaviour — nothing here
must be set for the code to work. They exist for tuning and rollback.

| Variable | Default | What it does |
|---|---|---|
| `KAFKA_PARTITION_ASSIGNMENT_STRATEGY` | **`cooperative-sticky`** | Set `range,roundrobin` for the old behaviour. Changing it either way needs a full-group restart |
| `KAFKA_HEARTBEAT_INTERVAL_MS` | `min(session//3, 3000)` | Now actually emitted; previously read by nothing. Only bites below ~9 s session timeout |
| `KEEP_CONSUMER_READY_MAX_POLL_GAP_SECONDS` | `90` | Readiness fails if the last poll is older than this |
| `KEEP_CONSUMER_LIVE_MAX_POLL_GAP_SECONDS` | `max(300, 0.8 × max.poll.interval.ms + 60s)` | Liveness fails if the loop stops polling this long. Derived so it can never sit below the retry budget; an override that does is honoured but warned about |
| `KEEP_CONSUMER_REVOKE_GRACE_SECONDS` | `45` | Readiness stays green this long after a revoke, so a rebalance doesn't flip the group NotReady |
| `KEEP_CONSUMER_READY_REQUIRE_PARTITIONS` | `true` | Set **false** when partitions ≤ replicas — see prereq A |
| `KEEP_SCHEMA_EXPECTED_REVISION` | *(unset)* | Exact alembic revision to wait for. Closes the "gateway is down, so its head is trivially stable" hole |
| `KEEP_SCHEMA_REQUIRED_TABLES` | `tenant,provider,alert,lastalert` | Core tables that must exist before the schema counts as ready |
| `KEEP_SCHEMA_RETRY_BACKOFF_START` / `_MAX` | `5` / `60` | Backoff between schema-wait attempts, now that a timeout retries instead of exiting |
| `KEEP_PROVISIONING_FATAL` | `false` | `true` restores fail-fast on a provisioning error — useful in CI |

`PROVISION_RESOURCES` is unchanged and still defaults to `true`. Setting it
`false` needs the gateway to provision instead and both services to agree on
`KEEP_PROVIDERS` — provisioning with that unset **deletes** provisioned
providers, so a mismatch is destructive in either direction.

---

## Prerequisites — answer BEFORE the deploy

**A. Partition count of the alert topic.** With `maxSurge: 1` Kubernetes runs
`replicas + 1` pods during a rollout. **If partitions ≤ replicas** (15 and 15 is
the current shape — this trips), Kafka legitimately assigns the surge pod
**none** — it is healthy, just idle — readiness never goes green, and every
future rolling update stalls forever. Set
`KEEP_CONSUMER_READY_REQUIRE_PARTITIONS=false`, which makes readiness mean
"joined and polling recently".

**A2. Which paths do the CURRENT probes target?** `grep` every values file. If
anything targets `/readyz` or `/livez` today it would 404 against the old image
(see §1). `/ready` is safe either way — it stays an unconditional 200 in the new
image precisely so an existing liveness probe on it keeps passing during the
schema wait.

**B. Verify on a dev pod** that `/readyz`, `/livez` and the legacy aliases `/`,
`/health`, `/healthz`, `/ready` all answer on the new image:

```bash
kubectl exec deploy/keep-event-handler -- \
  sh -c 'for p in /readyz /livez / /health /healthz /ready; do \
           echo -n "$p "; wget -qO- -S "http://localhost:8092$p" 2>&1 | head -1; done'
```

**C. Expect one SRE page.** Nothing consumes during the scale-to-0 window and
the 20 s verifier will fire. Mute the alert for the window or pre-announce the
page. Lag drains after scale-up; matching counters are the all-clear.

**D. Rehearse the rollback.** Rollback is: revert image + chart, scale to 0,
scale up — a second full-group restart. Cooperative-sticky is the only change
never exercised against a live broker (the tests use a mocked consumer, which
cannot validate protocol behaviour), so know the lever before you need it.

## Runbook

```bash
kubectl scale deploy/keep-event-handler --replicas=0
kubectl wait --for=delete pod -l app=keep-event-handler --timeout=180s
# sync the image + chart (ArgoCD sync of this app only)
kubectl scale deploy/keep-event-handler --replicas=15
kubectl rollout status deploy/keep-event-handler
```

## What each symptom means afterwards

| Symptom | Cause |
|---|---|
| Consumers exit at startup instead of waiting | Schema-wait retry missing from the image |
| Every pod restarting in a loop | Probe path 404s — image/chart mismatch inside the sync |
| CrashLoop persists on migration syncs | startupProbe passing in ~1 s — it must target `/readyz` |
| Rollout stuck, surge pod never Ready | Topic has fewer partitions than replicas (prereq A) |
| Whole group flips NotReady on a rebalance | `KEEP_CONSUMER_REVOKE_GRACE_SECONDS` too short |
| Pods Ready but consuming nothing | Someone rolled instead of scale-to-0 → mixed eager/cooperative group |
| Lag spikes then drains, counters match | Expected, including during the scale-to-0 window. Do not abort |
| `ingestion_total` > `events_in_total` | Alerts being lost — abort |

## Not fixed here

- **Alert loss on infrastructure errors (L1).** A transient DB error still
  exhausts its retries, records a terminal `AlertRaw(error=True)` and commits
  the offset. Needs the retry-topic vs partition-pause decision.
- **`acks=1` on the gateway producer** — accepted risk, documented.
- **The false "Keep failed" page itself.** Only a deploy-aware verifier, or a
  pipeline fast enough to pass at 20 s, stops the paging.
