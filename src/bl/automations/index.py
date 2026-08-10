"""The compiled trigger index and the probe.

Pure: zero I/O, no import from `src.core.db`, no clock, no thread. Everything
here is a function of the definitions handed to it, which is what makes the
compile step testable without a database and the probe testable without a
running service.

**The top level of the index is `tenant_id`.** `match(tenant_id, alert)`
resolves that key before it touches anything else, and is then handed one
tenant's posting structure holding no reference to any other. Tenant isolation
is therefore a property of the data structure rather than of a predicate
someone has to keep writing: there is no cross-tenant read to forget and no
`WHERE` clause a later refactor can drop. Leaking across tenants would require
deliberately re-plumbing the compiler.

Concurrency: a `TriggerIndex` is immutable once built. The publishing swap in
`reloader.py` is a single attribute rebind, and `match()` takes exactly one
local reference for the whole probe -- see the note there. Under CPython's GIL
a bytecode boundary is the interleaving granularity, so a reader sees either
the whole old index or the whole new one. `pyproject.toml` pins
`python = ">=3.11,<3.14"` (a GIL build); a free-threaded build would need this
argument revisited.
"""

from collections import defaultdict
from dataclasses import dataclass

from src.bl.automations.models import AutomationDefinition, AutomationMatch

# Shared, immutable, allocation-free "no matches". Returned for an unknown
# tenant, an empty index, and a probe that confirmed nothing -- the last is the
# overwhelmingly common case at 4000 alerts/min, and building a fresh [] for it
# is pure waste.
_EMPTY: tuple[AutomationMatch, ...] = ()

# tenant_id -> field -> value -> candidates
_Postings = dict[str, dict[str, dict[str, tuple[AutomationDefinition, ...]]]]


@dataclass(frozen=True, slots=True)
class TriggerIndex:
    """An immutable snapshot of every active automation, bucketed by tenant."""

    # Pre-flattened per tenant: tuple[(field, {value: candidates}), ...]. Built
    # once at compile so the probe iterates a tuple instead of re-deriving
    # dict.items() per alert.
    _by_tenant: dict[str, tuple[tuple[str, dict[str, tuple[AutomationDefinition, ...]]], ...]]
    size: int
    tenants: int
    generation: int
    # Candidates in the biggest single posting list. The probe is linear in
    # this, not in `size`, so it -- not the fleet-wide row cap -- is what
    # predicts whether the p99 SLO holds.
    largest_posting_list: int

    @staticmethod
    def empty() -> "TriggerIndex":
        return TriggerIndex(
            _by_tenant={}, size=0, tenants=0, generation=0, largest_posting_list=0
        )

    @staticmethod
    def compile(definitions) -> "TriggerIndex":
        """Build an index from `(tenant_id, conditions, match, generation)` tuples.

        `conditions` is the automation's FULL condition list; the pivot is
        chosen and removed here.

        Compilation is per tenant, and that is not just bookkeeping -- it fixes
        the denominator for pivot selection. A `(field, value)` pair that is
        common fleet-wide but rare inside one tenant is a *good* pivot for that
        tenant, and a global frequency count would have hidden that. Total work
        is unchanged, O(automations x conditions): each row is counted once, in
        exactly one bucket.
        """
        grouped: dict[str, list] = defaultdict(list)
        generation = 0
        for tenant_id, conditions, match, row_generation in definitions:
            grouped[tenant_id].append((conditions, match))
            if row_generation > generation:
                generation = row_generation

        by_tenant = {}
        size = 0
        largest = 0
        for tenant_id, rows in grouped.items():
            postings = _compile_tenant(rows)
            if not postings:
                continue
            by_tenant[tenant_id] = tuple(postings.items())
            size += len(rows)
            for bucket in postings.values():
                for candidates in bucket.values():
                    if len(candidates) > largest:
                        largest = len(candidates)

        return TriggerIndex(
            _by_tenant=by_tenant,
            size=size,
            tenants=len(by_tenant),
            generation=generation,
            largest_posting_list=largest,
        )

    def match(self, tenant_id: str, alert) -> tuple[AutomationMatch, ...] | list:
        """Every automation of `tenant_id` whose conditions all match `alert`.

        Returns a read-only sequence. Never raises, never blocks, never touches
        the network. B5 treats the result as read-only.
        """
        items = self._by_tenant.get(tenant_id)
        if items is None:
            # Unknown tenant, or a tenant with no active automations. The
            # common case, and it costs one dict lookup.
            return _EMPTY

        # Pydantic v1 writes attributes into __dict__, `Config.extra =
        # Extra.allow` puts webhook extras there too, and the bare setattr
        # enrichment loop in process_event_task writes there as well -- so this
        # sees everything getattr would, without the descriptor protocol or the
        # raise/catch on an absent optional field. A guard test asserts the
        # equivalence for all nine matchable fields, so the day someone adds a
        # @property to AlertDto this fails loudly instead of silently matching
        # nothing.
        values = alert.__dict__
        out = None
        for field, bucket in items:
            probe = values.get(field)
            # Not a semantic rule, a crash guard: AlertDto has no
            # validate_assignment and the enrichment loop assigns arbitrary
            # objects, so this can be a dict -- and `bucket.get(dict)` raises
            # TypeError: unhashable. Skipping is exactly equivalent to a miss,
            # because every posting key is a str from the database.
            if type(probe) is not str:
                continue
            candidates = bucket.get(probe)
            if candidates is None:
                continue
            for definition in candidates:
                for condition_field, expected in definition.conditions:
                    if values.get(condition_field) != expected:
                        break
                else:
                    if out is None:
                        out = []
                    out.append(definition.match)
        return out if out is not None else _EMPTY


def _compile_tenant(rows) -> dict:
    """Compile one tenant's rows into `field -> value -> candidates`."""
    # Pass 1: frequency of every (field, value) pair WITHIN this tenant.
    frequency: dict[tuple[str, str], int] = defaultdict(int)
    for conditions, _match in rows:
        for pair in conditions:
            frequency[pair] += 1

    postings: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for conditions, match in rows:
        if not conditions:
            # No conditions is not matchable -- it would match every alert of
            # the tenant. The API enforces a two-condition minimum; this is
            # defence against a hydrate against a half-applied schema.
            continue
        # Pass 2: pivot on the rarest pair. Ties break lexicographically so two
        # hydrates of the same data produce an identical index -- which is what
        # makes the digest-based skip in the reloader meaningful and the
        # compile step testable for determinism.
        pivot = min(conditions, key=lambda pair: (frequency[pair], pair))
        rest = tuple(
            pair for pair in conditions if pair != pivot
        )
        # Rarest-first, so a non-matching candidate fails on comparison #1.
        rest = tuple(sorted(rest, key=lambda pair: (frequency[pair], pair)))
        postings[pivot[0]][pivot[1]].append(
            AutomationDefinition(conditions=rest, match=match)
        )

    return {
        field: {value: tuple(candidates) for value, candidates in values.items()}
        for field, values in postings.items()
    }
