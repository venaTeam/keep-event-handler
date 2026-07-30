"""Value types for the automations trigger index.

Frozen dataclasses with `slots=True`, not Pydantic: these are hot-path objects
built once at compile time and read on every alert, and nothing here needs
validation -- keep-automation-api validated the triggers at authoring time
(`src/bl/validation.py`), which is why this repo deliberately vendors no
contracts package and holds no allowlist.

`slots=True` is for MEMORY, not speed. Measured on 3.11+ the specializing
interpreter resolves a plain dataclass attribute as fast as a slot, so the probe
does not get faster -- but dropping the per-instance `__dict__` saves ~184 bytes
per automation (~92 KiB at 500, ~368 KiB at the row cap) in a long-lived
ingestion process.
"""

from dataclasses import dataclass

# automation-contracts.md pins the current cooldown key scheme at 1. This is the
# ONE contracts literal this repo carries (see the no-vendoring decision in the
# B4 spec); it lives in two places today -- the contracts doc and here -- and
# will be three when keep-automation-consumer builds its key. They change
# together. Recorded as a named exception in .claude/rules/cross-repo.md.
COOLDOWN_SCHEME_VER = 1


@dataclass(frozen=True, slots=True)
class CooldownSpec:
    """Resolved cooldown gate config, stamped by the matcher.

    The consumer has no read path to the automation definition, so the matcher
    -- which already holds it -- is what puts this on the wire
    (automation-contracts.md).

    `fields` is stored **as authored, unsorted**. Sorting is step one of the
    consumer's canonicalization and belongs there; doing it here as well would
    be an undetectable behaviour change the day the consumer stops sorting.
    """

    fields: tuple[str, ...]
    seconds: int
    scheme_ver: int = COOLDOWN_SCHEME_VER


@dataclass(frozen=True, slots=True)
class AutomationMatch:
    """What a probe returns per matched automation.

    Deliberately three fields. `cooldown` and `grace_seconds` are here because
    nothing downstream can read them. Submit-time data -- `active_digest`,
    `namespace`, `secret_name`, `timeout_seconds` -- is deliberately absent so
    it cannot go stale between match and submit; the API re-reads the row.
    That exclusion is enforced structurally by the hydration query's column
    list, not by discipline here.

    Instances are built once at compile time and shared by reference across
    every probe. They are frozen; B5 must treat them as read-only.
    """

    automation_id: str
    grace_seconds: int
    cooldown: CooldownSpec | None


@dataclass(frozen=True, slots=True)
class AutomationDefinition:
    """One compiled automation.

    `conditions` holds every trigger condition EXCEPT the pivot, ordered
    rarest-first within its tenant. The pivot is excluded because the probe only
    reached this candidate by matching it -- re-checking is wasted work on the
    hot path. Rarest-first means a non-matching candidate fails on its first
    comparison rather than its last.
    """

    conditions: tuple[tuple[str, str], ...]
    match: AutomationMatch
