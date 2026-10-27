"""Probe micro-benchmark: p99 < 1ms at 500 automations.

The story's bar, asserted as written rather than loosened. A bound that cannot
fail is not a regression test -- an earlier draft proposed p99 < 5ms, roughly
50x the predicted worst case, which would have passed a change that made the
probe twenty times slower.

Flakiness is controlled the right way instead: `perf_counter_ns`, a discarded
warm-up, and the **median of k independent p99s** so one descheduled run cannot
fail the suite.

Three distributions, because only one of them is hard:

- `spread` -- pivots spread across many posting lists. The realistic case.
- `single_pivot` -- all 500 in ONE posting list. Not hypothetical: 500
  automations from one team template give every pair the same frequency, and
  the lexicographic tie-break puts them together. A template belongs to a team,
  so it lands inside one tenant -- exactly this bucket. Without this case the
  benchmark measures nothing the design's selectivity argument is defending.
- `miss` -- an alert matching nothing, which walks every seed field with no
  early exit. The common case at 4000 alerts/min.

**Never run this inside freeze_time.** Measured: a 1.5s wait under freezegun
burns 1.5s of real time while the frozen clock reports 0.00. `os.times().elapsed`
is 0.00 on Windows too. Only `perf_counter_ns` is trustworthy here.
"""

import statistics
import time

import pytest

from src.bl.automations.index import TriggerIndex
from src.bl.automations.models import AutomationMatch
from src.models.alert import AlertDto

TENANT = "keep"
AUTOMATION_COUNT = 500
PROBES_PER_ROUND = 2000
ROUNDS = 5
WARMUP_PROBES = 200
SLO_SECONDS = 1e-3


def _alert(**overrides):
    base = {
        "id": "bench",
        "name": "bench",
        "status": "firing",
        "severity": "critical",
        "lastReceived": "2026-07-30T00:00:00Z",
        "source": ["grafana"],
    }
    base.update(overrides)
    return AlertDto(**base)


def _definition(automation_id, conditions):
    return (
        TENANT,
        tuple(conditions),
        AutomationMatch(
            automation_id=automation_id, grace_seconds=300, cooldown=None
        ),
        1,
    )


def _spread_index():
    return TriggerIndex.compile(
        [
            _definition(
                f"a{i}",
                [
                    ("application", f"app-{i}"),
                    ("severity", "critical"),
                    ("status", "firing"),
                ],
            )
            for i in range(AUTOMATION_COUNT)
        ]
    )


def _single_pivot_index():
    """Every automation shares the same three pairs -> one posting list."""
    return TriggerIndex.compile(
        [
            _definition(
                f"a{i}",
                [
                    ("site", "dc1"),
                    ("severity", "critical"),
                    ("status", "firing"),
                ],
            )
            for i in range(AUTOMATION_COUNT)
        ]
    )


SCENARIOS = {
    # name: (index factory, alert factory)
    "spread": (_spread_index, lambda: _alert(application="app-250", severity="critical")),
    "single_pivot": (
        _single_pivot_index,
        lambda: _alert(site="dc1", severity="critical"),
    ),
    "miss": (_spread_index, lambda: _alert(application="nothing-matches-this")),
}


def _p99(index, alert) -> float:
    for _ in range(WARMUP_PROBES):
        index.match(TENANT, alert)
    samples = []
    for _ in range(PROBES_PER_ROUND):
        started = time.perf_counter_ns()
        index.match(TENANT, alert)
        samples.append(time.perf_counter_ns() - started)
    samples.sort()
    return samples[int(len(samples) * 0.99)] / 1e9


@pytest.mark.timeout(120)
@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_probe_p99_is_under_one_millisecond(scenario, capsys):
    build_index, build_alert = SCENARIOS[scenario]
    index = build_index()
    alert = build_alert()
    assert index.size == AUTOMATION_COUNT

    p99s = [_p99(index, alert) for _ in range(ROUNDS)]
    median_p99 = statistics.median(p99s)

    with capsys.disabled():
        print(
            f"\n  [{scenario}] p99 median={median_p99 * 1e6:.1f}us "
            f"min={min(p99s) * 1e6:.1f}us max={max(p99s) * 1e6:.1f}us "
            f"({AUTOMATION_COUNT} automations, {PROBES_PER_ROUND} probes x {ROUNDS})"
        )

    assert median_p99 < SLO_SECONDS, (
        f"{scenario}: p99 {median_p99 * 1e6:.1f}us exceeds the 1ms SLO"
    )


@pytest.mark.timeout(120)
def test_the_degenerate_case_really_is_one_posting_list():
    """Guards the benchmark itself.

    If a future pivot change spread these across many lists, `single_pivot`
    would silently stop measuring the worst case and the SLO assertion would
    become decorative.
    """
    index = _single_pivot_index()
    (_field, bucket), = index._by_tenant[TENANT]  # noqa: SLF001
    assert len(bucket) == 1
    (candidates,) = bucket.values()
    assert len(candidates) == AUTOMATION_COUNT
