"""Compiler and probe.

Pure tests -- no database, no Redis, no threads, no clock. Every one of these
runs everywhere, which matters because the integration tests self-skip.
"""

import pytest

from src.bl.automations.index import TriggerIndex
from src.bl.automations.models import AutomationMatch, CooldownSpec
from src.models.alert import AlertDto

# The nine matchable fields, per automation-contracts.md's field allowlist.
# Spelled out here rather than imported: this repo deliberately vendors no
# contracts package (the matcher does not validate -- keep-automation-api does,
# at authoring time). This literal exists ONLY to parametrize the __dict__
# guard below; nothing in src/ reads it, so it cannot silently reject a field
# the API later allows.
MATCHABLE_FIELDS = (
    "application",
    "component",
    "status",
    "site",
    "severity",
    "environment",
    "operator",
    "node_name",
    "network",
)

TENANT = "keep"
OTHER_TENANT = "other-tenant"


def make_alert(**overrides) -> AlertDto:
    base = {
        "id": "alert-1",
        "name": "disk full",
        "status": "firing",
        "severity": "critical",
        "lastReceived": "2026-07-30T00:00:00Z",
        "source": ["grafana"],
    }
    base.update(overrides)
    return AlertDto(**base)


def definition(automation_id, conditions, tenant_id=TENANT, generation=0, grace=300,
                cooldown=None):
    return (
        tenant_id,
        tuple(conditions),
        AutomationMatch(
            automation_id=automation_id, grace_seconds=grace, cooldown=cooldown
        ),
        generation,
    )


def matched_ids(index, tenant_id, alert):
    return [m.automation_id for m in index.match(tenant_id, alert)]


# --------------------------------------------------------------------------
# Matching semantics
# --------------------------------------------------------------------------


def test_all_conditions_must_match():
    index = TriggerIndex.compile(
        [definition("a", [("severity", "critical"), ("application", "payments")])]
    )
    alert = make_alert(severity="critical", application="payments")
    assert matched_ids(index, TENANT, alert) == ["a"]


def test_pivot_matches_but_second_condition_fails_yields_no_match():
    """The discriminating case for the whole single-pivot design.

    An implementation that returned the posting list without confirming would
    pass every other matching test in this file and fail only this one.
    `application=payments` is the rarest pair, so it is the pivot; the alert
    matches it but fails `status`.
    """
    index = TriggerIndex.compile(
        [
            definition("a", [("application", "payments"), ("status", "firing")]),
            # Two more rows sharing `status` so `application` is strictly rarer
            # and is therefore definitely the pivot.
            definition("b", [("application", "billing"), ("status", "firing")]),
            definition("c", [("application", "search"), ("status", "firing")]),
        ]
    )
    alert = make_alert(application="payments", status="resolved")
    assert matched_ids(index, TENANT, alert) == []


def test_absent_field_is_not_a_wildcard():
    """A trigger on a field the alert does not carry must fail, not match."""
    index = TriggerIndex.compile(
        [definition("a", [("node_name", "web-01"), ("severity", "critical")])]
    )
    alert = make_alert(severity="critical")  # node_name is None
    assert matched_ids(index, TENANT, alert) == []


def test_unknown_field_behaves_exactly_like_an_absent_one():
    """Why this repo needs no allowlist: an unrecognised field cannot match."""
    index = TriggerIndex.compile(
        [definition("a", [("not_a_real_field", "x"), ("severity", "critical")])]
    )
    assert matched_ids(index, TENANT, make_alert(severity="critical")) == []


def test_matching_is_case_sensitive():
    index = TriggerIndex.compile(
        [definition("a", [("severity", "critical"), ("application", "Payments")])]
    )
    assert matched_ids(index, TENANT, make_alert(application="payments")) == []


def test_enum_valued_fields_compare_as_plain_strings():
    """AlertDto sets Config.use_enum_values, so status/severity are `str` after
    validation. A probe writing `alert.severity.value` would AttributeError."""
    alert = make_alert(status="firing", severity="critical")
    assert alert.__dict__["severity"] == "critical"
    index = TriggerIndex.compile(
        [definition("a", [("severity", "critical"), ("status", "firing")])]
    )
    assert matched_ids(index, TENANT, alert) == ["a"]


def test_multiple_automations_can_match_one_alert():
    index = TriggerIndex.compile(
        [
            definition("a", [("severity", "critical"), ("application", "payments")]),
            definition("b", [("severity", "critical"), ("site", "dc1")]),
        ]
    )
    alert = make_alert(severity="critical", application="payments", site="dc1")
    assert sorted(matched_ids(index, TENANT, alert)) == ["a", "b"]


# --------------------------------------------------------------------------
# Tenant isolation -- structural, not a filter
# --------------------------------------------------------------------------


def test_an_alert_never_matches_another_tenants_automation():
    index = TriggerIndex.compile(
        [
            definition("mine", [("severity", "critical"), ("site", "dc1")], TENANT),
            definition(
                "theirs", [("severity", "critical"), ("site", "dc1")], OTHER_TENANT
            ),
        ]
    )
    alert = make_alert(severity="critical", site="dc1")
    assert matched_ids(index, TENANT, alert) == ["mine"]
    assert matched_ids(index, OTHER_TENANT, alert) == ["theirs"]


def test_unknown_tenant_returns_empty():
    index = TriggerIndex.compile(
        [definition("a", [("severity", "critical"), ("site", "dc1")])]
    )
    assert list(index.match("no-such-tenant", make_alert(severity="critical"))) == []


def test_an_unknown_tenant_gets_nothing_even_when_the_alert_fully_matches():
    """The guarantee this whole story exists to deliver.

    Every matchable field is settable straight from a webhook body, so an
    attacker-shaped alert can satisfy another tenant's conditions exactly. The
    previous unknown-tenant tests used alerts that matched nothing anyway, so a
    fallback to a fleet-wide scan would have passed them. This one probes with
    an alert that DOES satisfy tenant A's automation.
    """
    index = TriggerIndex.compile(
        [definition("theirs", [("severity", "critical"), ("site", "dc1")], TENANT)]
    )
    fully_matching = make_alert(severity="critical", site="dc1")

    # Sanity: the alert really does match, for the tenant that owns it.
    assert matched_ids(index, TENANT, fully_matching) == ["theirs"]

    # ...and reaches nothing from any other tenant identity.
    assert matched_ids(index, "unknown-tenant", fully_matching) == []
    assert matched_ids(index, OTHER_TENANT, fully_matching) == []
    assert matched_ids(index, "", fully_matching) == []


def test_a_known_tenant_cannot_see_another_tenants_matching_automation():
    """Same guarantee, with real automations on BOTH sides so neither result is
    empty for the trivial reason."""
    index = TriggerIndex.compile(
        [
            definition("a-only", [("severity", "critical"), ("site", "dc1")], TENANT),
            definition(
                "b-only", [("severity", "critical"), ("site", "dc1")], OTHER_TENANT
            ),
        ]
    )
    alert = make_alert(severity="critical", site="dc1")
    assert matched_ids(index, TENANT, alert) == ["a-only"]
    assert matched_ids(index, OTHER_TENANT, alert) == ["b-only"]


def test_pivot_frequency_is_counted_per_tenant_not_fleet_wide():
    """A pair common fleet-wide but rare in one tenant is a good pivot there.

    `severity=critical` appears on every row fleet-wide. Inside OTHER_TENANT it
    appears once, so it must still be selectable as that tenant's pivot. If
    frequency were counted globally the two tenants would be forced onto the
    same pivot choice.
    """
    definitions = [
        definition(f"big-{i}", [("severity", "critical"), ("site", f"dc{i}")], TENANT)
        for i in range(5)
    ]
    definitions.append(
        definition("small", [("severity", "critical"), ("site", "dc1")], OTHER_TENANT)
    )
    index = TriggerIndex.compile(definitions)
    alert = make_alert(severity="critical", site="dc1")
    assert matched_ids(index, OTHER_TENANT, alert) == ["small"]
    assert matched_ids(index, TENANT, alert) == ["big-1"]


# --------------------------------------------------------------------------
# Compiled-form properties the SLO depends on
# --------------------------------------------------------------------------


def _all_definitions(index, tenant_id):
    found = []
    for _field, bucket in index._by_tenant[tenant_id]:  # noqa: SLF001
        for candidates in bucket.values():
            found.extend(candidates)
    return found


def test_pivot_condition_is_removed_from_the_confirm_list():
    """The probe reached the candidate by matching the pivot; re-checking it is
    wasted work on the hot path."""
    index = TriggerIndex.compile(
        [definition("a", [("application", "payments"), ("status", "firing")])]
    )
    (compiled,) = _all_definitions(index, TENANT)
    assert len(compiled.conditions) == 1
    assert ("application", "payments") not in compiled.conditions


def test_remaining_conditions_are_ordered_rarest_first():
    """So a non-matching candidate fails on comparison #1, not #3."""
    definitions = [
        definition(
            "target",
            [
                ("application", "unique-app"),  # freq 1 -> pivot
                ("site", "rare-site"),  # freq 2
                ("status", "firing"),  # freq 4
            ],
        ),
        definition("f2", [("site", "rare-site"), ("status", "firing")]),
        definition("f3", [("severity", "critical"), ("status", "firing")]),
        definition("f4", [("severity", "warning"), ("status", "firing")]),
    ]
    index = TriggerIndex.compile(definitions)
    target = next(
        d for d in _all_definitions(index, TENANT) if d.match.automation_id == "target"
    )
    assert target.conditions == (("site", "rare-site"), ("status", "firing"))


def test_compile_is_deterministic_across_input_order():
    """Two hydrates of the same rows must produce an identical index -- the
    digest-based reload skip and the tie-break both depend on it."""
    definitions = [
        definition("a", [("severity", "critical"), ("site", "dc1")]),
        definition("b", [("severity", "critical"), ("site", "dc2")]),
        definition("c", [("application", "payments"), ("site", "dc1")]),
    ]
    first = TriggerIndex.compile(definitions)
    second = TriggerIndex.compile(list(reversed(definitions)))

    def shape(index):
        return sorted(
            (d.match.automation_id, d.conditions) for d in _all_definitions(index, TENANT)
        )

    assert shape(first) == shape(second)


def test_size_and_tenants_report_the_whole_fleet():
    index = TriggerIndex.compile(
        [
            definition("a", [("severity", "critical"), ("site", "dc1")], TENANT),
            definition("b", [("severity", "critical"), ("site", "dc2")], TENANT),
            definition("c", [("severity", "critical"), ("site", "dc1")], OTHER_TENANT),
        ]
    )
    assert index.size == 3
    assert index.tenants == 2


def test_generation_is_the_max_observed():
    index = TriggerIndex.compile(
        [
            definition("a", [("severity", "critical"), ("site", "dc1")], generation=4),
            definition("b", [("severity", "critical"), ("site", "dc2")], generation=9),
        ]
    )
    assert index.generation == 9


def test_condition_less_row_is_not_indexed():
    """It would otherwise match every alert of its tenant."""
    index = TriggerIndex.compile([definition("a", [])])
    assert list(index.match(TENANT, make_alert())) == []


# --------------------------------------------------------------------------
# Crash guards
# --------------------------------------------------------------------------


def test_unhashable_attribute_value_does_not_raise():
    """`process_event_task` does a bare `setattr` for enrichments and AlertDto
    has no validate_assignment, so an attribute can hold a dict. A dict lookup
    keyed on it would raise TypeError: unhashable.

    This is the single most likely production crash in B4.
    """
    index = TriggerIndex.compile(
        [definition("a", [("severity", "critical"), ("site", "dc1")])]
    )
    alert = make_alert(severity="critical", site="dc1")
    object.__setattr__(alert, "severity", {"not": "a string"})
    alert.__dict__["severity"] = {"not": "a string"}
    assert list(index.match(TENANT, alert)) == []


@pytest.mark.parametrize("bad", [{"a": 1}, ["x"], 7, None, object()])
def test_non_string_attribute_values_are_skipped_not_matched(bad):
    index = TriggerIndex.compile(
        [definition("a", [("severity", "critical"), ("site", "dc1")])]
    )
    alert = make_alert(severity="critical", site="dc1")
    alert.__dict__["severity"] = bad
    assert list(index.match(TENANT, alert)) == []


@pytest.mark.parametrize("field", MATCHABLE_FIELDS)
def test_alert_dict_matches_getattr_for_every_matchable_field(field):
    """The probe reads `alert.__dict__` instead of getattr.

    That is safe only while AlertDto declares no @property -- Pydantic v1 writes
    into __dict__, and `Config.extra = Extra.allow` puts webhook extras there
    too. If someone adds a property for one of these fields, __dict__ stops
    agreeing with attribute access and the probe would silently stop matching.
    This fails loudly on that day instead.
    """
    shapes = [
        make_alert(),
        make_alert(**{f: "webhook-value" for f in MATCHABLE_FIELDS}),
        make_alert(),
    ]
    # Third shape: an enrichment written by the bare setattr loop.
    setattr(shapes[2], field, "enriched-value")

    for alert in shapes:
        assert alert.__dict__.get(field) == getattr(alert, field, None)


def test_empty_index_returns_an_empty_sequence():
    assert list(TriggerIndex.empty().match(TENANT, make_alert())) == []


def test_no_match_and_unknown_tenant_share_one_allocation_free_result():
    index = TriggerIndex.compile(
        [definition("a", [("severity", "critical"), ("site", "dc1")])]
    )
    no_match = index.match(TENANT, make_alert(severity="warning"))
    unknown_tenant = index.match("nobody", make_alert())
    assert no_match is unknown_tenant  # the shared _EMPTY, not a fresh list


# --------------------------------------------------------------------------
# AutomationMatch payload
# --------------------------------------------------------------------------


def test_match_carries_cooldown_and_grace_and_nothing_else():
    """The matcher is the only component holding the definition, so it stamps
    cooldown and grace. Submit-time data is deliberately absent."""
    cooldown = CooldownSpec(fields=("node_name", "site"), seconds=600)
    index = TriggerIndex.compile(
        [
            definition(
                "a",
                [("severity", "critical"), ("site", "dc1")],
                grace=120,
                cooldown=cooldown,
            )
        ]
    )
    (result,) = index.match(TENANT, make_alert(severity="critical", site="dc1"))
    assert result.automation_id == "a"
    assert result.grace_seconds == 120
    assert result.cooldown.seconds == 600
    assert result.cooldown.scheme_ver == 1
    assert result.cooldown.fields == ("node_name", "site")
    assert not hasattr(result, "namespace")
    assert not hasattr(result, "active_digest")
    assert not hasattr(result, "secret_name")
    assert not hasattr(result, "timeout_seconds")


def test_match_results_are_frozen():
    index = TriggerIndex.compile(
        [definition("a", [("severity", "critical"), ("site", "dc1")])]
    )
    (result,) = index.match(TENANT, make_alert(severity="critical", site="dc1"))
    with pytest.raises(Exception):
        result.automation_id = "mutated"


# --------------------------------------------------------------------------
# Pivot selection, asserted on the compiled structure
# --------------------------------------------------------------------------
#
# Asserting on match RESULTS cannot test pivot choice: results are invariant to
# which condition is the pivot. A review proved it -- replacing the rarest-pair
# selection with `conditions[0]`, and dropping the lexicographic tie-break, both
# survived the whole file. Pivot choice is what the SLO rests on, so it is
# asserted where it is observable: the compiled index.


def _pivot_field_of(index, tenant_id, automation_id):
    for field, bucket in index._by_tenant[tenant_id]:  # noqa: SLF001
        for candidates in bucket.values():
            for definition_ in candidates:
                if definition_.match.automation_id == automation_id:
                    return field
    raise AssertionError(f"{automation_id} is not in the index")


def test_the_pivot_is_the_rarest_pair_not_the_first_condition():
    """`status=firing` is on every row; `application` is unique per row.

    An implementation pivoting on `conditions[0]` would put every automation
    into one posting list -- the degenerate case the benchmark measures at
    ~170us instead of the realistic sub-microsecond.
    """
    definitions = [
        definition(f"a{i}", [("status", "firing"), ("application", f"app-{i}")])
        for i in range(5)
    ]
    index = TriggerIndex.compile(definitions)
    for i in range(5):
        assert _pivot_field_of(index, TENANT, f"a{i}") == "application"


def test_pivot_choice_is_independent_of_condition_order_within_a_row():
    """The rarest pair wins wherever it sits in the list."""
    definitions = [
        definition("target", [("application", "unique"), ("status", "firing")]),
        definition("other1", [("status", "firing"), ("severity", "critical")]),
        definition("other2", [("status", "firing"), ("severity", "warning")]),
    ]
    forward = TriggerIndex.compile(definitions)
    reversed_row = [
        definition("target", [("status", "firing"), ("application", "unique")]),
        definitions[1],
        definitions[2],
    ]
    backward = TriggerIndex.compile(reversed_row)

    assert _pivot_field_of(forward, TENANT, "target") == "application"
    assert _pivot_field_of(backward, TENANT, "target") == "application"


def test_ties_break_lexicographically_so_the_index_is_reproducible():
    """Both pairs have frequency 1, so only the tie-break decides.

    Without a deterministic tie-break two hydrates of identical rows could
    produce different indexes, which would make the digest-based reload skip
    meaningless.
    """
    forward = TriggerIndex.compile(
        [definition("a", [("site", "dc1"), ("application", "payments")])]
    )
    backward = TriggerIndex.compile(
        [definition("a", [("application", "payments"), ("site", "dc1")])]
    )
    # ("application", ...) sorts before ("site", ...).
    assert _pivot_field_of(forward, TENANT, "a") == "application"
    assert _pivot_field_of(backward, TENANT, "a") == "application"


def test_the_largest_posting_list_is_reported():
    """The probe is linear in this, not in `size` -- so it, not the fleet-wide
    row cap, is what predicts whether the p99 SLO holds. Measured: p99 crosses
    1ms at roughly 1400 candidates in one list."""
    index = TriggerIndex.compile(
        [
            definition(f"a{i}", [("site", "dc1"), ("status", "firing")])
            for i in range(7)
        ]
        + [definition("b", [("site", "dc2"), ("status", "firing")])]
    )
    assert index.largest_posting_list == 7


def test_the_largest_posting_list_is_zero_for_an_empty_index():
    assert TriggerIndex.empty().largest_posting_list == 0
