"""B6 persistence, readback, ordering and replay contracts."""

import re
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy import event
from sqlmodel import select

import src.bl.automations.publish_matches as publishing
import src.bl.enrichments_bl as enrichment_module
import src.event_management.process_event_task as task
from src.bl.automations.errors import AutomationStampError
from src.bl.automations.grace import resolve_grace_seconds
from src.bl.automations.models import AutomationMatch
from src.bl.automations.producer import MatchedPublishError
from src.bl.enrichments_bl import EnrichmentsBl
from src.core.db.db import (
    get_last_alert_by_fingerprint,
    last_alert_enrichments_dict,
    set_last_alert,
)
from src.core.dependencies import SINGLE_TENANT_UUID as TENANT
from src.models.db.alert import Alert, AlertAudit, LastAlert
from src.models.db.tenant import Tenant
from src.utils.enrichment_helpers import convert_db_alerts_to_dto_alerts
from tests.automations.test_process_event_delivery import delivery_flow

_SAVE_EVENTS = task.__save_to_db


def insert_event(session, fingerprint="fp", tenant=TENANT, status="firing", tick=0):
    timestamp = datetime.now(timezone.utc) + timedelta(seconds=tick)
    alert = Alert(
        id=uuid4(), tenant_id=tenant, fingerprint=fingerprint,
        timestamp=timestamp, provider_type="test", provider_id="test",
        status=status, alert_hash=str(uuid4()), name="coverage test",
        time_created="2026-09-22T00:00:00Z",
    )
    session.add(alert)
    session.commit()
    set_last_alert(tenant, alert, session=session)
    return alert


def wire_alert(alert):
    return {
        "id": str(alert.id), "fingerprint": alert.fingerprint,
        "time_created": alert.time_created, "status": alert.status,
    }


@pytest.fixture
def flow(db_session, monkeypatch):
    monkeypatch.setattr(EnrichmentsBl, "ENRICHMENT_DISABLED", False)
    elastic = Mock()
    monkeypatch.setattr(enrichment_module, "ElasticClient", lambda **kw: elastic)
    # Exercise the real BL and DB with the fixture-owned session.
    monkeypatch.setattr(publishing, "EnrichmentsBl", lambda tenant: EnrichmentsBl(tenant, db_session))
    producer = Mock(enabled=True)
    monkeypatch.setattr(publishing, "get_matched_producer", lambda: producer)
    matcher = Mock(return_value=(AutomationMatch("a", 300, None),))
    monkeypatch.setattr(publishing, "match", matcher)
    return db_session, producer, matcher, elastic


@pytest.mark.parametrize("windows, expected", [([300], 300), ([120, 600], 120), ([600, 120], 120), ([0, 300], 0)])
def test_grace_strategy(windows, expected):
    matches = tuple(AutomationMatch(str(i), grace, None) for i, grace in enumerate(windows))
    assert resolve_grace_seconds(matches) == expected
    assert [match.grace_seconds for match in matches] == windows


def test_empty_strategy_input_is_an_error():
    with pytest.raises(ValueError, match="without automation matches"):
        resolve_grace_seconds(())


@pytest.mark.parametrize("windows", [(300,), (120, 600), (600, 120)])
def test_stamp_commits_once_before_fanout_without_event_writes(flow, windows):
    session, producer, matcher, elastic = flow
    alert = insert_event(session)
    payload = wire_alert(alert)
    matcher.return_value = tuple(AutomationMatch(str(i), grace, None) for i, grace in enumerate(windows))
    statements = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(str(statement))
    def published(messages):
        current = get_last_alert_by_fingerprint(TENANT, "fp", session)
        assert current.automation_matched is True
        assert current.grace_seconds == min(windows)
        assert len(messages) == len(windows)
        assert "automation_matched" not in messages[0]["alert"]
    producer.publish.side_effect = published
    event.listen(session.bind, "before_cursor_execute", capture)
    try:
        publishing.publish_matches(TENANT, [payload])
    finally:
        event.remove(session.bind, "before_cursor_execute", capture)
    writes = [sql for sql in statements if re.match(r"\s*(INSERT|UPDATE|DELETE)\b", sql, re.I)]
    assert len(writes) == 1
    assert re.match(r"UPDATE lastalert\b", writes[0], re.I)
    assert session.exec(select(AlertAudit)).all() == []
    session.refresh(alert)
    assert "automation_matched" not in alert.dict()
    assert "grace_seconds" not in alert.dict()
    elastic.enrich_alert.assert_called_once_with(
        alert_fingerprint="fp",
        alert_enrichments={"automation_matched": True, "grace_seconds": min(windows)},
    )


def test_no_match_defaults_and_native_readback(flow):
    session, producer, matcher, elastic = flow
    alert = insert_event(session)
    matcher.return_value = ()
    publishing.publish_matches(TENANT, [wire_alert(alert)])
    row = get_last_alert_by_fingerprint(TENANT, "fp", session)
    assert row.automation_matched is False
    assert row.grace_seconds is None
    assert last_alert_enrichments_dict(row)["automation_matched"] is False
    assert "grace_seconds" not in last_alert_enrichments_dict(row)
    dto = convert_db_alerts_to_dto_alerts([alert], session=session)[0]
    assert dto.dict()["automation_matched"] is False
    producer.publish.assert_not_called()
    elastic.enrich_alert.assert_not_called()


def test_refire_resolve_nonmatch_and_cooldown_retain_coverage(flow):
    session, producer, matcher, _ = flow
    original = insert_event(session)
    publishing.publish_matches(TENANT, [wire_alert(original)])
    # A downstream gate consumes the published record but suppresses execution.
    cooldown_gate = Mock(return_value=False)
    assert not cooldown_gate(producer.publish.call_args.args[0][0])
    row = get_last_alert_by_fingerprint(TENANT, "fp", session)
    assert (row.automation_matched, row.grace_seconds) == (True, 300)
    matcher.return_value = ()
    for tick, status in enumerate(("firing", "resolved"), 1):
        alert = insert_event(session, status=status, tick=tick)
        publishing.publish_matches(TENANT, [wire_alert(alert)])
        session.refresh(row)
        current = session.exec(select(Alert).where(Alert.id == row.alert_id)).one()
        assert convert_db_alerts_to_dto_alerts([current], session=session)[0].status == status
        assert (row.automation_matched, row.grace_seconds) == (True, 300)
    matcher.return_value = (AutomationMatch("a", 120, None),)
    refire = insert_event(session, tick=3)
    publishing.publish_matches(TENANT, [wire_alert(refire)])
    session.refresh(row)
    assert row.grace_seconds == 120
    dto = convert_db_alerts_to_dto_alerts([refire], session=session)[0]
    assert dto.dict()["automation_matched"] is True
    assert type(dto.dict()["grace_seconds"]) is int
    assert dto.time_created == "2026-09-22T00:00:00Z"


def test_tenant_and_unrelated_state_preserved(flow):
    session, _, _, _ = flow
    session.add(Tenant(id="other", name="other", created_by="test"))
    session.commit()
    insert_event(session, tenant="other")
    alert = insert_event(session)
    row = get_last_alert_by_fingerprint(TENANT, "fp", session)
    row.note = "operator note"
    row.assignee = "operator"
    row.status = "suppressed"
    row.dismiss_mode = "permanent"
    row.ticket_url = "https://tickets.example/1"
    row.firing_start_time = "2026-09-22T00:00:00Z"
    session.add(row)
    session.commit()
    publishing.publish_matches(TENANT, [dict(wire_alert(alert), tenant_id="other")])
    session.refresh(row)
    assert (row.note, row.assignee, row.status, row.dismiss_mode, row.ticket_url) == (
        "operator note", "operator", "suppressed", "permanent", "https://tickets.example/1",
    )
    assert row.firing_start_time == "2026-09-22T00:00:00Z"
    other = get_last_alert_by_fingerprint("other", "fp", session)
    assert (other.automation_matched, other.grace_seconds) == (False, None)


def test_disabled_publisher_still_stamps(flow):
    session, producer, _, _ = flow
    producer.enabled = False
    publishing.publish_matches(TENANT, [wire_alert(insert_event(session))])
    assert get_last_alert_by_fingerprint(TENANT, "fp", session).automation_matched is True
    producer.publish.assert_not_called()


def test_missing_row_stops_publish(flow):
    _, producer, _, elastic = flow
    with pytest.raises(AutomationStampError) as error:
        publishing.publish_matches(TENANT, [{"id": "missing", "fingerprint": "missing", "time_created": "now"}])
    assert isinstance(error.value.__cause__, LookupError)
    producer.publish.assert_not_called()
    elastic.enrich_alert.assert_not_called()


def test_db_commit_failure_stops_publish_and_rolls_back(flow, monkeypatch):
    session, producer, _, elastic = flow
    payload = wire_alert(insert_event(session))
    with monkeypatch.context() as patch:
        patch.setattr(session, "commit", Mock(side_effect=RuntimeError("db unavailable")))
        with pytest.raises(AutomationStampError):
            publishing.publish_matches(TENANT, [payload])
    session.rollback()
    row = get_last_alert_by_fingerprint(TENANT, "fp", session)
    assert (row.automation_matched, row.grace_seconds) == (False, None)
    producer.publish.assert_not_called()
    elastic.enrich_alert.assert_not_called()


@pytest.mark.parametrize("failure_point", ["publish", "elastic"])
def test_committed_stamp_survives_failure_and_replay(flow, failure_point):
    session, producer, _, elastic = flow
    payload = wire_alert(insert_event(session))
    if failure_point == "publish":
        producer.publish.side_effect = MatchedPublishError("broker unavailable")
        expected = MatchedPublishError
    else:
        elastic.enrich_alert.side_effect = RuntimeError("elastic unavailable")
        expected = AutomationStampError
    with pytest.raises(expected):
        publishing.publish_matches(TENANT, [payload])
    session.expire_all()
    assert get_last_alert_by_fingerprint(TENANT, "fp", session).automation_matched is True
    producer.publish.side_effect = None
    elastic.enrich_alert.side_effect = None
    publishing.publish_matches(TENANT, [payload])
    assert len(session.exec(select(Alert)).all()) == 1
    assert producer.publish.call_args.args[0][0]["alert"]["id"] == payload["id"]


def test_disabled_enrichment_is_explicit_failure(flow, monkeypatch):
    session, producer, _, _ = flow
    payload = wire_alert(insert_event(session))
    monkeypatch.setattr(EnrichmentsBl, "ENRICHMENT_DISABLED", True)
    with pytest.raises(AutomationStampError) as error:
        publishing.publish_matches(TENANT, [payload])
    assert "requires enrichment" in str(error.value.__cause__)
    producer.publish.assert_not_called()


def test_real_processing_persists_coverage_and_replays(delivery_flow, db_session, monkeypatch):
    from src.controllers.event_controller import process_event_sync

    dto, _, _, errors, _, producer = delivery_flow
    dto.tenant_id = TENANT
    dto.event.update(alert_hash="coverage-hash", status="firing", severity="critical")
    monkeypatch.setattr(task, "get_session_sync", lambda: db_session)
    monkeypatch.setattr(task, "__save_to_db", _SAVE_EVENTS)
    monkeypatch.setattr(enrichment_module, "ElasticClient", Mock())
    monkeypatch.setattr(EnrichmentsBl, "ENRICHMENT_DISABLED", False)
    monkeypatch.setattr(publishing, "EnrichmentsBl", lambda tenant: EnrichmentsBl(tenant, db_session))
    with pytest.raises(MatchedPublishError):
        process_event_sync(dto)
    row = get_last_alert_by_fingerprint(TENANT, "fp", db_session)
    assert row is not None
    assert (row.automation_matched, row.grace_seconds) == (True, 300)
    assert len(db_session.exec(select(Alert)).all()) == 1
    dto.is_replay = True
    dto.event["is_full_duplicate"] = True
    producer.publish.side_effect = None
    process_event_sync(dto)
    assert len(db_session.exec(select(Alert)).all()) == 1
    assert producer.publish.call_count == 2
    assert get_last_alert_by_fingerprint(TENANT, "fp", db_session).grace_seconds == 300
    errors.assert_not_called()
