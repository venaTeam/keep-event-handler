import pytest

pytestmark = pytest.mark.skip(reason="Tests require API Gateway /metrics logic and endpoint integrations")

from core.db.db import (
    add_alerts_to_incident,
    create_incident_from_dict,
)
from tests.fixtures.client import setup_api_key


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_add_remove_alert_to_incidents(
    db_session, client, test_app, setup_stress_alerts_no_elastic
):
    alerts = setup_stress_alerts_no_elastic(14)
    incident = create_incident_from_dict(
        "keep", {"user_generated_name": "test", "description": "test"}
    )
    valid_api_key = "valid_api_key"
    setup_api_key(db_session, valid_api_key)

    add_alerts_to_incident("keep", incident, [a.fingerprint for a in alerts])

    response = client.get("/metrics?labels=a.b", headers={"X-API-KEY": "valid_api_key"})

    # Checking for alert_total metric
    assert (
        f'alerts_total{{incident_name="test",incident_id="{incident.id}",a_b=""}} 14'
        in response.text.split("\n")
    )

    # Checking for open_incidents_total metric
    assert "open_incidents_total 1" in response.text.split("\n")


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_bi_metrics(client, db_session, test_app):
    valid_api_key = "valid_api_key"
    setup_api_key(db_session, valid_api_key)
    headers = {"X-API-KEY": valid_api_key}

    # Send an alert
    alert = {
        "source": ["test_source"],
        "name": "test_alert",
        "status": "firing",
        "lastReceived": "2023-10-26T12:00:00Z",
    }
    resp = client.post("/alerts/event", json=alert, headers=headers)
    assert resp.status_code == 202

    # Get metrics
    resp = client.get("/metrics", headers=headers)
    assert resp.status_code == 200

    # Check for keep_alert_ingestion_total
    # The value might be greater than 1 if other tests ran, so we check for existence
    assert 'keep_alert_ingestion_total{source="generic",status="success"}' in resp.text


    # Check for keep_alert_deduplication_events_total
    # Since we sent a new alert, it might not be a duplicate, so we check for status="new"
    assert 'keep_alert_deduplication_events_total{provider_type="generic",status="new"}' in resp.text


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_rum_metrics(client, db_session, test_app):
    valid_api_key = "valid_api_key"
    setup_api_key(db_session, valid_api_key)
    headers = {"X-API-KEY": valid_api_key}

    # Send a RUM metric
    metric = {
        "id": "test-id",
        "name": "LCP",
        "delta": 100,
        "value": 2500,  # 2.5 seconds
        "rating": "good",
        "navigationType": "navigate",
        "path": "/dashboard"
    }
    
    # Post to /rum
    resp = client.post("/rum", json=metric, headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    # Get metrics
    resp = client.get("/metrics", headers=headers)
    assert resp.status_code == 200

    # Check for keep_frontend_web_vital_lcp
    # Expected: 2.5s should fall into the appropriate bucket
    # Note: buckets are cumulative, so checking for count/sum is safer
    assert 'keep_frontend_web_vital_lcp_count{path="/dashboard"} 1.0' in resp.text
    assert 'keep_frontend_web_vital_lcp_sum{path="/dashboard"} 2.5' in resp.text
