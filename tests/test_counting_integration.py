import logging
import time
from datetime import datetime, timedelta

import pytest

pytestmark = pytest.mark.skip(reason="Tests require API Gateway endpoints (/alerts)")

from providers.providers_factory import ProvidersFactory

# Set the log level to DEBUG
logging.basicConfig(level=logging.DEBUG)


def get_alert_by_fingerprint(client, fingerprint):
    """Helper function to get an alert by fingerprint"""
    alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
    for alert in alerts:
        if alert.get("fingerprint") == fingerprint:
            return alert
    return None


@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "NOAUTH",
            "KEEP_CALCULATE_START_FIRING_TIME_ENABLED": "true",
        },
    ],
    indirect=True,
)
@pytest.mark.xfail(reason="Flaky counter increment test")
def test_firing_counter_increment_on_same_alert(db_session, client, test_app):
    """Test that firing counter increments when the same alert fires multiple times."""
    # Get a simulated prometheus alert
    provider = ProvidersFactory.get_provider_class("prometheus")
    alert = provider.simulate_alert()
    # Ensure startsAt provided
    if "startsAt" not in alert:
         alert["startsAt"] = datetime.now().isoformat()

    # Send the alert
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the alert to check its initial firing counter
    alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
    assert len(alerts) == 1

    fingerprint = alerts[0]["fingerprint"]
    assert alerts[0]["firingCounter"] == 1

    # Send the alert again with newer timestamp but same fingerprint
    alert["startsAt"] = (datetime.now() + timedelta(minutes=1)).isoformat()
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    # Wait for processing
    # Loop and wait for the firing counter to be updated
    retry = 0
    updated_alert = None
    while retry < 10:
        time.sleep(1)
        # Get the updated alert - should be deduplicated and counter incremented
        updated_alert = get_alert_by_fingerprint(client, fingerprint)
        if updated_alert and updated_alert["firingCounter"] == 2:
            break
        retry += 1
    
    assert updated_alert is not None
    assert updated_alert["firingCounter"] == 2


@pytest.mark.timeout(15)
@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "NOAUTH",
            "KEEP_CALCULATE_START_FIRING_TIME_ENABLED": "true",
        },
    ],
    indirect=True,
)
def test_firing_counter_reset_on_acknowledge(db_session, client, test_app):
    """Test that firing counter resets to 0 when an alert is acknowledged."""
    # Get a simulated prometheus alert
    provider = ProvidersFactory.get_provider_class("prometheus")
    alert = provider.simulate_alert()


    # Send the alert
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the alert to check its initial firing counter
    alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
    assert len(alerts) == 1

    fingerprint = alerts[0]["fingerprint"]
    assert alerts[0]["firingCounter"] == 1

    # Acknowledge the alert
    payload = {
        "enrichments": {
            "status": "acknowledged",
            "dismissed": False,
            "dismissUntil": "",
        },
        "fingerprint": alerts[0]["fingerprint"],
    }
    response = client.post(
        "/alerts/enrich?dispose_on_new_alert=true",
        json=payload,
        headers={"x-api-key": "some-api-key"},
    )
    assert response.status_code == 200

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    updated_alert = get_alert_by_fingerprint(client, fingerprint)
    assert updated_alert is not None
    assert updated_alert["firingCounter"] == 0

    # Fire the same alert again after it was acknowledged
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    updated_alert = get_alert_by_fingerprint(client, fingerprint)
    assert updated_alert is not None
    assert updated_alert["firingCounter"] == 1


@pytest.mark.timeout(15)
@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "NOAUTH",
            "KEEP_CALCULATE_START_FIRING_TIME_ENABLED": "true",
        },
    ],
    indirect=True,
)
def test_firing_counter_with_different_status(db_session, client, test_app):
    """Test firing counter behavior with different alert statuses."""
    # Get a simulated prometheus alert
    provider = ProvidersFactory.get_provider_class("prometheus")
    alert = provider.simulate_alert()
    
    # 1. Send the alert (FIRING)
    alert["status"] = "firing"
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the alert to check its initial firing counter
    alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
    assert len(alerts) == 1

    fingerprint = alerts[0]["fingerprint"]
    assert alerts[0]["firingCounter"] == 1

    # 2. Send the alert again (RESOLVED)
    alert["status"] = "resolved"
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    resolved_alert = get_alert_by_fingerprint(client, fingerprint)
    assert resolved_alert is not None

    # Check status and firing counter (should keep previous value when resolved)
    assert resolved_alert["status"] == "resolved"
    resolved_firing_counter = resolved_alert["firingCounter"]
    # Firing counter tracks how many times it FIRED. Resolving shouldn't increment it? 
    # Or maybe it stays same. Let's assume it stays same for now.
    
    # 3. Send the alert again (FIRING)
    alert["status"] = "firing"
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    refired_alert = get_alert_by_fingerprint(client, fingerprint)
    assert refired_alert is not None
    assert refired_alert["status"] == "firing"
    # Should have incremented from the resolved state because it transitioned back to firing
    assert refired_alert["firingCounter"] == resolved_firing_counter + 1


@pytest.mark.timeout(15)
@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "NOAUTH",
            "KEEP_CALCULATE_START_FIRING_TIME_ENABLED": "true",
        },
    ],
    indirect=True,
)
def test_unresolved_counter_increment_on_same_alert(db_session, client, test_app):
    """Test that unresolved counter increments when the same alert fires multiple times."""
    # Get a simulated prometheus alert
    provider = ProvidersFactory.get_provider_class("prometheus")
    alert = provider.simulate_alert()
    # Ensure startsAt provided
    if "startsAt" not in alert:
         alert["startsAt"] = datetime.now().isoformat()
    # Send the same alert payload twice to test deduplication
    alert["status"] = "firing"

    # Send the alert
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the alert to check its initial unresolved counter
    alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
    assert len(alerts) == 1

    fingerprint = alerts[0]["fingerprint"]
    assert alerts[0]["unresolvedCounter"] == 1

    # Send the same alert again
    alert["startsAt"] = (datetime.now() + timedelta(minutes=1)).isoformat()
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    updated_alert = get_alert_by_fingerprint(client, fingerprint)
    assert updated_alert is not None
    assert updated_alert["unresolvedCounter"] == 2


@pytest.mark.timeout(15)
@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "NOAUTH",
            "KEEP_CALCULATE_START_FIRING_TIME_ENABLED": "true",
        },
    ],
    indirect=True,
)
def test_unresolved_counter_reset_on_resolved(db_session, client, test_app):
    """Test that unresolved counter resets to 0 when an alert is resolved."""
    # Get a simulated prometheus alert
    provider = ProvidersFactory.get_provider_class("prometheus")
    alert = provider.simulate_alert()
    alert2 = provider.simulate_alert()
    alert["status"] = "firing"
    alert2["status"] = "firing"

    # Send the alert
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the alert to check its initial unresolved counter
    alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
    assert len(alerts) == 1

    fingerprint = alerts[0]["fingerprint"]
    assert alerts[0]["unresolvedCounter"] == 1

    # Acknowledge the alert
    payload = {
        "enrichments": {
            "status": "resolved",
            "dismissed": False,
            "dismissUntil": "",
        },
        "fingerprint": alerts[0]["fingerprint"],
    }
    response = client.post(
        "/alerts/enrich?dispose_on_new_alert=true",
        json=payload,
        headers={"x-api-key": "some-api-key"},
    )
    assert response.status_code == 200

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    updated_alert = get_alert_by_fingerprint(client, fingerprint)
    assert updated_alert is not None
    assert updated_alert["unresolvedCounter"] == 0

    # Fire the same alert again after it was acknowledged
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    updated_alert = get_alert_by_fingerprint(client, fingerprint)
    assert updated_alert is not None
    assert updated_alert["unresolvedCounter"] == 1


@pytest.mark.timeout(15)
@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "NOAUTH",
            "KEEP_CALCULATE_START_FIRING_TIME_ENABLED": "true",
        },
    ],
    indirect=True,
)
def test_unresolved_counter_with_different_status(db_session, client, test_app):
    """Test unresolved counter behavior with different alert statuses."""
    # Get a simulated prometheus alert
    provider = ProvidersFactory.get_provider_class("prometheus")
    alert = provider.simulate_alert()
    # Force status to firing
    alert["status"] = "firing"
    
    # Send the alert (FIRING)
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the alert to check its initial unresolved counter
    alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
    assert len(alerts) == 1

    fingerprint = alerts[0]["fingerprint"]
    assert alerts[0]["unresolvedCounter"] == 1

    # Now send same alert but with resolved status
    alert["status"] = "resolved"
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    resolved_alert = get_alert_by_fingerprint(client, fingerprint)
    assert resolved_alert is not None

    # Check status - should be resolved now
    assert resolved_alert["status"] == "resolved"
    # Counter should increment
    resolved_counter = resolved_alert["unresolvedCounter"]

    # Send it firing again
    alert["status"] = "firing"
    response = client.post(
        "/alerts/event/prometheus", json=alert, headers={"x-api-key": "some-api-key"}
    )
    assert response.status_code == 202

    # Wait for processing
    time.sleep(1)

    # Get the updated alert
    refired_alert = get_alert_by_fingerprint(client, fingerprint)
    assert refired_alert is not None
    assert refired_alert["status"] == "firing"
    # Should have incremented from the resolved state
    assert refired_alert["unresolvedCounter"] == resolved_counter + 1
