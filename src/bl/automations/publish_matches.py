"""Pure message construction plus the small B5 hot-path orchestration."""
import json
import uuid

from src.bl.automations.producer import get_matched_producer
from src.bl.automations.reloader import match
from src.core.metrics import automation_alerts_matched_total, automation_alerts_probed_total, automation_matched_m


def _alert_snapshot(alert) -> dict:
    snapshot = json.loads(alert.json()) if hasattr(alert, "json") else dict(alert)
    try:
        uuid.UUID(snapshot.get("history_id"))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("alert.history_id must be a UUID string") from error
    return snapshot


def build_messages(tenant_id: str, alert, matches) -> list[dict]:
    snapshot = _alert_snapshot(alert)
    matched_m = len(matches)
    result = []
    for automation in matches:
        cooldown = automation.cooldown
        result.append({
            "tenant_id": tenant_id,
            "alert": snapshot,
            "automation_id": automation.automation_id,
            "matched_m": matched_m,
            "cooldown": None if cooldown is None else {
                "fields": list(cooldown.fields), "seconds": cooldown.seconds,
                "scheme_ver": cooldown.scheme_ver,
            },
        })
    return result


def publish_matches(tenant_id: str, alerts) -> None:
    producer = get_matched_producer()
    if not producer.enabled:
        return
    for alert in alerts:
        snapshot = _alert_snapshot(alert)
        automation_alerts_probed_total.inc()
        matches = tuple(match(tenant_id, snapshot))
        automation_matched_m.observe(len(matches))
        if matches:
            automation_alerts_matched_total.inc()
            producer.publish(build_messages(tenant_id, snapshot, matches))
