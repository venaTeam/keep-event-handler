"""Pure message construction plus the small B5 hot-path orchestration."""

import json
import logging
from collections.abc import Sequence
from typing import Any

from src.bl.automations.models import AutomationMatch
from src.bl.automations.producer import MatchedContractError, get_matched_producer
from src.bl.automations.reloader import match
from src.core.metrics import (
    automation_alerts_matched_total,
    automation_alerts_probed_total,
    automation_matched_m,
)

logger = logging.getLogger(__name__)


def _alert_snapshot(alert: Any) -> dict[str, Any]:
    snapshot = json.loads(alert.json()) if hasattr(alert, "json") else dict(alert)
    source_id = snapshot.get("id")
    if source_id is None or not str(source_id).strip():
        raise MatchedContractError("alert.id is required")
    if not snapshot.get("fingerprint"):
        raise MatchedContractError("alert.fingerprint is required")
    if not snapshot.get("started_at"):
        raise MatchedContractError("alert.started_at is required")
    return snapshot


def build_messages(
    tenant_id: str,
    alert: Any,
    matches: Sequence[AutomationMatch],
) -> list[dict[str, Any]]:
    snapshot = _alert_snapshot(alert)
    matched_m = len(matches)
    result = []
    for automation in matches:
        cooldown = automation.cooldown
        result.append(
            {
                "tenant_id": tenant_id,
                "alert": snapshot,
                "automation_id": automation.automation_id,
                "matched_m": matched_m,
                "cooldown": (
                    None
                    if cooldown is None
                    else {
                        "fields": list(cooldown.fields),
                        "seconds": cooldown.seconds,
                        "scheme_ver": cooldown.scheme_ver,
                    }
                ),
            }
        )
    return result


def publish_matches(tenant_id: str, alerts: Sequence[Any]) -> None:
    producer = get_matched_producer()
    for alert in alerts:
        automation_alerts_probed_total.inc()
        matches = tuple(match(tenant_id, alert))
        matched_m = len(matches)
        automation_matched_m.observe(matched_m)
        logger.debug(
            "Automation matching completed (tenant_id=%s, matched_m=%s)",
            tenant_id,
            matched_m,
        )

        if matches:
            automation_alerts_matched_total.inc()
            producer.publish(build_messages(tenant_id, alert, matches))
