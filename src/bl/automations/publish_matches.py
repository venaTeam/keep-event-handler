"""Pure message construction plus the small B5 hot-path orchestration."""

import json
import logging
from collections.abc import Mapping, Sequence
from typing import Any

from src.bl.automations.errors import AutomationStampError
from src.bl.automations.grace import resolve_grace_seconds
from src.bl.automations.models import AutomationMatch
from src.bl.automations.producer import MatchedContractError, get_matched_producer
from src.bl.automations.reloader import match
from src.bl.enrichments_bl import EnrichmentsBl
from src.core.metrics import (
    automation_alerts_matched_total,
    automation_alerts_probed_total,
    automation_matched_alerts_rejected_total,
    automation_matched_m,
)

logger = logging.getLogger(__name__)

_REQUIRED_ALERT_FIELDS = ("id", "fingerprint", "time_created")


def _validate_required_alert_fields(snapshot: dict[str, Any]) -> None:
    for field in _REQUIRED_ALERT_FIELDS:
        value = snapshot.get(field)
        if not isinstance(value, str) or not value.strip():
            raise MatchedContractError(
                f"alert.{field} must be a non-empty string"
            )


def _alert_snapshot(alert: Any) -> dict[str, Any]:
    try:
        snapshot = json.loads(alert.json()) if hasattr(alert, "json") else dict(alert)
    except (TypeError, ValueError, RecursionError) as error:
        raise MatchedContractError("alert snapshot cannot be serialized") from error
    if not isinstance(snapshot, dict):
        raise MatchedContractError("alert snapshot must be an object")
    _validate_required_alert_fields(snapshot)

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
    for alert_index, alert in enumerate(alerts):
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
            try:
                messages = build_messages(tenant_id, alert, matches)
            except MatchedContractError as error:
                _reject_alert(tenant_id, alert_index, alert, error)
                continue

            # Keep persistence errors outside malformed-message handling. Both
            # the task and raw consumer retain this record for replay.
            try:
                with EnrichmentsBl(tenant_id) as enrichments:
                    enrichments.stamp_automation_match(
                        messages[0]["alert"]["fingerprint"],
                        resolve_grace_seconds(matches),
                    )
            except Exception as error:
                raise AutomationStampError("Automation coverage stamp failed") from error

            if producer.enabled:
                try:
                    producer.publish(messages)
                except MatchedContractError as error:
                    _reject_alert(tenant_id, alert_index, alert, error)


def _reject_alert(tenant_id, alert_index, alert, error):
    automation_matched_alerts_rejected_total.inc()
    alert_id = (
        alert.get("id") if isinstance(alert, Mapping)
        else getattr(alert, "id", None)
    )
    # Do not stringify malformed objects or log arbitrary payloads.
    alert_id = alert_id[:200] if isinstance(alert_id, str) else None
    logger.warning(
        "Rejected malformed matched alert "
        "(tenant_id=%s, alert_index=%s, alert_id=%r, reason=%s)",
        tenant_id, alert_index, alert_id, error,
    )
