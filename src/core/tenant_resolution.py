"""Operator-based tenant resolution for events ingested via Kafka.

This logic was originally applied in keep-ingestions while that service still
had a database dependency. After keep-ingestions was made DB-less, operator ->
tenant routing moved downstream to keep-event-handler (VENA-5596 Epic 5).
"""

import logging

from src.core.db import get_operator_by_name

logger = logging.getLogger(__name__)

# Fallback tenant for alerts that carry no operator, or an operator that maps
# to no tenant. Matches the gateway/GENERAL tenant.
GENERIC_TENANT_UUID = "keep"


def _extract_operator(event) -> str | None:
    """Best-effort read of the alert's `operator` routing key from an incoming
    event, which may be a single alert dict or a list of alert dicts. For a
    batch we use the first alert's operator. Non-dict payloads route to the
    general tenant.
    """
    if not isinstance(event, (dict, list)):
        return None
    item = event[0] if isinstance(event, list) and event else event
    if not isinstance(item, dict):
        return None
    return item.get("operator")


def _resolve_ingestion_tenant(event) -> str:
    """Route an alert to the tenant that owns its `operator`.

    An alert with no operator, or an operator that maps to no tenant, goes to
    the GENERAL tenant -- NOT the ingestion key's tenant -- so a specific tenant
    only ever receives its own operators' alerts.
    """
    operator_name = _extract_operator(event)
    if not operator_name:
        return GENERIC_TENANT_UUID
    operator = get_operator_by_name(operator_name)
    if operator is None:
        logger.info(
            "Alert operator matched no tenant; routing to general",
            extra={"operator": operator_name, "tenant_id": GENERIC_TENANT_UUID},
        )
        return GENERIC_TENANT_UUID
    logger.info(
        "Routing alert by operator",
        extra={"operator": operator_name, "tenant_id": operator.tenant_id},
    )
    return operator.tenant_id