# builtins
import copy
import datetime
import json
import logging
import os
import sys
import time
import traceback
from typing import List

# third-parties
import dateutil
from arq import Retry
from fastapi.datastructures import FormData
from opentelemetry import trace
from sqlalchemy.orm.attributes import flag_modified
from sqlmodel import Session, select

# internals
from keep.common.alert_deduplicator.alert_deduplicator import AlertDeduplicator
from keep.common.bl.enrichments_bl import EnrichmentsBl
from keep.common.bl.incidents_bl import IncidentBl
from keep.common.bl.maintenance_windows_bl import MaintenanceWindowsBl
from keep.common.consts import KEEP_CORRELATION_ENABLED, MAINTENANCE_WINDOW_ALERT_STRATEGY
from core.db import (
    bulk_upsert_alert_fields,
    enrich_alerts_with_incidents,
    get_alerts_by_fingerprint,
    get_all_presets_dtos,
    get_enrichment_with_session, 
    get_last_alert_hashes_by_fingerprints,
    get_provider_by_name,
    get_session_sync,
    get_started_at_for_alerts,
    set_last_alert,
)
from keep.common.core.dependencies import get_pusher_client
from keep.common.core.elastic import ElasticClient
from keep.common.core.metrics import (
    events_error_counter,
    events_in_counter,
    events_out_counter,
    processing_time_summary,
    alert_enrichment_duration_seconds,
    deduplication_events_total,
    deduplication_duration_seconds,
    rules_engine_duration_seconds,
)
from models.action_type import ActionType
from models.alert import AlertDto, AlertStatus
from models.db.alert import Alert, AlertAudit, AlertRaw
from models.db.incident import IncidentStatus
from models.incident import IncidentDto
from event_managment.notification_cache import get_notification_cache
from keep.common.utils.alert_utils import sanitize_alert
from keep.common.utils.enrichment_helpers import (
    calculate_firing_time_since_last_resolved,
    calculated_firing_counter,
    calculated_start_firing_time,
    calculated_unresolved_counter,
    convert_db_alerts_to_dto_alerts,
)
from keep.providers.providers_factory import ProvidersFactory
from keep.rulesengine.rulesengine import RulesEngine

TIMES_TO_RETRY_JOB = 5  # the number of times to retry the job in case of failure
# Opt-outs/ins
KEEP_STORE_RAW_ALERTS = os.environ.get("KEEP_STORE_RAW_ALERTS", "false") == "true"

KEEP_ALERT_FIELDS_ENABLED = (
    os.environ.get("KEEP_ALERT_FIELDS_ENABLED", "true") == "true"
)
KEEP_MAINTENANCE_WINDOWS_ENABLED = (
    os.environ.get("KEEP_MAINTENANCE_WINDOWS_ENABLED", "true") == "true"
)
KEEP_AUDIT_EVENTS_ENABLED = (
    os.environ.get("KEEP_AUDIT_EVENTS_ENABLED", "true") == "true"
)
KEEP_CALCULATE_START_FIRING_TIME_ENABLED = (
    os.environ.get("KEEP_CALCULATE_START_FIRING_TIME_ENABLED", "true") == "true"
)

logger = logging.getLogger(__name__)


def _serialize_event_for_logging(event, max_size: int = 1000):
    """
    Safely serialize event for logging, truncating if too large.

    Args:
        event: The event to serialize (AlertDto, dict, list, etc.)
        max_size: Maximum size of serialized string before truncation

    Returns:
        str: Serialized event representation
    """
    try:
        if isinstance(event, AlertDto):
            event_dict = event.dict()
            # Include key fields
            serialized = json.dumps(
                {
                    "fingerprint": event_dict.get("fingerprint"),
                    "name": event_dict.get("name"),
                    "status": event_dict.get("status"),
                    "event_id": event_dict.get("event_id"),
                    "source": event_dict.get("source"),
                },
                default=str,
            )
        elif isinstance(event, dict):
            serialized = json.dumps(event, default=str)
        elif isinstance(event, list):
            # For lists, include count and first few items
            if len(event) > 0:
                first_item = event[0]
                if isinstance(first_item, AlertDto):
                    serialized = json.dumps(
                        {
                            "count": len(event),
                            "first_item": {
                                "fingerprint": first_item.fingerprint
                                if hasattr(first_item, "fingerprint")
                                else None,
                                "name": first_item.name
                                if hasattr(first_item, "name")
                                else None,
                            },
                        },
                        default=str,
                    )
                else:
                    serialized = json.dumps(
                        {"count": len(event), "first_item": first_item}, default=str
                    )
            else:
                serialized = json.dumps({"count": 0}, default=str)
        else:
            serialized = str(event)

        if len(serialized) > max_size:
            return serialized[:max_size] + "... (truncated)"
        return serialized
    except Exception:
        return str(type(event))


def __internal_preparation(
    alerts: list[AlertDto], fingerprint: str | None, api_key_name: str | None
):
    """
    Internal function to prepare the alerts for the digest

    Args:
        alerts (list[AlertDto]): List of alerts to iterate over
        fingerprint (str | None): Fingerprint to set on the alerts
        api_key_name (str | None): API key name to set on the alerts (that were used to push them)
    """
    for alert in alerts:
        try:
            if not alert.source:
                alert.source = ["keep"]
        # weird bug on Mailgun where source is int
        except Exception:
            logger.exception(
                "failed to parse source",
                extra={
                    "alert": alerts,
                },
            )
            raise

        if fingerprint is not None:
            alert.fingerprint = fingerprint

        if api_key_name is not None:
            alert.apiKeyRef = api_key_name


def __validate_last_received(event):
    # Make sure the lastReceived is a valid date string
    # tb: we do this because `AlertDto` object lastReceived is a string and not a datetime object
    # TODO: `AlertDto` object `lastReceived` should be a datetime object so we can easily validate with pydantic
    if not event.lastReceived:
        event.lastReceived = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    else:
        try:
            dateutil.parser.isoparse(event.lastReceived)
        except ValueError:
            logger.warning("Invalid lastReceived date, setting to now")
            event.lastReceived = datetime.datetime.now(
                tz=datetime.timezone.utc
            ).isoformat()


def __save_to_db(
    tenant_id,
    provider_type,
    session: Session,
    raw_events: list[dict],
    formatted_events: list[AlertDto],
    deduplicated_events: list[AlertDto],
    provider_id: str | None = None,
    timestamp_forced: datetime.datetime | None = None,
):
    logger.info(
        "Starting __save_to_db",
        extra={
            "tenant_id": tenant_id,
            "provider_type": provider_type,
            "provider_id": provider_id,
            "formatted_events_count": len(formatted_events),
            "deduplicated_events_count": len(deduplicated_events),
            "raw_events_count": len(raw_events) if isinstance(raw_events, list) else 1,
            "session_active": session.is_active
            if hasattr(session, "is_active")
            else "unknown",
        },
    )
    try:
        # keep raw events in the DB if the user wants to
        # this is mainly for debugging and research purposes
        if KEEP_STORE_RAW_ALERTS:
            logger.debug(
                "Storing raw alerts",
                extra={
                    "tenant_id": tenant_id,
                    "raw_events_count": len(raw_events)
                    if isinstance(raw_events, list)
                    else 1,
                },
            )
            if isinstance(raw_events, dict):
                raw_events = [raw_events]

            for idx, raw_event in enumerate(raw_events):
                try:
                    logger.debug(
                        "Creating AlertRaw object",
                        extra={
                            "tenant_id": tenant_id,
                            "provider_type": provider_type,
                            "raw_event_index": idx,
                        },
                    )
                    alert = AlertRaw(
                        tenant_id=tenant_id,
                        raw_alert=raw_event,
                        provider_type=provider_type,
                    )
                    session.add(alert)
                    logger.debug(
                        "AlertRaw object added to session",
                        extra={
                            "tenant_id": tenant_id,
                            "raw_event_index": idx,
                        },
                    )
                except Exception as e:
                    logger.exception(
                        "Failed to create AlertRaw object",
                        extra={
                            "tenant_id": tenant_id,
                            "provider_type": provider_type,
                            "raw_event_index": idx,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                        },
                    )
                    raise

        enrichments_bl = EnrichmentsBl(tenant_id, session)
        # add audit to the deduplicated events
        # TODO: move this to the alert deduplicator
        if KEEP_AUDIT_EVENTS_ENABLED:
            for event in deduplicated_events:
                audit = AlertAudit(
                    tenant_id=tenant_id,
                    fingerprint=event.fingerprint,
                    status=event.status,
                    action=ActionType.DEDUPLICATED.value,
                    user_id="system",
                    description="Alert was deduplicated",
                )
                session.add(audit)

                __validate_last_received(event)
                enrichments_bl.enrich_entity(
                    event.fingerprint,
                    enrichments={"lastReceived": event.lastReceived},
                    dispose_on_new_alert=True,
                    action_type=ActionType.GENERIC_ENRICH,
                    action_callee="system",
                    action_description="Alert lastReceived enriched on deduplication",
                )
                try:
                    enrichments_bl.dispose_enrichments(event.fingerprint)
                except Exception:
                    logger.exception(
                        "Failed to dispose enrichments for deduplicated alert",
                        extra={
                            "tenant_id": tenant_id,
                            "fingerprint": event.fingerprint,
                        },
                    )

                # Update the existing alert record's lastReceived field
                try:
                    logger.debug(
                        "Updating lastReceived for deduplicated alert",
                        extra={
                            "tenant_id": tenant_id,
                            "fingerprint": event.fingerprint,
                            "lastReceived": event.lastReceived,
                        },
                    )
                    # Query the most recent alert for this fingerprint using the existing session
                    query = (
                        select(Alert)
                        .where(Alert.tenant_id == tenant_id)
                        .where(Alert.fingerprint == event.fingerprint)
                        .order_by(Alert.timestamp.desc())
                        .limit(1)
                    )
                    existing_alert = session.exec(query).first()
                    if existing_alert:
                        # Update the event dict's lastReceived field
                        if existing_alert.event:
                            existing_alert.event["lastReceived"] = event.lastReceived
                            # Mark the JSON field as modified so SQLAlchemy detects the change
                            flag_modified(existing_alert, "event")
                            session.add(existing_alert)
                            session.flush()
                            logger.debug(
                                "Updated lastReceived for deduplicated alert",
                                extra={
                                    "tenant_id": tenant_id,
                                    "fingerprint": event.fingerprint,
                                    "alert_id": str(existing_alert.id),
                                    "lastReceived": event.lastReceived,
                                },
                            )
                        else:
                            logger.warning(
                                "Existing alert has no event dict",
                                extra={
                                    "tenant_id": tenant_id,
                                    "fingerprint": event.fingerprint,
                                    "alert_id": str(existing_alert.id),
                                },
                            )
                    else:
                        logger.warning(
                            "No existing alert found to update lastReceived",
                            extra={
                                "tenant_id": tenant_id,
                                "fingerprint": event.fingerprint,
                            },
                        )
                except Exception as e:
                    logger.exception(
                        "Failed to update lastReceived for deduplicated alert",
                        extra={
                            "tenant_id": tenant_id,
                            "fingerprint": event.fingerprint,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                        },
                    )

        enriched_formatted_events = []
        saved_alerts = []

        fingerprints = [event.fingerprint for event in formatted_events]
        logger.debug(
            "Getting started_at for alerts",
            extra={
                "tenant_id": tenant_id,
                "fingerprints_count": len(fingerprints),
                "fingerprints": fingerprints[:10],  # Log first 10 to avoid huge logs
            },
        )
        try:
            started_at_for_fingerprints = get_started_at_for_alerts(
                tenant_id, fingerprints, session=session
            )
            logger.debug(
                "Retrieved started_at for alerts",
                extra={
                    "tenant_id": tenant_id,
                    "started_at_count": len(started_at_for_fingerprints),
                },
            )
        except Exception as e:
            logger.exception(
                "Failed to get started_at for alerts",
                extra={
                    "tenant_id": tenant_id,
                    "fingerprints_count": len(fingerprints),
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )
            raise

        logger.info(
            "Processing formatted events",
            extra={
                "tenant_id": tenant_id,
                "formatted_events_count": len(formatted_events),
            },
        )
        for idx, formatted_event in enumerate(formatted_events):
            logger.debug(
                "Processing formatted event",
                extra={
                    "tenant_id": tenant_id,
                    "event_index": idx,
                    "fingerprint": formatted_event.fingerprint
                    if hasattr(formatted_event, "fingerprint")
                    else None,
                    "event_name": formatted_event.name
                    if hasattr(formatted_event, "name")
                    else None,
                },
            )
            formatted_event.pushed = True

            started_at = started_at_for_fingerprints.get(
                formatted_event.fingerprint, None
            )
            if started_at:
                formatted_event.startedAt = str(started_at)

            if KEEP_CALCULATE_START_FIRING_TIME_ENABLED:
                # calculate startFiring time
                previous_alert = get_alerts_by_fingerprint(
                    tenant_id=tenant_id,
                    fingerprint=formatted_event.fingerprint,
                    limit=1,
                )
                previous_alert = convert_db_alerts_to_dto_alerts(previous_alert)
                formatted_event.firingStartTime = calculated_start_firing_time(
                    formatted_event, previous_alert
                )
                formatted_event.firingStartTimeSinceLastResolved = (
                    calculate_firing_time_since_last_resolved(
                        formatted_event, previous_alert
                    )
                )

                # we now need to update the firing and unresolved counters
                formatted_event.firingCounter = calculated_firing_counter(
                    formatted_event, previous_alert
                )

                formatted_event.unresolvedCounter = calculated_unresolved_counter(
                    formatted_event, previous_alert
                )

            # Dispose enrichments that needs to be disposed
            try:
                if formatted_event.status == AlertStatus.RESOLVED.value:
                    enrichments_bl.make_enrichments_permanent(
                        formatted_event.fingerprint,
                        dispose_keys=["assignees", "status", "dismissed", "dismissUntil"],
                    )
                else:
                    enrichments_bl.dispose_enrichments(formatted_event.fingerprint)
                    # Propagate permanent assignments to the new event
                    try:
                        current_enrichment = get_enrichment_with_session(
                            session, tenant_id, formatted_event.fingerprint
                        )
                        if current_enrichment:
                            assignees = current_enrichment.enrichments.get(
                                "assignees", {}
                            )
                            if assignees:
                                # Find the latest assignment
                                sorted_timestamps = sorted(assignees.keys())
                                latest_ts = sorted_timestamps[-1]
                                latest_assignee = assignees[latest_ts]

                                # If we have a valid assignee and it's not already assigned for this timestamp
                                if (
                                    latest_assignee
                                    and formatted_event.lastReceived not in assignees
                                ):
                                    logger.info(
                                        f"Propagating assignment for {formatted_event.fingerprint} to {latest_assignee}",
                                        extra={
                                            "tenant_id": tenant_id,
                                            "fingerprint": formatted_event.fingerprint,
                                            "assignee": latest_assignee,
                                        },
                                    )
                                    enrichments_bl.enrich_entity(
                                        fingerprint=formatted_event.fingerprint,
                                        enrichments={
                                            "assignees": {
                                                formatted_event.lastReceived: latest_assignee
                                            }
                                        },
                                        action_type=ActionType.GENERIC_ENRICH,
                                        action_callee="system",
                                        action_description="Propagating assignment to new event",
                                        dispose_on_new_alert=False,
                                    )
                    except Exception:
                        logger.exception(
                            "Failed to propagate assignment",
                            extra={
                                "tenant_id": tenant_id,
                                "fingerprint": formatted_event.fingerprint,
                            },
                        )
                    # Propagate permanent assignments to the new event
                    try:
                        current_enrichment = get_enrichment_with_session(
                            session, tenant_id, formatted_event.fingerprint
                        )
                        if current_enrichment:
                            assignees = current_enrichment.enrichments.get(
                                "assignees", {}
                            )
                            if assignees:
                                # Find the latest assignment
                                sorted_timestamps = sorted(assignees.keys())
                                latest_ts = sorted_timestamps[-1]
                                latest_assignee = assignees[latest_ts]

                                # If we have a valid assignee and it's not already assigned for this timestamp
                                if (
                                    latest_assignee
                                    and formatted_event.lastReceived not in assignees
                                ):
                                    logger.info(
                                        f"Propagating assignment for {formatted_event.fingerprint} to {latest_assignee}",
                                        extra={
                                            "tenant_id": tenant_id,
                                            "fingerprint": formatted_event.fingerprint,
                                            "assignee": latest_assignee,
                                        },
                                    )
                                    enrichments_bl.enrich_entity(
                                        fingerprint=formatted_event.fingerprint,
                                        enrichments={
                                            "assignees": {
                                                formatted_event.lastReceived: latest_assignee
                                            }
                                        },
                                        action_type=ActionType.GENERIC_ENRICH,
                                        action_callee="system",
                                        action_description="Propagating assignment to new event",
                                        dispose_on_new_alert=False,
                                    )
                    except Exception:
                        logger.exception(
                            "Failed to propagate assignment",
                            extra={
                                "tenant_id": tenant_id,
                                "fingerprint": formatted_event.fingerprint,
                            },
                        )
            except Exception:
                logger.exception(
                    "Failed to dispose enrichments",
                    extra={
                        "tenant_id": tenant_id,
                        "fingerprint": formatted_event.fingerprint,
                    },
                )

            # Post format enrichment
            try:
                formatted_event = enrichments_bl.run_extraction_rules(formatted_event)
            except Exception:
                logger.exception(
                    "Failed to run post-formatting extraction rules",
                    extra={
                        "tenant_id": tenant_id,
                        "fingerprint": formatted_event.fingerprint,
                    },
                )

            __validate_last_received(formatted_event)

            logger.debug(
                "Preparing alert arguments",
                extra={
                    "tenant_id": tenant_id,
                    "event_index": idx,
                    "fingerprint": formatted_event.fingerprint
                    if hasattr(formatted_event, "fingerprint")
                    else None,
                },
            )
            alert_args = {
                "tenant_id": tenant_id,
                "provider_type": (
                    provider_type if provider_type else formatted_event.source[0]
                ),
                "event": formatted_event.dict(),
                "provider_id": provider_id,
                "fingerprint": formatted_event.fingerprint,
                "alert_hash": formatted_event.alert_hash,
            }
            alert_args = sanitize_alert(alert_args)
            if timestamp_forced is not None:
                alert_args["timestamp"] = timestamp_forced

            logger.debug(
                "Creating Alert object",
                extra={
                    "tenant_id": tenant_id,
                    "event_index": idx,
                    "fingerprint": formatted_event.fingerprint
                    if hasattr(formatted_event, "fingerprint")
                    else None,
                    "provider_type": alert_args.get("provider_type"),
                },
            )
            try:
                alert = Alert(**alert_args)
                logger.debug(
                    "Alert object created, adding to session",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                    },
                )
                session.add(alert)
                logger.debug(
                    "Flushing session to get alert ID",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                    },
                )
                session.flush()
                saved_alerts.append(alert)
                alert_id = alert.id
                formatted_event.event_id = str(alert_id)
                logger.debug(
                    "Alert saved with ID",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "alert_id": alert_id,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                    },
                )
            except Exception as e:
                logger.exception(
                    "Failed to create or save Alert object",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "alert_args_keys": list(alert_args.keys()),
                    },
                )
                raise

            if KEEP_AUDIT_EVENTS_ENABLED:
                logger.debug(
                    "Creating audit event",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                        "status": formatted_event.status
                        if hasattr(formatted_event, "status")
                        else None,
                    },
                )
                try:
                    audit = AlertAudit(
                        tenant_id=tenant_id,
                        fingerprint=formatted_event.fingerprint,
                        action=(
                            ActionType.AUTOMATIC_RESOLVE.value
                            if formatted_event.status == AlertStatus.RESOLVED.value
                            else ActionType.TIGGERED.value
                        ),
                        user_id="system",
                        description=f"Alert recieved from provider with status {formatted_event.status}",
                    )
                    session.add(audit)
                    logger.debug(
                        "Audit event added to session",
                        extra={
                            "tenant_id": tenant_id,
                            "event_index": idx,
                            "fingerprint": formatted_event.fingerprint
                            if hasattr(formatted_event, "fingerprint")
                            else None,
                        },
                    )
                except Exception as e:
                    logger.exception(
                        "Failed to create audit event",
                        extra={
                            "tenant_id": tenant_id,
                            "event_index": idx,
                            "fingerprint": formatted_event.fingerprint
                            if hasattr(formatted_event, "fingerprint")
                            else None,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                        },
                    )

            logger.debug(
                "Committing session",
                extra={
                    "tenant_id": tenant_id,
                    "event_index": idx,
                    "fingerprint": formatted_event.fingerprint
                    if hasattr(formatted_event, "fingerprint")
                    else None,
                },
            )
            try:
                session.commit()
                logger.debug(
                    "Session committed, flushing again",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                    },
                )
                session.flush()
                logger.debug(
                    "Setting last alert",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "alert_id": alert_id,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                    },
                )
                set_last_alert(tenant_id, alert, session=session)
                logger.debug(
                    "Last alert set",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "alert_id": alert_id,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                    },
                )
            except Exception as e:
                logger.exception(
                    "Failed to commit session or set last alert",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "alert_id": alert_id if "alert_id" in locals() else None,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    },
                )
                raise

            # Mapping
            try:
                enrichments_bl.run_mapping_rules(formatted_event)
            except Exception:
                logger.exception("Failed to run mapping rules")

            logger.debug(
                "Getting enrichment for alert",
                extra={
                    "tenant_id": tenant_id,
                    "event_index": idx,
                    "fingerprint": formatted_event.fingerprint
                    if hasattr(formatted_event, "fingerprint")
                    else None,
                },
            )
            try:
                alert_enrichment = get_enrichment_with_session(
                    session=session,
                    tenant_id=tenant_id,
                    fingerprint=formatted_event.fingerprint,
                )
                if alert_enrichment:
                    logger.debug(
                        "Enrichment found, applying to alert",
                        extra={
                            "tenant_id": tenant_id,
                            "event_index": idx,
                            "fingerprint": formatted_event.fingerprint
                            if hasattr(formatted_event, "fingerprint")
                            else None,
                            "enrichment_keys": list(alert_enrichment.enrichments.keys())
                            if hasattr(alert_enrichment, "enrichments")
                            else None,
                        },
                    )
                    for enrichment in alert_enrichment.enrichments:
                        # set the enrichment
                        value = alert_enrichment.enrichments[enrichment]
                        if isinstance(value, str):
                            value = value.strip()
                        setattr(formatted_event, enrichment, value)
                else:
                    logger.debug(
                        "No enrichment found for alert",
                        extra={
                            "tenant_id": tenant_id,
                            "event_index": idx,
                            "fingerprint": formatted_event.fingerprint
                            if hasattr(formatted_event, "fingerprint")
                            else None,
                        },
                    )
            except Exception as e:
                logger.exception(
                    "Failed to get or apply enrichment",
                    extra={
                        "tenant_id": tenant_id,
                        "event_index": idx,
                        "fingerprint": formatted_event.fingerprint
                        if hasattr(formatted_event, "fingerprint")
                        else None,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    },
                )
            enriched_formatted_events.append(formatted_event)
            logger.debug(
                "Completed processing formatted event",
                extra={
                    "tenant_id": tenant_id,
                    "event_index": idx,
                    "fingerprint": formatted_event.fingerprint
                    if hasattr(formatted_event, "fingerprint")
                    else None,
                },
            )

        logger.info(
            "Checking for incidents to resolve",
            extra={
                "tenant_id": tenant_id,
                "saved_alerts_count": len(saved_alerts),
            },
        )
        try:
            logger.debug(
                "Enriching alerts with incidents",
                extra={
                    "tenant_id": tenant_id,
                    "saved_alerts_count": len(saved_alerts),
                },
            )
            saved_alerts = enrich_alerts_with_incidents(
                tenant_id, saved_alerts, session
            )  # note: this only enriches incidents that were not yet ended
            logger.debug(
                "Alerts enriched with incidents",
                extra={
                    "tenant_id": tenant_id,
                    "saved_alerts_count": len(saved_alerts),
                },
            )

            session.expire_on_commit = False
            incident_bl = IncidentBl(tenant_id, session)
            for alert in saved_alerts:
                if alert.event.get("status") == AlertStatus.RESOLVED.value:
                    logger.debug(
                        "Checking for alert with status resolved",
                        extra={
                            "alert_id": alert.id,
                            "tenant_id": tenant_id,
                            "incidents_count": len(alert._incidents)
                            if hasattr(alert, "_incidents")
                            else 0,
                        },
                    )
                    for incident in alert._incidents:
                        if incident.status in IncidentStatus.get_active(
                            return_values=True
                        ):
                            logger.debug(
                                "Resolving incident",
                                extra={
                                    "alert_id": alert.id,
                                    "tenant_id": tenant_id,
                                    "incident_id": incident.id
                                    if hasattr(incident, "id")
                                    else None,
                                    "incident_status": incident.status
                                    if hasattr(incident, "status")
                                    else None,
                                },
                            )
                            incident_bl.resolve_incident_if_require(incident)
            logger.info(
                "Completed checking for incidents to resolve",
                extra={"tenant_id": tenant_id},
            )
        except Exception as e:
            logger.exception(
                "Failed to check for incidents to resolve",
                extra={
                    "tenant_id": tenant_id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )

        logger.debug(
            "Performing final commit",
            extra={
                "tenant_id": tenant_id,
                "saved_alerts_count": len(saved_alerts),
            },
        )
        try:
            session.commit()
            logger.debug(
                "Final commit completed",
                extra={
                    "tenant_id": tenant_id,
                },
            )
        except Exception as e:
            logger.exception(
                "Failed to perform final commit",
                extra={
                    "tenant_id": tenant_id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                },
            )
            raise

        logger.info(
            "Added new alerts to the DB",
            extra={
                "provider_type": provider_type,
                "num_of_alerts": len(formatted_events),
                "provider_id": provider_id,
                "tenant_id": tenant_id,
                "enriched_formatted_events_count": len(enriched_formatted_events),
            },
        )
        return enriched_formatted_events
    except Exception as e:
        error_type = type(e).__name__
        error_message = str(e)
        logger.exception(
            "Failed to add new alerts to the DB",
            extra={
                "provider_type": provider_type,
                "num_of_alerts": len(formatted_events),
                "provider_id": provider_id,
                "tenant_id": tenant_id,
                "error_type": error_type,
                "error_message": error_message,
                "session_exists": session is not None,
                "session_active": session.is_active
                if session and hasattr(session, "is_active")
                else "N/A",
                "formatted_events_count": len(formatted_events)
                if formatted_events
                else 0,
                "formatted_events_summary": _serialize_event_for_logging(
                    formatted_events[:5]
                )
                if formatted_events
                else "N/A",  # First 5 events
            },
        )
        raise


def __handle_formatted_events(
    tenant_id,
    provider_type,
    session: Session,
    raw_events: list[dict],
    formatted_events: list[AlertDto],
    tracer: trace.Tracer,
    provider_id: str | None = None,
    notify_client: bool = True,
    timestamp_forced: datetime.datetime | None = None,
    job_id: str | None = None,
):
    """
    this is super important function and does five things:
    0. checks for deduplications using alertdeduplicator
    1. adds the alerts to the DB
    2. adds the alerts to elasticsearch
    4. runs the rules engine
    5. update the presets

    TODO: add appropriate logs, trace and all of that so we can track errors

    """
    logger.info(
        "Adding new alerts to the DB",
        extra={
            "provider_type": provider_type,
            "num_of_alerts": len(formatted_events),
            "provider_id": provider_id,
            "tenant_id": tenant_id,
            "job_id": job_id,
        },
    )

    # first, check for maintenance windows
    if KEEP_MAINTENANCE_WINDOWS_ENABLED:
        with tracer.start_as_current_span("process_event_maintenance_windows_check"):
            maintenance_windows_bl = MaintenanceWindowsBl(
                tenant_id=tenant_id, session=session
            )
            if maintenance_windows_bl.maintenance_rules:
                formatted_events = [
                    event
                    for event in formatted_events
                    if maintenance_windows_bl.check_if_alert_in_maintenance_windows(
                        event
                    )
                    is False
                ]
            else:
                logger.debug(
                    "No maintenance windows configured for this tenant",
                    extra={"tenant_id": tenant_id},
                )

            if not formatted_events:
                logger.info(
                    "No alerts to process after running maintenance windows check",
                    extra={"tenant_id": tenant_id},
                )
                return

    with tracer.start_as_current_span("process_event_deduplication"):
        # second, filter out any deduplicated events
        start_dedup_time = time.time()
        alert_deduplicator = AlertDeduplicator(tenant_id)
        deduplication_rules = alert_deduplicator.get_deduplication_rules(
            tenant_id=tenant_id, provider_id=provider_id, provider_type=provider_type
        )
        last_alerts_fingerprint_to_hash = get_last_alert_hashes_by_fingerprints(
            tenant_id, [event.fingerprint for event in formatted_events]
        )
        for event in formatted_events:
            # apply_deduplication set alert_hash and isDuplicate on event
            event = alert_deduplicator.apply_deduplication(
                event, deduplication_rules, last_alerts_fingerprint_to_hash
            )

        # filter out the deduplicated events
        deduplicated_events = list(
            filter(lambda event: event.isFullDuplicate, formatted_events)
        )
        dedup_count = len(deduplicated_events)
        formatted_events = list(
            filter(lambda event: not event.isFullDuplicate, formatted_events)
        )
        
        # record metrics
        deduplication_duration_seconds.labels(
            provider_type=provider_type or "generic"
        ).observe(time.time() - start_dedup_time)
        
        if dedup_count > 0:
            deduplication_events_total.labels(
                provider_type=provider_type or "generic", status="duplicated"
            ).inc(dedup_count)
        
        # also count non-duplicated events to know the ratio
        deduplication_events_total.labels(
            provider_type=provider_type or "generic", status="new"
        ).inc(len(formatted_events))

    with tracer.start_as_current_span("process_event_save_to_db"):
        # save to db
        enriched_formatted_events = __save_to_db(
            tenant_id,
            provider_type,
            session,
            raw_events,
            formatted_events,
            deduplicated_events,
            provider_id,
            timestamp_forced,
        )

    # let's save all fields to the DB so that we can use them in the future such in deduplication fields suggestions
    # todo: also use it on correlation rules suggestions
    if KEEP_ALERT_FIELDS_ENABLED:
        with tracer.start_as_current_span("process_event_bulk_upsert_alert_fields"):
            for enriched_formatted_event in enriched_formatted_events:
                logger.debug(
                    "Bulk upserting alert fields",
                    extra={
                        "alert_event_id": enriched_formatted_event.event_id,
                        "alert_fingerprint": enriched_formatted_event.fingerprint,
                    },
                )
                fields = []
                for key, value in enriched_formatted_event.dict().items():
                    if isinstance(value, dict):
                        for nested_key in value.keys():
                            fields.append(f"{key}.{nested_key}")
                    else:
                        fields.append(key)

                bulk_upsert_alert_fields(
                    tenant_id=tenant_id,
                    fields=fields,
                    provider_id=enriched_formatted_event.providerId,
                    provider_type=enriched_formatted_event.providerType,
                    session=session,
                )

                logger.debug(
                    "Bulk upserted alert fields",
                    extra={
                        "alert_event_id": enriched_formatted_event.event_id,
                        "alert_fingerprint": enriched_formatted_event.fingerprint,
                    },
                )

    # after the alert enriched and mapped, lets send it to the elasticsearch
    with tracer.start_as_current_span("process_event_push_to_elasticsearch"):
        elastic_client = ElasticClient(tenant_id=tenant_id)
        if elastic_client.enabled:
            for alert in enriched_formatted_events:
                try:
                    logger.debug(
                        "Pushing alert to elasticsearch",
                        extra={
                            "alert_event_id": alert.event_id,
                            "alert_fingerprint": alert.fingerprint,
                        },
                    )
                    elastic_client.index_alert(
                        alert=alert,
                    )
                except Exception:
                    logger.exception(
                        "Failed to push alerts to elasticsearch",
                        extra={
                            "provider_type": provider_type,
                            "num_of_alerts": len(formatted_events),
                            "provider_id": provider_id,
                            "tenant_id": tenant_id,
                        },
                    )
                    continue

    if MAINTENANCE_WINDOW_ALERT_STRATEGY == "recover_previous_status":
        ignored_events = list(
            filter(
                lambda event: event.status == AlertStatus.MAINTENANCE.value,
                enriched_formatted_events,
            )
        )
        enriched_formatted_events = list(
            filter(
                lambda event: event.status != AlertStatus.MAINTENANCE.value,
                enriched_formatted_events,
            )
        )

    incidents = []
    with tracer.start_as_current_span("process_event_run_rules_engine"):
        # Now we need to run the rules engine
        if KEEP_CORRELATION_ENABLED:
            start_rules_time = time.time()
            try:
                rules_engine = RulesEngine(tenant_id=tenant_id)
                # handle incidents
                incidents: List[IncidentDto] = rules_engine.run_rules(
                    enriched_formatted_events, session=session
                )
            except Exception:
                logger.exception(
                    "Failed to run rules engine",
                    extra={
                        "provider_type": provider_type,
                        "num_of_alerts": len(formatted_events),
                        "provider_id": provider_id,
                        "tenant_id": tenant_id,
                    },
                )
            finally:
                rules_engine_duration_seconds.labels(
                    provider_type=provider_type or "generic"
                ).observe(time.time() - start_rules_time)

    if MAINTENANCE_WINDOW_ALERT_STRATEGY == "recover_previous_status":
        enriched_formatted_events.extend(ignored_events)

    with tracer.start_as_current_span("process_event_notify_client"):
        pusher_client = get_pusher_client() if notify_client else None
        if not pusher_client:
            return
        # Get the notification cache
        pusher_cache = get_notification_cache()

        # Tell the client to poll alerts
        if pusher_cache.should_notify(tenant_id, "poll-alerts"):
            try:
                pusher_client.trigger(
                    f"private-{tenant_id}",
                    "poll-alerts",
                    "{}",
                )
                logger.info("Told client to poll alerts")
            except Exception:
                logger.exception("Failed to tell client to poll alerts")

        if incidents and pusher_cache.should_notify(tenant_id, "incident-change"):
            try:
                pusher_client.trigger(
                    f"private-{tenant_id}",
                    "incident-change",
                    {},
                )
            except Exception:
                logger.exception("Failed to tell the client to pull incidents")

        # Now we need to update the presets
        # send with pusher

        try:
            presets = get_all_presets_dtos(tenant_id)
            rules_engine = RulesEngine(tenant_id=tenant_id)
            presets_do_update = []
            for preset_dto in presets:
                # filter the alerts based on the search query
                filtered_alerts = rules_engine.filter_alerts(
                    enriched_formatted_events, preset_dto.cel_query
                )
                # if not related alerts, no need to update
                if not filtered_alerts:
                    continue
                presets_do_update.append(preset_dto)
            if pusher_cache.should_notify(tenant_id, "poll-presets"):
                try:
                    pusher_client.trigger(
                        f"private-{tenant_id}",
                        "poll-presets",
                        json.dumps(
                            [p.name.lower() for p in presets_do_update], default=str
                        ),
                    )
                except Exception:
                    logger.exception("Failed to send presets via pusher")
        except Exception:
            logger.exception(
                "Failed to send presets via pusher",
                extra={
                    "provider_type": provider_type,
                    "num_of_alerts": len(formatted_events),
                    "provider_id": provider_id,
                    "tenant_id": tenant_id,
                },
            )
    return enriched_formatted_events


@processing_time_summary.time()
def process_event(
    ctx: dict,  # arq context
    tenant_id: str,
    provider_type: str | None,
    provider_id: str | None,
    fingerprint: str | None,
    api_key_name: str | None,
    trace_id: str | None,  # so we can track the job from the request to the digest
    event: (
        AlertDto | list[AlertDto] | IncidentDto | list[IncidentDto] | dict | None
    ),  # the event to process, either plain (generic) or from a specific provider
    notify_client: bool = True,
    timestamp_forced: datetime.datetime | None = None,
    provider_name: str | None = None,
) -> list[Alert]:
    start_time = time.time()
    job_id = ctx.get("job_id")

    extra_dict = {
        "tenant_id": tenant_id,
        "provider_type": provider_type,
        "provider_id": provider_id,
        "fingerprint": fingerprint,
        "event_type": str(type(event)),
        "trace_id": trace_id,
        "job_id": job_id,
        "raw_event": (
            event if KEEP_STORE_RAW_ALERTS else None
        ),  # Let's log the events if we store it for debugging
    }
    logger.info("Processing event", extra=extra_dict)

    tracer = trace.get_tracer(__name__)

    raw_event = copy.deepcopy(event)
    events_in_counter.inc()
    session = None
    try:
        logger.info(
            "Starting event processing",
            extra={
                **extra_dict,
                "event_summary": _serialize_event_for_logging(event),
            },
        )

        with tracer.start_as_current_span("process_event_get_db_session"):
            # Create a session to be used across the processing task
            logger.debug(
                "Creating database session",
                extra={
                    **extra_dict,
                },
            )
            try:
                session = get_session_sync()
                logger.info(
                    "Database session created successfully",
                    extra={
                        **extra_dict,
                        "session_active": session.is_active
                        if hasattr(session, "is_active")
                        else "unknown",
                    },
                )
            except Exception as e:
                logger.exception(
                    "Failed to create database session",
                    extra={
                        **extra_dict,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    },
                )
                raise

        # If we have a provider name but no provider id, we need to get the provider
        if provider_name and not provider_id:
            logger.info(
                "Resolving provider by name", extra={"provider_name": provider_name}
            )
            provider = get_provider_by_name(tenant_id, provider_name)
            if provider:
                provider_id = provider.id
                provider_type = provider.type
                extra_dict.update(
                    {"provider_id": provider_id, "provider_type": provider_type}
                )
                logger.info(
                    "Provider resolved",
                    extra={"provider_id": provider_id, "provider_type": provider_type},
                )
            else:
                logger.warning(
                    "Provider not found by name",
                    extra={"provider_name": provider_name, "tenant_id": tenant_id},
                )

        # If we have a provider type and the event needs parsing (it's a dict but we might want to let the provider parse it if it has specific logic)
        # Note: currently the API does extract_generic_body which returns dict/bytes/Form.
        # If we moved that here, 'event' is that raw body.
        if provider_type and provider_id:
            try:
                provider_class = ProvidersFactory.get_installed_provider(
                    tenant_id=tenant_id,
                    provider_id=provider_id,
                    provider_type=provider_type,
                )
                if hasattr(provider_class, "parse_event_raw_body"):
                    # This allows providers to parse the raw body (e.g. bytes to dict, or dict to dict)
                    # Before this change, the API did this.
                    logger.info(
                        "Parsing event raw body using provider",
                        extra={"provider_type": provider_type},
                    )
                    event = provider_class.parse_event_raw_body(event)
                    # update summary
                    extra_dict["event_summary"] = _serialize_event_for_logging(event)
            except Exception as e:
                # If we fail to load the provider or parse, we just continue with the event as is,
                # but log the error. This mimics previous "best effort" or "generic" behavior if provider fails?
                # Actually, if parsing fails, formatting might fail later. But we shouldn't stop processing entirely if possible.
                logger.warning(
                    "Failed to parse event with provider",
                    extra={"error": str(e), "provider_type": provider_type},
                )

        # Pre alert formatting extraction rules
        with tracer.start_as_current_span("process_event_pre_alert_formatting"):
            logger.debug(
                "Running pre-formatting extraction rules",
                extra={
                    **extra_dict,
                    "event_summary": _serialize_event_for_logging(event),
                },
            )
            enrichments_bl = EnrichmentsBl(tenant_id, session)
            try:
                event = enrichments_bl.run_extraction_rules(event, pre=True)
                logger.debug(
                    "Pre-formatting extraction rules completed",
                    extra={
                        **extra_dict,
                        "event_summary": _serialize_event_for_logging(event),
                    },
                )
            except Exception as e:
                logger.exception(
                    "Failed to run pre-formatting extraction rules",
                    extra={
                        **extra_dict,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                        "event_summary": _serialize_event_for_logging(event),
                    },
                )

        with tracer.start_as_current_span("process_event_provider_formatting"):
            logger.debug(
                "Starting provider formatting",
                extra={
                    **extra_dict,
                    "event_type": str(type(event)),
                    "event_summary": _serialize_event_for_logging(event),
                },
            )
            if (
                provider_type is not None
                and isinstance(event, dict)
                or isinstance(event, FormData)
                or isinstance(event, list)
            ):
                try:
                    logger.debug(
                        "Getting provider class",
                        extra={
                            **extra_dict,
                            "provider_type": provider_type,
                        },
                    )
                    provider_class = ProvidersFactory.get_provider_class(provider_type)
                    logger.debug(
                        "Provider class retrieved",
                        extra={
                            **extra_dict,
                            "provider_class": str(provider_class),
                        },
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to get provider class, falling back to 'keep'",
                        extra={
                            **extra_dict,
                            "provider_type": provider_type,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                        },
                    )
                    provider_class = ProvidersFactory.get_provider_class("keep")

                if isinstance(event, list):
                    logger.debug(
                        "Formatting list of events",
                        extra={
                            **extra_dict,
                            "event_count": len(event),
                        },
                    )
                    event_list = []
                    for idx, event_item in enumerate(event):
                        try:
                            if not isinstance(event_item, AlertDto):
                                logger.debug(
                                    "Formatting event item",
                                    extra={
                                        **extra_dict,
                                        "item_index": idx,
                                        "item_type": str(type(event_item)),
                                    },
                                )
                                formatted_item = provider_class.format_alert(
                                    tenant_id=tenant_id,
                                    event=event_item,
                                    provider_id=provider_id,
                                    provider_type=provider_type,
                                )
                                event_list.append(formatted_item)
                                logger.debug(
                                    "Event item formatted",
                                    extra={
                                        **extra_dict,
                                        "item_index": idx,
                                        "formatted_summary": _serialize_event_for_logging(
                                            formatted_item
                                        ),
                                    },
                                )
                            else:
                                event_list.append(event_item)
                        except Exception as e:
                            logger.exception(
                                "Failed to format event item",
                                extra={
                                    **extra_dict,
                                    "item_index": idx,
                                    "error_type": type(e).__name__,
                                    "error_message": str(e),
                                },
                            )
                            raise
                    event = event_list
                    logger.info(
                        "Formatted list of events",
                        extra={
                            **extra_dict,
                            "formatted_count": len(event),
                        },
                    )
                else:
                    logger.debug(
                        "Formatting single event",
                        extra={
                            **extra_dict,
                            "event_summary": _serialize_event_for_logging(event),
                        },
                    )
                    try:
                        event = provider_class.format_alert(
                            tenant_id=tenant_id,
                            event=event,
                            provider_id=provider_id,
                            provider_type=provider_type,
                        )
                        logger.debug(
                            "Single event formatted",
                            extra={
                                **extra_dict,
                                "formatted_summary": _serialize_event_for_logging(
                                    event
                                ),
                            },
                        )
                    except Exception as e:
                        logger.exception(
                            "Failed to format single event",
                            extra={
                                **extra_dict,
                                "error_type": type(e).__name__,
                                "error_message": str(e),
                                "event_summary": _serialize_event_for_logging(event),
                            },
                        )
                        raise
                # SHAHAR: for aws cloudwatch, we get a subscription notification message that we should skip
                #         todo: move it to be generic
                if event is None and provider_type == "cloudwatch":
                    logger.info(
                        "This is a subscription notification message from AWS - skipping processing",
                        extra=extra_dict,
                    )
                    return
                elif event is None:
                    logger.info(
                        "Provider returned None (failed silently), skipping processing",
                        extra=extra_dict,
                    )

        if event:
            logger.debug(
                "Processing formatted event",
                extra={
                    **extra_dict,
                    "event_type": str(type(event)),
                    "event_summary": _serialize_event_for_logging(event),
                },
            )
            if isinstance(event, str):
                extra_dict["raw_event"] = event
                logger.error(
                    "Event is a string (malformed json?), skipping processing",
                    extra=extra_dict,
                )
                return None

            # In case when provider_type is not set
            if isinstance(event, dict):
                logger.debug(
                    "Converting dict event to AlertDto",
                    extra={
                        **extra_dict,
                        "event_keys": list(event.keys())
                        if isinstance(event, dict)
                        else None,
                    },
                )
                if not event.get("name"):
                    event["name"] = event.get("id", "unknown alert name")
                event = [AlertDto(**event)]
                raw_event = [raw_event]
                logger.debug(
                    "Converted dict to AlertDto list",
                    extra={
                        **extra_dict,
                        "alert_count": len(event),
                    },
                )

            # Prepare the event for the digest
            if isinstance(event, AlertDto):
                logger.debug(
                    "Converting single AlertDto to list",
                    extra={
                        **extra_dict,
                        "alert_fingerprint": event.fingerprint
                        if hasattr(event, "fingerprint")
                        else None,
                    },
                )
                event = [event]
                raw_event = [raw_event]

            with tracer.start_as_current_span("process_event_internal_preparation"):
                logger.debug(
                    "Running internal preparation",
                    extra={
                        **extra_dict,
                        "alert_count": len(event) if isinstance(event, list) else 1,
                        "fingerprint": fingerprint,
                        "api_key_name": api_key_name,
                    },
                )
                __internal_preparation(event, fingerprint, api_key_name)
                logger.debug(
                    "Internal preparation completed",
                    extra={
                        **extra_dict,
                        "alert_count": len(event) if isinstance(event, list) else 1,
                    },
                )

            logger.info(
                "Calling __handle_formatted_events",
                extra={
                    **extra_dict,
                    "alert_count": len(event) if isinstance(event, list) else 1,
                    "alerts_summary": _serialize_event_for_logging(event),
                },
            )
            formatted_events = __handle_formatted_events(
                tenant_id,
                provider_type,
                session,
                raw_event,
                event,
                tracer,
                provider_id,
                notify_client,
                timestamp_forced,
                job_id,
            )
            logger.info(
                "__handle_formatted_events completed",
                extra={
                    **extra_dict,
                    "formatted_events_count": len(formatted_events)
                    if formatted_events
                    else 0,
                },
            )

            logger.info(
                "Event processed successfully",
                extra={
                    **extra_dict,
                    "processing_time": time.time() - start_time,
                    "formatted_events_count": len(formatted_events)
                    if formatted_events
                    else 0,
                },
            )
            events_out_counter.inc()
            return formatted_events
        else:
            logger.info(
                "Event is None or empty, skipping processing",
                extra=extra_dict,
            )
            return []
    except Exception as e:
        error_type = type(e).__name__
        error_message = str(e)
        stacktrace = traceback.format_exc()
        tb = traceback.extract_tb(sys.exc_info()[2])

        # Get the name of the last function in the traceback
        try:
            last_function = tb[-1].name if tb else ""
            last_file = tb[-1].filename if tb else ""
            last_line = tb[-1].lineno if tb else ""
        except Exception:
            last_function = ""
            last_file = ""
            last_line = ""

        # Check if the last function matches the pattern
        if "_format_alert" in last_function or "_format" in last_function:
            # In case of exception, add the alerts to the defect table
            error_msg = stacktrace
        # if this is a bug in the code, we don't want the user to see the stacktrace
        else:
            error_msg = "Error processing event, contact Keep team for more information"

        logger.exception(
            "Error processing event",
            extra={
                **extra_dict,
                "processing_time": time.time() - start_time,
                "error_type": error_type,
                "error_message": error_message,
                "last_function": last_function,
                "last_file": last_file,
                "last_line": last_line,
                "raw_event_summary": _serialize_event_for_logging(raw_event),
                "event_summary": _serialize_event_for_logging(event),
                "session_exists": session is not None,
                "session_active": session.is_active
                if session and hasattr(session, "is_active")
                else "N/A",
            },
        )

        logger.error(
            "Attempting to save error alerts",
            extra={
                **extra_dict,
                "error_type": error_type,
                "raw_event_summary": _serialize_event_for_logging(raw_event),
            },
        )
        try:
            __save_error_alerts(tenant_id, provider_type, raw_event, error_msg)
            logger.info(
                "Error alerts saved successfully",
                extra={
                    **extra_dict,
                },
            )
        except Exception as save_error:
            logger.exception(
                "Failed to save error alerts",
                extra={
                    **extra_dict,
                    "save_error_type": type(save_error).__name__,
                    "save_error_message": str(save_error),
                },
            )

        events_error_counter.inc()

        # Retrying only if context is present (running the job in arq worker)
        if bool(ctx):
            retry_defer = ctx["job_try"] * TIMES_TO_RETRY_JOB
            logger.warning(
                "Retrying job",
                extra={
                    **extra_dict,
                    "job_try": ctx.get("job_try", 0),
                    "retry_defer": retry_defer,
                    "error_type": error_type,
                },
            )
            raise Retry(defer=retry_defer)
        else:
            logger.warning(
                "Not retrying job (no context)",
                extra={
                    **extra_dict,
                    "error_type": error_type,
                },
            )
    finally:
        alert_enrichment_duration_seconds.labels(
            source=provider_type or "unknown"
        ).observe(time.time() - start_time)
        if session is not None:
            try:
                logger.debug(
                    "Closing database session",
                    extra={
                        **extra_dict,
                        "session_active": session.is_active
                        if hasattr(session, "is_active")
                        else "unknown",
                    },
                )
                session.close()
                logger.debug(
                    "Database session closed",
                    extra={
                        **extra_dict,
                    },
                )
            except Exception as close_error:
                logger.exception(
                    "Failed to close database session",
                    extra={
                        **extra_dict,
                        "close_error_type": type(close_error).__name__,
                        "close_error_message": str(close_error),
                    },
                )
        else:
            logger.debug(
                "No database session to close",
                extra={
                    **extra_dict,
                },
            )


def __save_error_alerts(
    tenant_id,
    provider_type,
    raw_events: dict | list[dict] | list[AlertDto] | AlertDto | None,
    error_message: str,
):
    if not raw_events:
        logger.info("No raw events to save as errors")
        return

    try:
        logger.info(
            "Getting database session",
            extra={
                "tenant_id": tenant_id,
            },
        )
        session = get_session_sync()

        # Convert to list if single dict
        if not isinstance(raw_events, list):
            logger.info("Converting single dict or AlertDto to list")
            raw_events = [raw_events]

        logger.info(f"Saving {len(raw_events)} error alerts")

        if len(raw_events) > 5:
            logger.info(
                "Raw Alert Payload",
                extra={
                    "tenant_id": tenant_id,
                    "raw_events": raw_events,
                },
            )
        for raw_event in raw_events:
            # Convert AlertDto to dict if needed
            if isinstance(raw_event, AlertDto):
                logger.info("Converting AlertDto to dict")
                raw_event = raw_event.dict()

            # TODO: change to debug
            logger.debug(
                "Creating AlertRaw object",
                extra={
                    "tenant_id": tenant_id,
                    "raw_event": raw_event,
                },
            )
            alert = AlertRaw(
                tenant_id=tenant_id,
                raw_alert=raw_event,
                provider_type=provider_type,
                error=True,
                error_message=error_message,
            )
            session.add(alert)
            logger.info("AlertRaw object created")
        session.commit()
        logger.info("Successfully saved error alerts")
    except Exception:
        logger.exception("Failed to save error alerts")
    finally:
        session.close()


