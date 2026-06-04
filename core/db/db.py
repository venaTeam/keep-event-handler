"""
Keep main database module.

This module contains the CRUD database functions for Keep.
"""

import logging
from dotenv import load_dotenv, find_dotenv
from dateutil.parser import parse
import hashlib
from datetime import datetime, timedelta, timezone
import time
from sqlalchemy.orm import foreign, joinedload, subqueryload
from functools import wraps
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import  Callable, Iterator, List, Optional, Tuple
import uuid
from uuid import UUID
from sqlalchemy.sql import exists, expression
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.orm.attributes import flag_modified


from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from retry import retry
from sqlalchemy import (
    String,
    and_,
    case,
    cast,
    desc,
    func,
    literal,
    null,
    select,
    union,
    update,
)

from sqlalchemy.exc import IntegrityError, InternalError, OperationalError
from sqlalchemy.orm import subqueryload
from sqlmodel import Session, col, or_, select, text


from enum import Enum
from core.db.helpers import NULL_FOR_DELETED_AT
from core.db.db_utils import get_json_extract_field
from models.db.preset import PresetDto, StaticPresetsId, Preset
from models.db.alert import LastAlertToIncident, AlertDeduplicationEvent, LastAlert, Alert, AlertDeduplicationRule, AlertEnrichment, AlertAudit, AlertField
from models.db.provider import Provider, ProviderExecutionLog
from models.db.rule import Rule
from models.db.incident import Incident, IncidentType, IncidentStatus, IncidentSeverity
from models.incident import IncidentDtoIn, IncidentDto
from models.db.tenant import TenantApiKey, Tenant
from models.alert import AlertStatus, DeduplicationRuleDto, DeduplicationRuleRequestDto
from models.db.maintenance_window import MaintenanceWindowRule
from models.db.topology import TopologyService
from models.db.extraction import ExtractionRule
from models.db.mapping import MappingRule
from fastapi import HTTPException


from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.sql.functions import count


STATIC_PRESETS = {
    "feed": PresetDto(
        id=StaticPresetsId.FEED_PRESET_ID.value,
        name="feed",
        options=[
            {"label": "CEL", "value": ""},
            {
                "label": "SQL",
                "value": {"sql": "", "params": {}},
            },
        ],
        created_by=None,
        is_private=False,
        is_noisy=False,
        should_do_noise_now=False,
        static=True,
        tags=[],
    )
}
from core.db.db_utils import (
    create_db_engine,
    get_json_extract_field,
)

# This import is required to create the tables
from models.action_type import ActionType

logger = logging.getLogger(__name__)


# this is a workaround for gunicorn to load the env vars
# because somehow in gunicorn it doesn't load the .env file
load_dotenv(find_dotenv())


engine = create_db_engine()
SQLAlchemyInstrumentor().instrument(enable_commenter=True, engine=engine)


ALLOWED_INCIDENT_FILTERS = [
    "status",
    "severity",
    "sources",
    "affected_services",
    "assignee",
]


INTERVAL_WORKFLOWS_RELAUNCH_TIMEOUT = timedelta(minutes=60)
WORKFLOWS_TIMEOUT = timedelta(minutes=120)


def retry_on_db_error(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (OperationalError, IntegrityError, NoActiveSqlTransaction) as e:
            logger.warning(f"Database error in {func.__name__}: {str(e)}")
            # Basic retry once for now, or just raise if it fails again
            try:
                return func(*args, **kwargs)
            except Exception:
                raise e
    return wrapper



def get_alerts_data_for_incident(
    tenant_id: str,
    fingerprints: Optional[List[str]] = None,
    session: Optional[Session] = None,
):
    """
    Function to prepare aggregated data for incidents from the given list of alert_ids
    Logic is wrapped to the inner function for better usability with an optional database session

    Args:
        tenant_id (str): The tenant ID to filter alerts
        alert_ids (list[str | UUID]): list of alert ids for aggregation
        session (Optional[Session]): The database session or None

    Returns: dict {sources: list[str], services: list[str], count: int}
    """
    with existed_or_new_session(session) as session:
        fields = (
            Alert.service,
            Alert.provider_type,
            Alert.fingerprint,
            Alert.severity,
        )

        alerts_data = session.exec(
            select(*fields)
            .select_from(LastAlert)
            .join(
                Alert,
                and_(
                    LastAlert.tenant_id == Alert.tenant_id,
                    LastAlert.alert_id == Alert.id,
                ),
            )
            .where(
                LastAlert.tenant_id == tenant_id,
                col(LastAlert.fingerprint).in_(fingerprints),
            )
        ).all()

        sources = []
        services = []
        severities = []

        for service, source, fingerprint, severity in alerts_data:
            if source:
                sources.append(source)
            if service:
                services.append(service)
            if severity:
                if isinstance(severity, int):
                    severities.append(IncidentSeverity.from_number(severity))
                else:
                    severities.append(IncidentSeverity(severity))

        return {
            "sources": set(sources),
            "services": set(services),
            "max_severity": max(severities) if severities else IncidentSeverity.LOW,
        }


def enrich_incidents_with_alerts(
    tenant_id: str, incidents: List[Incident], session: Optional[Session] = None
):
    with existed_or_new_session(session) as session:
        incident_alerts = session.exec(
            select(LastAlertToIncident.incident_id, Alert, LastAlert)
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                    LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                    LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .where(
                LastAlert.tenant_id == tenant_id,
                LastAlertToIncident.incident_id.in_(
                    [incident.id for incident in incidents]
                ),
            )
        ).all()

        # The cross-occurrence tracking + user-state fields were
        # relocated from alert to lastalert. Attach them as runtime attributes
        # on the raw Alert so existing consumers that read e.g.
        # alert.unresolved_counter / alert.status keep working.
        # Tracking counters are always taken from lastalert; user-state columns
        # (status override, assignee, note, ...) only override when set so the
        # provider's alert.status is preserved when there is no override.
        _tracking_attrs = (
            "last_received",
            "firing_counter",
            "unresolved_counter",
            "started_at",
            "firing_start_time",
            "firing_start_time_since_last_resolved",
        )
        _user_state_attrs = (
            "status",
            "assignee",
            "note",
            "dismiss_mode",
            "dismissed_until",
        )
        alerts_per_incident = defaultdict(list)
        for incident_id, alert, last_alert in incident_alerts:
            # The relocated fields are no longer mapped columns on Alert, so set
            # them as plain Python attributes (bypass SQLModel/Pydantic field
            # validation via object.__setattr__).
            for _attr in _tracking_attrs:
                object.__setattr__(alert, _attr, getattr(last_alert, _attr, None))
            for _attr in _user_state_attrs:
                _val = getattr(last_alert, _attr, None)
                if _val is not None:
                    object.__setattr__(alert, _attr, _val)
            object.__setattr__(alert, "deleted", bool(last_alert.deleted))
            alerts_per_incident[incident_id].append(alert)

        for incident in incidents:
            incident._alerts = alerts_per_incident[incident.id]

        return incidents

@retry_on_db_error
def create_incident_from_dict(
    tenant_id: str, incident_data: dict, session: Optional[Session] = None
) -> Optional[Incident]:
    is_predicted = incident_data.get("is_predicted", False)
    if "is_candidate" not in incident_data:
        incident_data["is_candidate"] = is_predicted
    with existed_or_new_session(session) as session:
        new_incident = Incident(**incident_data, tenant_id=tenant_id)
        session.add(new_incident)
        session.commit()
        session.refresh(new_incident)
    return new_incident


def __convert_to_uuid(value: str, should_raise: bool = False) -> UUID | None:
    try:
        return UUID(value)
    except ValueError:
        if should_raise:
            raise ValueError(f"Invalid UUID: {value}")
        return None


@contextmanager
def existed_or_new_session(session: Optional[Session] = None) -> Iterator[Session]:
    try:
        if session:
            yield session
        else:
            with Session(engine) as session:
                yield session
    except Exception as e:
        e.session = session
        raise e


def get_session() -> Session:
    """
    Creates a database session.

    Yields:
        Session: A database session
    """
    from opentelemetry import trace  # pylint: disable=import-outside-toplevel

    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("get_session"):
        with Session(engine) as session:
            yield session



def get_session_sync() -> Session:
    """
    Creates a database session.

    Returns:
        Session: A database session
    """
    return Session(engine)


# === Typed user-enrichment columns on LastAlert ===
# Derived from the LastAlert model (single source of truth) — columns tagged
# info={"enrichable": True} are the user-writable enrichment columns. Keeping this in sync
# with the model is automatic; do not hand-maintain a literal list.
LASTALERT_ENRICHMENT_COLUMNS = {
    column.name
    for column in LastAlert.__table__.columns
    if column.info.get("enrichable")
}
# Legacy keys accepted at the write boundary and translated below.
_LEGACY_ENRICHMENT_KEYS = {"dismissed", "dismiss_until"}

# System tracking columns owned by set_last_alert(tracking=...), derived from the LastAlert
# model (single source of truth) — columns tagged info={"tracking": True}. Strict allow-list
# so the tracking write path can never clobber user-enrichment columns.
LASTALERT_TRACKING_COLUMNS = {
    column.name
    for column in LastAlert.__table__.columns
    if column.info.get("tracking")
}


def normalize_enrichments(enrichments: dict, strict: bool = True) -> dict:
    """Translate legacy enrichment keys to the typed-column model and handle
    unknown keys.

    Translation rules (see ALERTENRICHMENT_REMOVAL_SPEC §"Dismiss"):
      - dismissed: true  -> status='suppressed', dismiss_mode='permanent'
          (if a dismiss_until/timestamp is also present -> dismiss_mode='dismiss_until',
           dismissed_until=<ts>)
      - dismissed: false -> status=None, dismiss_mode=None, dismissed_until=None
      - dismiss_mode/dismissed_until forwarded directly.

    Unknown keys (e.g. arbitrary extraction/mapping fields, which have no
    destination in the strict schema):
      - strict=True (route-driven writes): raise ValueError -> HTTP 422.
      - strict=False (internal system writes): discard with a warning.
    """
    normalized = dict(enrichments)

    if "dismissed" in normalized:
        dismissed = normalized.pop("dismissed")
        # A dismiss_until / dismissed_until timestamp may accompany dismissed:true
        ts = normalized.get("dismissed_until")
        if ts is None:
            ts = normalized.pop("dismiss_until", None)
        if dismissed:
            normalized.setdefault("status", "suppressed")
            if ts:
                normalized["dismiss_mode"] = "dismiss_until"
                normalized["dismissed_until"] = ts
            else:
                normalized.setdefault("dismiss_mode", "permanent")
        else:
            # Undismiss: clear dismiss state; revert status to provider value
            # UNLESS the caller supplied an explicit status (matches the
            # equivalent fix in api-gateway + workflows for change-status flows).
            normalized.setdefault("status", None)
            normalized["dismiss_mode"] = None
            normalized["dismissed_until"] = None
    elif "dismiss_until" in normalized:
        # dismiss_until without dismissed flag -> treat as dismiss_until mode
        ts = normalized.pop("dismiss_until")
        if ts:
            normalized.setdefault("status", "suppressed")
            normalized["dismiss_mode"] = "dismiss_until"
            normalized["dismissed_until"] = ts

    unknown = set(normalized) - LASTALERT_ENRICHMENT_COLUMNS
    if unknown:
        if strict:
            raise ValueError(
                f"Unknown enrichment key(s): {sorted(unknown)}. "
                f"Allowed: {sorted(LASTALERT_ENRICHMENT_COLUMNS | _LEGACY_ENRICHMENT_KEYS)}"
            )
        logger.warning(
            "enrichment.discard_unknown_keys",
            extra={"keys": sorted(unknown)},
        )
        for key in unknown:
            normalized.pop(key, None)
    return normalized


def last_alert_enrichments_dict(last_alert: "LastAlert") -> dict:
    """Build the user-enrichment dict (status/assignee/note/dismiss/deleted)
    from a LastAlert row's typed columns. NULL columns are omitted so callers
    fall back to the provider value. Always includes the derived `dismissed`
    compat field.
    """
    data: dict = {}
    for col_name in (
        "status",
        "assignee",
        "note",
        "dismiss_mode",
        "ticket_type",
        "ticket_url",
        "ticket_provider_id",
    ):
        val = getattr(last_alert, col_name, None)
        if val is not None:
            data[col_name] = val
    if last_alert.dismissed_until is not None:
        ts = last_alert.dismissed_until
        if isinstance(ts, datetime):
            # Match the legacy "...%f.Z" wire format AlertDto.validate_dismissed parses
            # (strptime "%Y-%m-%dT%H:%M:%S.%fZ"); plain .isoformat() yields "...+00:00"
            # which the validator rejects and json.dumps cannot serialize a raw datetime.
            ts = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        data["dismissed_until"] = ts
    if last_alert.deleted:
        data["deleted"] = True
    # derived compat field for existing consumers
    data["dismissed"] = last_alert.status == "suppressed"
    return data


def _apply_enrichments_to_last_alert(last_alert: LastAlert, enrichments: dict, force=False):
    """Write normalized enrichment keys onto LastAlert typed columns.

    - None sets the column NULL (reverts a field to the provider value).
    - Note-guard: an empty/whitespace/None incoming note is excluded from the
      write unless force=True (explicit clear).
    """
    for key, value in enrichments.items():
        if key == "note" and not force:
            if value is None or (isinstance(value, str) and not value.strip()):
                # never erase an existing user note on an automated write
                continue
        setattr(last_alert, key, value)


def _enrich_incident_alertenrichment(
    session,
    tenant_id,
    fingerprint,
    enrichments,
    action_type: ActionType,
    action_callee: str,
    action_description: str,
    force=False,
    audit_enabled=True,
):
    """
    Legacy AlertEnrichment upsert for INCIDENT enrichment (entity_type=="incident").

    ALERT enrichment was moved to typed LastAlert columns, but incidents are
    UUID-keyed and have no LastAlert row, so incident enrichment must continue to
    write/read the AlertEnrichment JSONB row (keyed by the incident UUID in
    alert_fingerprint) exactly as it did before the alertenrichment removal —
    until a later migration removes the `alertenrichment` table.

    No dismissed/dismiss_mode translation, no D1 no-op, no unknown-key rejection:
    arbitrary keys are allowed and AlertAudit is preserved. This is a faithful
    recovery of the `_enrich_entity` body from before the alertenrichment removal.
    """
    enrichment = get_enrichment_with_session(session, tenant_id, fingerprint)
    if enrichment:
        # if force - override existing enrichments. being used to dispose enrichments if necessary
        if force:
            new_enrichment_data = enrichments
        else:
            new_enrichment_data = {**enrichment.enrichments, **enrichments}
        # Preserve existing note if incoming note is empty/None/not provided
        # BUT only when NOT forcing — force=True means the caller explicitly wants
        # to replace all enrichments, including removing the note.
        if not force:
            incoming_note = enrichments.get("note")
            if not incoming_note or (
                isinstance(incoming_note, str) and not incoming_note.strip()
            ):
                existing_note = enrichment.enrichments.get("note")
                if existing_note:
                    new_enrichment_data["note"] = existing_note
        # Remove keys with None values (e.g., status=None when undismissing)
        # This allows the entity to revert to its original value from event data
        for key, value in list(enrichments.items()):
            if value is None and key in new_enrichment_data:
                del new_enrichment_data[key]

        # SQLAlchemy doesn't support updating JSON fields, so we need to do it manually
        # https://github.com/sqlalchemy/sqlalchemy/discussions/8396#discussion-4308891
        stmt = (
            update(AlertEnrichment)
            .where(AlertEnrichment.id == enrichment.id)
            .values(enrichments=new_enrichment_data)
        )
        session.execute(stmt)
        if audit_enabled:
            audit = AlertAudit(
                tenant_id=tenant_id,
                fingerprint=fingerprint,
                user_id=action_callee,
                action=action_type.value,
                description=action_description,
            )
            session.add(audit)
        session.commit()
        # Refresh the instance to get updated data from the database
        session.refresh(enrichment)
        return enrichment
    else:
        try:
            alert_enrichment = AlertEnrichment(
                tenant_id=tenant_id,
                alert_fingerprint=fingerprint,
                enrichments=enrichments,
            )
            session.add(alert_enrichment)
            if audit_enabled:
                audit = AlertAudit(
                    tenant_id=tenant_id,
                    fingerprint=fingerprint,
                    user_id=action_callee,
                    action=action_type.value,
                    description=action_description,
                )
                session.add(audit)
            session.commit()
            return alert_enrichment
        except IntegrityError:
            # If we hit a duplicate entry error, rollback and get the existing enrichment
            logger.warning(
                "Duplicate entry error",
                extra={
                    "tenant_id": tenant_id,
                    "fingerprint": fingerprint,
                    "enrichments": enrichments,
                },
            )
            session.rollback()
            return get_enrichment_with_session(session, tenant_id, fingerprint)


def _enrich_entity(
    session,
    tenant_id,
    fingerprint,
    enrichments,
    action_type: ActionType,
    action_callee: str,
    action_description: str,
    force=False,
    audit_enabled=True,
    strict=True,
    entity_type: str = "alert",
):
    """
    Enrich an entity.

    ALERT enrichment (entity_type=="alert", the normal fingerprint path):
        user-enrichment state lives on LastAlert typed columns, not on the
        alertenrichment JSONB. Legacy `dismissed`/`dismiss_until` keys are
        translated. Unknown keys are rejected (strict, ValueError -> 422 at the
        route) or discarded (strict=False, internal system writes). D1: if no
        LastAlert row exists for the fingerprint, the column UPDATE is skipped
        (logged) but the AlertAudit row is still created.

    INCIDENT enrichment (entity_type=="incident", UUID-keyed, no LastAlert row):
        falls back to the legacy AlertEnrichment JSONB upsert until Phase 3.
        See _enrich_incident_alertenrichment.
    """
    if entity_type == "incident":
        return _enrich_incident_alertenrichment(
            session,
            tenant_id,
            fingerprint,
            enrichments,
            action_type,
            action_callee,
            action_description,
            force=force,
            audit_enabled=audit_enabled,
        )

    normalized = normalize_enrichments(enrichments, strict=strict)

    last_alert = get_last_alert_by_fingerprint(
        tenant_id, fingerprint, session, for_update=True
    )

    if last_alert is None:
        # D1: enrich-before-first-alert -> no column write, still audit.
        logger.warning(
            "enrichment.no_lastalert",
            extra={
                "tenant_id": tenant_id,
                "fingerprint": fingerprint,
                "enrichments": list(normalized.keys()),
            },
        )
    else:
        _apply_enrichments_to_last_alert(last_alert, normalized, force=force)
        session.add(last_alert)

    if audit_enabled:
        audit = AlertAudit(
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            user_id=action_callee,
            action=action_type.value,
            description=action_description,
        )
        session.add(audit)

    session.commit()
    if last_alert is not None:
        session.refresh(last_alert)
    return last_alert


def enrich_entity(
    tenant_id,
    fingerprint,
    enrichments,
    action_type: ActionType,
    action_callee: str,
    action_description: str,
    session=None,
    force=False,
    audit_enabled=True,
    strict=True,
    entity_type: str = "alert",
):
    with existed_or_new_session(session) as session:
        return _enrich_entity(
            session,
            tenant_id,
            fingerprint,
            enrichments,
            action_type,
            action_callee,
            action_description,
            force=force,
            audit_enabled=audit_enabled,
            strict=strict,
            entity_type=entity_type,
        )

@retry(exceptions=(Exception,), tries=3, delay=0.1, backoff=2)
def get_enrichment_with_session(session, tenant_id, fingerprint, refresh=False):
    try:
        alert_enrichment = session.exec(
            select(AlertEnrichment)
            .where(AlertEnrichment.tenant_id == tenant_id)
            .where(AlertEnrichment.alert_fingerprint == fingerprint)
        ).first()

        if refresh and alert_enrichment:
            try:
                session.refresh(alert_enrichment)
            except Exception:
                logger.exception(
                    "Failed to refresh enrichment",
                    extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
                )
                session.rollback()
                raise  # This will trigger a retry

        return alert_enrichment

    except Exception as e:
        if "PendingRollbackError" in str(e):
            logger.warning(
                "Session has pending rollback, attempting recovery",
                extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
            )
            session.rollback()
            raise  # This will trigger a retry
        else:
            logger.exception(
                "Unexpected error getting enrichment",
                extra={"tenant_id": tenant_id, "fingerprint": fingerprint},
            )
            raise  # This will trigger a retry


def get_started_at_for_alerts(
    tenant_id,
    fingerprints: list[str],
    session: Optional[Session] = None,
) -> dict[str, datetime]:
    with existed_or_new_session(session) as session:
        statement = select(LastAlert.fingerprint, LastAlert.first_timestamp).where(
            LastAlert.tenant_id == tenant_id,
            LastAlert.fingerprint.in_(fingerprints),
        )
        result = session.exec(statement).all()
        return {row[0]: row[1] for row in result}

def get_alerts_by_fingerprint(
    tenant_id: str,
    fingerprint: str,
    limit=1,
    status=None,
) -> List[Alert]:
    """
    Get all alerts for a given fingerprint.

    Alert enrichment state now lives on LastAlert typed columns, so no
    alertenrichment eager-load is needed here.

    Args:
        tenant_id (str): The tenant_id to filter the alerts by.
        fingerprint (str): The fingerprint to filter the alerts by.

    Returns:
        List[Alert]: A list of Alert objects.
    """
    with Session(engine) as session:
        # Create the query using select() instead of session.query()
        query = select(Alert)

        # Filter by tenant_id
        query = query.where(Alert.tenant_id == tenant_id)

        query = query.where(Alert.fingerprint == fingerprint)

        query = query.order_by(Alert.timestamp.desc())

        if status:
            query = query.where(
                Alert.status == status
            )

        if limit:
            query = query.limit(limit)

        # Execute the query using exec() instead of execute()
        alerts = session.exec(query).all()

        return alerts

def get_db_presets(tenant_id: str) -> List[Preset]:
    with Session(engine) as session:
        presets = (
            session.exec(select(Preset).where(Preset.tenant_id == tenant_id))
            .unique()
            .all()
        )
    return presets


def get_all_presets_dtos(tenant_id: str) -> List[PresetDto]:
    presets = get_db_presets(tenant_id)
    static_presets_dtos = list(STATIC_PRESETS.values())
    return [PresetDto(**preset.to_dict()) for preset in presets] + static_presets_dtos


def enrich_alerts_with_incidents(
    tenant_id: str, alerts: List[Alert], session: Optional[Session] = None
):
    with existed_or_new_session(session) as session:
        alert_incidents = session.exec(
            select(LastAlertToIncident.fingerprint, Incident)
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                    LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                    LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                ),
            )
            .join(Incident, LastAlertToIncident.incident_id == Incident.id)
            .where(
                LastAlert.tenant_id == tenant_id,
                LastAlertToIncident.fingerprint.in_(
                    [alert.fingerprint for alert in alerts]
                ),
            )
        ).all()

        incidents_per_alert = defaultdict(list)
        for fingerprint, incident in alert_incidents:
            incidents_per_alert[fingerprint].append(incident)

        for alert in alerts:
            alert._incidents = incidents_per_alert[alert.fingerprint]

        return alerts


def get_provider_by_name(tenant_id: str, provider_name: str) -> Provider:
    with Session(engine) as session:
        provider = session.exec(
            select(Provider)
            .where(Provider.tenant_id == tenant_id)
            .where(Provider.name == provider_name)
        ).first()
    return provider

def get_alerts_fields(tenant_id: str) -> List[AlertField]:
    with Session(engine) as session:
        fields = session.exec(
            select(AlertField).where(AlertField.tenant_id == tenant_id)
        ).all()
    return fields

def create_deduplication_event(
    tenant_id, deduplication_rule_id, deduplication_type, provider_id, provider_type
):
    logger.debug(
        "Adding deduplication event",
        extra={
            "deduplication_rule_id": deduplication_rule_id,
            "deduplication_type": deduplication_type,
            "provider_id": provider_id,
            "provider_type": provider_type,
            "tenant_id": tenant_id,
        },
    )
    if isinstance(deduplication_rule_id, str):
        deduplication_rule_id = __convert_to_uuid(deduplication_rule_id)
        if not deduplication_rule_id:
            logger.debug(
                "Deduplication rule id is not a valid uuid",
                extra={
                    "deduplication_rule_id": deduplication_rule_id,
                    "tenant_id": tenant_id,
                },
            )
            return False
    with Session(engine) as session:
        deduplication_event = AlertDeduplicationEvent(
            tenant_id=tenant_id,
            deduplication_rule_id=deduplication_rule_id,
            deduplication_type=deduplication_type,
            provider_id=provider_id,
            provider_type=provider_type,
            timestamp=datetime.now(tz=timezone.utc),
            date_hour=datetime.now(tz=timezone.utc).replace(
                minute=0, second=0, microsecond=0
            ),
        )
        session.add(deduplication_event)
        session.commit()
        logger.debug(
            "Deduplication event added",
            extra={
                "deduplication_event_id": deduplication_event.id,
                "tenant_id": tenant_id,
            },
        )


def get_all_deduplication_stats(tenant_id):
    with Session(engine) as session:
        # Query to get all-time deduplication stats
        all_time_query = (
            select(
                AlertDeduplicationEvent.deduplication_rule_id,
                AlertDeduplicationEvent.provider_id,
                AlertDeduplicationEvent.provider_type,
                AlertDeduplicationEvent.deduplication_type,
                func.count(AlertDeduplicationEvent.id).label("dedup_count"),
            )
            .where(AlertDeduplicationEvent.tenant_id == tenant_id)
            .group_by(
                AlertDeduplicationEvent.deduplication_rule_id,
                AlertDeduplicationEvent.provider_id,
                AlertDeduplicationEvent.provider_type,
                AlertDeduplicationEvent.deduplication_type,
            )
        )

        all_time_results = session.exec(all_time_query).all()

        # Query to get alerts distribution in the last 24 hours
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        alerts_last_24_hours_query = (
            select(
                AlertDeduplicationEvent.deduplication_rule_id,
                AlertDeduplicationEvent.provider_id,
                AlertDeduplicationEvent.provider_type,
                AlertDeduplicationEvent.date_hour,
                func.count(AlertDeduplicationEvent.id).label("hourly_count"),
            )
            .where(AlertDeduplicationEvent.tenant_id == tenant_id)
            .where(AlertDeduplicationEvent.date_hour >= twenty_four_hours_ago)
            .group_by(
                AlertDeduplicationEvent.deduplication_rule_id,
                AlertDeduplicationEvent.provider_id,
                AlertDeduplicationEvent.provider_type,
                AlertDeduplicationEvent.date_hour,
            )
        )

        alerts_last_24_hours_results = session.exec(alerts_last_24_hours_query).all()

        # Create a dictionary with deduplication stats for each rule
        stats = {}
        current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        for result in all_time_results:
            provider_id = result.provider_id
            provider_type = result.provider_type
            dedup_count = result.dedup_count
            dedup_type = result.deduplication_type

            # alerts without provider_id and provider_type are considered as "keep"
            if not provider_type:
                provider_type = "keep"

            key = str(result.deduplication_rule_id)
            if key not in stats:
                # initialize the stats for the deduplication rule
                stats[key] = {
                    "full_dedup_count": 0,
                    "partial_dedup_count": 0,
                    "none_dedup_count": 0,
                    "alerts_last_24_hours": [
                        {"hour": (current_hour - timedelta(hours=i)).hour, "number": 0}
                        for i in range(0, 24)
                    ],
                    "provider_id": provider_id,
                    "provider_type": provider_type,
                }

            if dedup_type == "full":
                stats[key]["full_dedup_count"] += dedup_count
            elif dedup_type == "partial":
                stats[key]["partial_dedup_count"] += dedup_count
            elif dedup_type == "none":
                stats[key]["none_dedup_count"] += dedup_count

        # Add alerts distribution from the last 24 hours
        for result in alerts_last_24_hours_results:
            provider_id = result.provider_id
            provider_type = result.provider_type
            date_hour = result.date_hour
            hourly_count = result.hourly_count
            key = str(result.deduplication_rule_id)

            if not provider_type:
                provider_type = "keep"

            if key in stats:
                hours_ago = int((current_hour - date_hour).total_seconds() / 3600)
                if 0 <= hours_ago < 24:
                    stats[key]["alerts_last_24_hours"][23 - hours_ago]["number"] = (
                        hourly_count
                    )

    return stats

def bulk_upsert_alert_fields(
    tenant_id: str,
    fields: List[str],
    provider_id: str,
    provider_type: str,
    session: Optional[Session] = None,
    max_retries=3,
):
    with existed_or_new_session(session) as session:
        for attempt in range(max_retries):
            try:
                # Prepare the data for bulk insert
                data = [
                    {
                        "tenant_id": tenant_id,
                        "field_name": field,
                        "provider_id": provider_id,
                        "provider_type": provider_type,
                    }
                    for field in fields
                ]

                if engine.dialect.name == "postgresql":
                    stmt = pg_insert(AlertField).values(data)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=[
                            "tenant_id",
                            "field_name",
                        ],  # Unique constraint columns
                        set_={
                            "provider_id": stmt.excluded.provider_id,
                            "provider_type": stmt.excluded.provider_type,
                        },
                    )
                elif engine.dialect.name == "mysql":
                    stmt = mysql_insert(AlertField).values(data)
                    stmt = stmt.on_duplicate_key_update(
                        provider_id=stmt.inserted.provider_id,
                        provider_type=stmt.inserted.provider_type,
                    )
                elif engine.dialect.name == "sqlite":
                    stmt = sqlite_insert(AlertField).values(data)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=[
                            "tenant_id",
                            "field_name",
                        ],  # Unique constraint columns
                        set_={
                            "provider_id": stmt.excluded.provider_id,
                            "provider_type": stmt.excluded.provider_type,
                        },
                    )
                elif engine.dialect.name == "mssql":
                    # SQL Server requires a raw query with a MERGE statement
                    values = ", ".join(
                        f"('{tenant_id}', '{field}', '{provider_id}', '{provider_type}')"
                        for field in fields
                    )

                    merge_query = text(
                        f"""
                        MERGE INTO AlertField AS target
                        USING (VALUES {values}) AS source (tenant_id, field_name, provider_id, provider_type)
                        ON target.tenant_id = source.tenant_id AND target.field_name = source.field_name
                        WHEN MATCHED THEN
                            UPDATE SET provider_id = source.provider_id, provider_type = source.provider_type
                        WHEN NOT MATCHED THEN
                            INSERT (tenant_id, field_name, provider_id, provider_type)
                            VALUES (source.tenant_id, source.field_name, source.provider_id, source.provider_type)
                    """
                    )

                    session.execute(merge_query)
                else:
                    raise NotImplementedError(
                        f"Upsert not supported for {engine.dialect.name}"
                    )

                # Execute the statement
                if engine.dialect.name != "mssql":  # Already executed for SQL Server
                    session.execute(stmt)
                session.commit()

                break

            except OperationalError as e:
                # Handle any potential race conditions
                session.rollback()
                if "Deadlock found" in str(e):
                    logger.info(
                        f"Deadlock found during bulk_upsert_alert_fields `{e}`, retry #{attempt}"
                    )
                    if attempt >= max_retries:
                        raise e
                    continue
                else:
                    raise e


def get_last_alert_by_fingerprint(
    tenant_id: str,
    fingerprint: str,
    session: Optional[Session] = None,
    for_update: bool = False,
) -> Optional[LastAlert]:
    with existed_or_new_session(session) as session:
        query = select(LastAlert).where(
            and_(
                LastAlert.tenant_id == tenant_id,
                LastAlert.fingerprint == fingerprint,
            )
        )
        if for_update:
            query = query.with_for_update()
        return session.exec(query).first()


def get_last_alert_hashes_by_fingerprints(
    tenant_id, fingerprints: list[str]
) -> dict[str, str | None]:
    # get the last alert hashes for a list of fingerprints
    # to check deduplication
    with Session(engine) as session:
        query = (
            select(LastAlert.fingerprint, LastAlert.alert_hash)
            .where(LastAlert.tenant_id == tenant_id)
            .where(LastAlert.fingerprint.in_(fingerprints))
        )

        results = session.exec(query).all()

        # Create a dictionary from the results
        alert_hash_dict = {
            fingerprint: alert_hash
            for fingerprint, alert_hash in results
            if alert_hash is not None
        }
        return alert_hash_dict



def set_last_alert(
    tenant_id: str,
    alert: Alert,
    session: Optional[Session] = None,
    max_retries=3,
    tracking: Optional[dict] = None,
) -> None:
    """Create or repoint the LastAlert row for a fingerprint.

    `tracking` carries the system tracking columns relocated from
    `alert` (last_received, firing_counter, unresolved_counter, started_at,
    firing_start_time, firing_start_time_since_last_resolved). When None those
    columns are left unchanged. Status/dismiss clearing on re-fire/resolve also
    happens here (replacing the old dispose/make-permanent enrichment dance).
    """
    fingerprint = alert.fingerprint
    logger.info(f"Setting last alert for `{fingerprint}`")
    with existed_or_new_session(session) as session:
        for attempt in range(1, max_retries + 1):
            logger.info(
                f"Attempt {attempt} to set last alert for `{fingerprint}`",
                extra={
                    "alert_id": alert.id,
                    "tenant_id": tenant_id,
                    "fingerprint": fingerprint,
                },
            )
            try:
                last_alert = get_last_alert_by_fingerprint(
                    tenant_id, fingerprint, session, for_update=True
                )

                # To prevent rare, but possible race condition
                # For example if older alert failed to process
                # and retried after new one
                if last_alert and last_alert.timestamp.replace(
                    tzinfo=timezone.utc
                ) < alert.timestamp.replace(tzinfo=timezone.utc):
                    logger.info(
                        f"Update last alert for `{fingerprint}`: {last_alert.alert_id} -> {alert.id}",
                        extra={
                            "alert_id": alert.id,
                            "tenant_id": tenant_id,
                            "fingerprint": fingerprint,
                        },
                    )
                    last_alert.timestamp = alert.timestamp
                    last_alert.alert_id = alert.id
                    last_alert.alert_hash = alert.alert_hash

                    # Write relocated tracking columns when provided.
                    # Strict allow-list — never let `tracking` clobber user-
                    # enrichment columns (status/assignee/note/dismiss_*) which
                    # the enrich path owns.
                    if tracking is not None:
                        for _col, _val in tracking.items():
                            if _col not in LASTALERT_TRACKING_COLUMNS:
                                logger.warning(
                                    "set_last_alert.ignored_tracking_key",
                                    extra={
                                        "tenant_id": tenant_id,
                                        "fingerprint": fingerprint,
                                        "key": _col,
                                    },
                                )
                                continue
                            setattr(last_alert, _col, _val)

                    # Status/dismiss clearing on this occurrence's
                    # provider status (replaces dispose/make-permanent).
                    resolved = alert.status == AlertStatus.RESOLVED.value
                    if not resolved:
                        if last_alert.status_disposable:
                            last_alert.status = None
                            last_alert.status_disposable = False
                    else:
                        if last_alert.dismiss_mode not in (
                            "permanent",
                            "dismiss_until",
                        ):
                            last_alert.status = None
                            last_alert.dismiss_mode = None
                            last_alert.dismissed_until = None

                    session.add(last_alert)

                elif not last_alert:
                    logger.info(f"No last alert for `{fingerprint}`, creating new")
                    new_last_alert = LastAlert(
                        tenant_id=tenant_id,
                        fingerprint=alert.fingerprint,
                        timestamp=alert.timestamp,
                        first_timestamp=alert.timestamp,
                        alert_id=alert.id,
                        alert_hash=alert.alert_hash,
                    )
                    # Write relocated tracking columns when provided.
                    # Strict allow-list — see comment above.
                    if tracking is not None:
                        for _col, _val in tracking.items():
                            if _col not in LASTALERT_TRACKING_COLUMNS:
                                logger.warning(
                                    "set_last_alert.ignored_tracking_key",
                                    extra={
                                        "tenant_id": tenant_id,
                                        "fingerprint": fingerprint,
                                        "key": _col,
                                    },
                                )
                                continue
                            setattr(new_last_alert, _col, _val)
                    session.add(new_last_alert)

                session.commit()
            except IntegrityError as ex:
                session.rollback()
                logger.warning(
                    f"Integrity error while updating lastalert for `{fingerprint}`, retry #{attempt}",
                    extra={
                        "alert_id": alert.id,
                        "tenant_id": tenant_id,
                        "fingerprint": fingerprint,
                        "error": str(ex),
                    },
                )
                if attempt == max_retries:
                    raise
                # Small delay before retry to avoid hammering the database
                time.sleep(0.1 * attempt)
                continue
            except OperationalError as ex:
                session.rollback()
                message = ex.args[0] if ex.args else ""
                if "no such savepoint" in message:
                    logger.info(
                        f"No such savepoint while updating lastalert for `{fingerprint}`, retry #{attempt}"
                    )
                elif "Deadlock found" in message:
                    logger.info(
                        f"Deadlock found while updating lastalert for `{fingerprint}`, retry #{attempt}"
                    )
                else:
                    logger.exception(
                        f"Operational error while updating lastalert for `{fingerprint}`",
                        extra={
                            "alert_id": alert.id,
                            "tenant_id": tenant_id,
                            "fingerprint": fingerprint,
                        },
                    )
                    raise

                if attempt == max_retries:
                    raise
                # Small delay before retry to avoid hammering the database
                time.sleep(0.1 * attempt)
                continue
            except InternalError as ex:
                session.rollback()
                logger.exception(
                    f"No active sql transaction while updating lastalert for `{fingerprint}`, retry #{attempt}",
                    extra={
                        "alert_id": alert.id,
                        "tenant_id": tenant_id,
                        "fingerprint": fingerprint,
                    },
                )
                if attempt == max_retries:
                    raise ex
                # Small delay before retry to avoid hammering the database
                time.sleep(0.1 * attempt)
                continue
            else:
                logger.debug(
                    f"Successfully updated lastalert for `{fingerprint}`",
                    extra={
                        "alert_id": alert.id,
                        "tenant_id": tenant_id,
                        "fingerprint": fingerprint,
                    },
                )
                break
        else:
            # REVIEW-TODO: defensive belt — currently unreachable because every
            # exception branch above re-raises on `attempt == max_retries`. Kept
            # as a guard against future refactors silently dropping the re-raise.
            raise RuntimeError(
                f"Failed to set last alert for `{fingerprint}` after {max_retries} attempts"
            )


def enrich_incidents_with_enrichments(
    tenant_id: str,
    incidents: List[Incident],
    session: Optional[Session] = None,
) -> List[Incident]:
    """Enrich incidents with their enrichment data."""
    if not incidents:
        return incidents

    with existed_or_new_session(session) as session:
        # Get all enrichments for these incidents in one query
        enrichments = session.exec(
            select(AlertEnrichment).where(
                AlertEnrichment.tenant_id == tenant_id,
                AlertEnrichment.alert_fingerprint.in_(
                    [str(incident.id) for incident in incidents]
                ),
            )
        ).all()

        # Create a mapping of incident_id to enrichment
        enrichments_map = {
            enrichment.alert_fingerprint: enrichment.enrichments
            for enrichment in enrichments
        }

        # Add enrichments to each incident
        for incident in incidents:
            incident._enrichments = enrichments_map.get(str(incident.id), {})

        return incidents

def get_incident_alerts_and_links_by_incident_id(
    tenant_id: str,
    incident_id: UUID | str,
    limit: Optional[int] = None,
    offset: Optional[int] = 0,
    session: Optional[Session] = None,
    include_unlinked: bool = False,
) -> tuple[List[tuple[Alert, LastAlertToIncident]], int]:
    with existed_or_new_session(session) as session:
        query = (
            session.query(
                Alert,
                LastAlertToIncident,
            )
            .select_from(LastAlertToIncident)
            .join(
                LastAlert,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident_id,
            )
            .order_by(col(LastAlert.timestamp).desc())
        )
        if not include_unlinked:
            query = query.filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
            )

    total_count = query.count()

    if limit is not None and offset is not None:
        query = query.limit(limit).offset(offset)

    return query.all(), total_count


def get_incident_alerts_by_incident_id(*args, **kwargs) -> tuple[List[Alert], int]:
    """
    Unpacking (List[(Alert, LastAlertToIncident)], int) to (List[Alert], int).
    """
    alerts_and_links, total_alerts = get_incident_alerts_and_links_by_incident_id(
        *args, **kwargs
    )
    alerts = [alert_and_link[0] for alert_and_link in alerts_and_links]
    return alerts, total_alerts


def get_tenants_configurations(only_with_config=False) -> dict:
    with Session(engine) as session:
        try:
            tenants = session.exec(select(Tenant)).all()
        # except column configuration does not exist (new column added)
        except OperationalError as e:
            if "Unknown column" in str(e):
                logger.warning("Column configuration does not exist in the database")
                return {}
            else:
                logger.exception("Failed to get tenants configurations")
                return {}

    tenants_configurations = {}
    for tenant in tenants:
        if only_with_config and not tenant.configuration:
            continue
        tenants_configurations[tenant.id] = tenant.configuration or {}

    return tenants_configurations

class _FingerprintEnrichments:
    """Lightweight read-only view exposing the same `.alert_fingerprint` /
    `.enrichments` shape that consumers expect, but sourced from LastAlert
    typed columns."""

    __slots__ = ("alert_fingerprint", "enrichments")

    def __init__(self, alert_fingerprint: str, enrichments: dict):
        self.alert_fingerprint = alert_fingerprint
        self.enrichments = enrichments


def get_enrichments(
    tenant_id: int, fingerprints: List[str]
) -> List[Optional["_FingerprintEnrichments"]]:
    """
    Get the user-enrichment state for a list of fingerprints from LastAlert
    typed columns.

    :param tenant_id: The tenant ID to filter the alerts by.
    :param fingerprints: A list of fingerprints to get the enrichments for.
    :return: A list of objects exposing `.alert_fingerprint` and `.enrichments`.
    """
    with Session(engine) as session:
        rows = session.exec(
            select(LastAlert)
            .where(LastAlert.tenant_id == tenant_id)
            .where(LastAlert.fingerprint.in_(fingerprints))
        ).all()
    return [
        _FingerprintEnrichments(la.fingerprint, last_alert_enrichments_dict(la))
        for la in rows
    ]


def _batch_enrich_incident_alertenrichment(
    session,
    tenant_id,
    fingerprints,
    enrichments,
    action_type: ActionType,
    action_callee: str,
    action_description: str,
    audit_enabled=True,
):
    """
    Legacy AlertEnrichment batch upsert for INCIDENT enrichment.

    Faithful recovery of the pre-Phase-2 batch_enrich body: merges into the
    AlertEnrichment JSONB, preserves notes, drops None-valued keys, allows
    arbitrary keys, no D1 no-op, no dismissed translation. See
    _enrich_incident_alertenrichment for the single-entity equivalent.
    """
    # Get all existing enrichments in one query
    existing_enrichments = {
        e.alert_fingerprint: e
        for e in session.exec(
            select(AlertEnrichment)
            .where(AlertEnrichment.tenant_id == tenant_id)
            .where(AlertEnrichment.alert_fingerprint.in_(fingerprints))
        ).all()
    }

    to_update = {}
    to_create = []
    audit_entries = []

    for fingerprint in fingerprints:
        existing = existing_enrichments.get(fingerprint)

        if existing:
            merged_enrichments = {**existing.enrichments, **enrichments}
            # Preserve existing note if incoming note is empty/None/not provided
            incoming_note = enrichments.get("note")
            if not incoming_note or (
                isinstance(incoming_note, str) and not incoming_note.strip()
            ):
                existing_note = existing.enrichments.get("note")
                if existing_note:
                    merged_enrichments["note"] = existing_note

            # Remove keys with None values (revert to original event value)
            for key, value in enrichments.items():
                if value is None and key in merged_enrichments:
                    del merged_enrichments[key]

            to_update[existing.id] = merged_enrichments
        else:
            to_create.append(
                AlertEnrichment(
                    tenant_id=tenant_id,
                    alert_fingerprint=fingerprint,
                    enrichments=enrichments,
                )
            )

        if audit_enabled:
            audit_entries.append(
                AlertAudit(
                    tenant_id=tenant_id,
                    fingerprint=fingerprint,
                    user_id=action_callee,
                    action=action_type.value,
                    description=action_description,
                )
            )

    if to_update:
        for enrichment_id, merged_enrichments in to_update.items():
            stmt = (
                update(AlertEnrichment)
                .where(AlertEnrichment.id == enrichment_id)
                .values(enrichments=merged_enrichments)
            )
            session.execute(stmt)

    if to_create:
        session.add_all(to_create)

    if audit_entries:
        session.add_all(audit_entries)

    session.commit()

    # No callers consume the return value; the legacy implementation re-queried
    # all rows here but the result was always discarded. Drop the round-trip.
    return None


def batch_enrich(
    tenant_id,
    fingerprints,
    enrichments,
    action_type: ActionType,
    action_callee: str,
    action_description: str,
    session=None,
    audit_enabled=True,
    strict=True,
    entity_type: str = "alert",
):
    """
    Batch enrich multiple entities with the same enrichments in a single transaction.

    ALERT (entity_type=="alert"): writes typed LastAlert columns.
    INCIDENT (entity_type=="incident"): legacy AlertEnrichment JSONB upsert until
    Phase 3 (see _batch_enrich_incident_alertenrichment).

    Args:
        tenant_id (str): The tenant ID to filter the alert enrichments by.
        fingerprints (List[str]): List of alert fingerprints to enrich.
        enrichments (dict): The enrichments to add to all alerts.
        action_type (ActionType): The type of action being performed.
        action_callee (str): The ID of the user performing the action.
        action_description (str): Description of the action.
        session (Session, optional): Database session to use.
        force (bool, optional): Whether to override existing enrichments. Defaults to False.
        audit_enabled (bool, optional): Whether to create audit entries. Defaults to True.

    Returns:
        List[AlertEnrichment]: List of enriched alert objects.
    """
    if entity_type == "incident":
        with existed_or_new_session(session) as session:
            return _batch_enrich_incident_alertenrichment(
                session,
                tenant_id,
                fingerprints,
                enrichments,
                action_type,
                action_callee,
                action_description,
                audit_enabled=audit_enabled,
            )

    # Write typed LastAlert columns. Translate legacy keys / handle
    # unknown keys once for the whole batch (same enrichments for all fps).
    normalized = normalize_enrichments(enrichments, strict=strict)

    with existed_or_new_session(session) as session:
        existing_last_alerts = {
            la.fingerprint: la
            for la in session.exec(
                select(LastAlert)
                .where(LastAlert.tenant_id == tenant_id)
                .where(LastAlert.fingerprint.in_(fingerprints))
                .with_for_update()
            ).all()
        }

        audit_entries = []
        updated = []

        for fingerprint in fingerprints:
            last_alert = existing_last_alerts.get(fingerprint)
            if last_alert is None:
                # D1: enrich-before-first-alert -> no column write, still audit.
                logger.warning(
                    "enrichment.no_lastalert",
                    extra={
                        "tenant_id": tenant_id,
                        "fingerprint": fingerprint,
                        "enrichments": list(normalized.keys()),
                    },
                )
            else:
                _apply_enrichments_to_last_alert(last_alert, normalized)
                session.add(last_alert)
                updated.append(last_alert)

            if audit_enabled:
                audit_entries.append(
                    AlertAudit(
                        tenant_id=tenant_id,
                        fingerprint=fingerprint,
                        user_id=action_callee,
                        action=action_type.value,
                        description=action_description,
                    )
                )

        if audit_entries:
            session.add_all(audit_entries)

        session.commit()

        return updated

def get_alert_by_event_id(
    tenant_id: str, event_id: str, session: Optional[Session] = None
) -> Alert:
    with existed_or_new_session(session) as session:
        query = (
            select(Alert)
            .filter(Alert.tenant_id == tenant_id)
            .filter(Alert.id == uuid.UUID(event_id))
        )
        alert = session.exec(query).first()
    return alert


def get_extraction_rule_by_id(
    tenant_id: str, rule_id: str, session: Optional[Session] = None
) -> ExtractionRule | None:
    with existed_or_new_session(session) as session:
        query = select(ExtractionRule).where(
            ExtractionRule.tenant_id == tenant_id, ExtractionRule.id == rule_id
        )
        return session.exec(query).first()


def get_incidents_by_alert_fingerprint(
    tenant_id: str, fingerprint: str, session: Optional[Session] = None
) -> List[Incident]:
    with existed_or_new_session(session) as session:
        alert_incidents = session.exec(
            select(Incident)
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                    LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                    LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                ),
            )
            .join(Incident, LastAlertToIncident.incident_id == Incident.id)
            .where(
                LastAlert.tenant_id == tenant_id,
                LastAlertToIncident.fingerprint == fingerprint,
            )
        ).all()
        return alert_incidents


def get_mapping_rule_by_id(
    tenant_id: str, rule_id: str, session: Optional[Session] = None
) -> MappingRule | None:
    with existed_or_new_session(session) as session:
        query = select(MappingRule).where(
            MappingRule.tenant_id == tenant_id, MappingRule.id == rule_id
        )
        return session.exec(query).first()


def get_topology_data_by_dynamic_matcher(
    tenant_id: str, matchers_value: dict[str, str]
) -> TopologyService | None:
    with Session(engine) as session:
        query = select(TopologyService).where(TopologyService.tenant_id == tenant_id)
        for matcher in matchers_value:
            query = query.where(
                getattr(TopologyService, matcher) == matchers_value[matcher]
            )
        # Add joinedload for applications to avoid detached instance error
        query = query.options(joinedload(TopologyService.applications))
        service = session.exec(query).first()
        return service


def is_all_alerts_resolved(
    fingerprints: Optional[List[str]] = None,
    incident: Optional[Incident] = None,
    session: Optional[Session] = None,
):
    return is_all_alerts_in_status(
        fingerprints, incident, AlertStatus.RESOLVED, session
    )

def assign_alert_to_incident(
    fingerprint: str,
    incident: Incident,
    tenant_id: str,
    session: Optional[Session] = None,
):
    return add_alerts_to_incident(tenant_id, incident, [fingerprint], session=session)


def get_rules(tenant_id, ids=None) -> list[Rule]:
    with Session(engine) as session:
        # Start building the query
        query = (
            select(Rule)
            .where(Rule.tenant_id == tenant_id)
            .where(Rule.is_deleted.is_(False))
        )

        # Apply additional filters if ids are provided
        if ids is not None:
            query = query.where(Rule.id.in_(ids))

        # Execute the query
        rules = session.exec(query).all()
        return rules


def is_all_alerts_in_status(
    fingerprints: Optional[List[str]] = None,
    incident: Optional[Incident] = None,
    status: AlertStatus = AlertStatus.RESOLVED,
    session: Optional[Session] = None,
):
    if incident and incident.alerts_count == 0:
        return False

    with existed_or_new_session(session) as session:
        # Enriched status override lives on LastAlert.status
        enriched_status_field = LastAlert.status
        status_field = Alert.status

        subquery = (
            select(
                enriched_status_field.label("enriched_status"),
                status_field.label("status"),
            )
            .select_from(LastAlert)
            .join(Alert, LastAlert.alert_id == Alert.id)
        )

        if fingerprints:
            subquery = subquery.where(LastAlert.fingerprint.in_(fingerprints))

        if incident:
            subquery = subquery.join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                    LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                ),
            ).where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident.id,
            )

        subquery = subquery.subquery()

        not_in_status_exists = session.query(
            exists(
                select(
                    subquery.c.enriched_status,
                    subquery.c.status,
                )
                .select_from(subquery)
                .where(
                    or_(
                        subquery.c.enriched_status != status.value,
                        and_(
                            subquery.c.enriched_status.is_(None),
                            subquery.c.status != status.value,
                        ),
                    )
                )
            )
        ).scalar()

        return not not_in_status_exists


def add_audit(
    tenant_id: str,
    fingerprint: str,
    user_id: str,
    action: ActionType,
    description: str,
    session: Session = None,
    commit: bool = True,
) -> AlertAudit:
    with existed_or_new_session(session) as session:
        audit = AlertAudit(
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            user_id=user_id,
            action=action.value,
            description=description,
        )
        session.add(audit)
        if commit:
            session.commit()
            session.refresh(audit)
    return audit


def retry_on_db_error(f):
    @retry(
        exceptions=(OperationalError, IntegrityError, StaleDataError),
        tries=3,
        delay=0.1,
        backoff=2,
        jitter=(0, 0.1),
        logger=logger,
    )
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (OperationalError, IntegrityError, StaleDataError) as e:
            if hasattr(e, "session") and not e.session.is_active:
                e.session.rollback()

            if "Deadlock found" in str(e):
                logger.warning(
                    "Deadlock detected, retrying transaction", extra={"error": str(e)}
                )
                raise  # retry will catch this
            else:
                logger.exception(
                    f"Error while executing transaction during {f.__name__}",
                )
            raise  # if it's not a deadlock, let it propagate

    return wrapper

@retry_on_db_error
def create_incident_for_grouping_rule(
    tenant_id,
    rule: Rule,
    rule_fingerprint,
    incident_name: str = None,
    past_incident: Optional[Incident] = None,
    assignee: str | None = None,
    session: Optional[Session] = None,
):
    with existed_or_new_session(session) as session:
        # Create and add a new incident if it doesn't exist
        incident = Incident(
            tenant_id=tenant_id,
            user_generated_name=incident_name or f"{rule.name}",
            rule_id=rule.id,
            rule_fingerprint=rule_fingerprint,
            is_predicted=True,
            is_candidate=rule.require_approve,
            is_visible=False,  # rule.create_on == CreateIncidentOn.ANY.value,
            incident_type=IncidentType.RULE.value,
            same_incident_in_the_past_id=past_incident.id if past_incident else None,
            resolve_on=rule.resolve_on,
            assignee=assignee,
        )
        session.add(incident)
        session.flush()
        if rule.incident_prefix:
            incident.user_generated_name = f"{rule.incident_prefix}-{incident.running_number} - {incident.user_generated_name}"
        session.commit()
        session.refresh(incident)
    return incident


def push_logs_to_db(log_entries):
    # avoid circular import
    from logging_utils import LOG_FORMAT, LOG_FORMAT_OPEN_TELEMETRY

    db_log_entries = []
    if LOG_FORMAT == LOG_FORMAT_OPEN_TELEMETRY:
        for log_entry in log_entries:
            try:
                try:
                    datetime.strptime(
                        log_entry["asctime"], "%Y-%m-%d %H:%M:%S,%f"
                    )
                except Exception:
                    pass

            except Exception:
                print("Failed to parse log entry - ", log_entry)

    else:
        for log_entry in log_entries:
            try:
                # WorkflowExecutionLog removed as it's undefined and not currently used correctly
                pass
            except Exception:
                print("Failed to parse log entry - ", log_entry)

    # Add the LogEntry instances to the database session
    with Session(engine) as session:
        session.add_all(db_log_entries)
        session.commit()


def get_incident_for_grouping_rule(
    tenant_id, rule, rule_fingerprint, session: Optional[Session] = None
) -> (Optional[Incident], bool):
    # checks if incident with the incident criteria exists, if not it creates it
    #   and then assign the alert to the incident
    with existed_or_new_session(session) as session:
        incident = session.exec(
            select(Incident)
            .where(Incident.tenant_id == tenant_id)
            .where(Incident.rule_id == rule.id)
            .where(Incident.rule_fingerprint == rule_fingerprint)
            .order_by(Incident.creation_time.desc())
        ).first()

        # if the last alert in the incident is older than the timeframe, create a new incident
        is_incident_expired = False
        if incident and incident.status in [
            IncidentStatus.RESOLVED.value,
            IncidentStatus.MERGED.value,
            IncidentStatus.DELETED.value,
        ]:
            is_incident_expired = True
        elif incident and incident.alerts_count > 0:
            enrich_incidents_with_alerts(tenant_id, [incident], session)
            is_incident_expired = max(
                alert.timestamp for alert in incident.alerts
            ) < datetime.utcnow() - timedelta(seconds=rule.timeframe)

        # if there is no incident with the rule_fingerprint, create it or existed is already expired
        if not incident:
            return None, None

    return incident, is_incident_expired



@retry_on_db_error
def add_alerts_to_incident(
    tenant_id: str,
    incident: Incident,
    fingerprints: List[str],
    is_created_by_ai: bool = False,
    session: Optional[Session] = None,
    override_count: bool = False,
    exclude_unlinked_alerts: bool = False,  # if True, do not add alerts to incident if they are manually unlinked
    max_retries=3,
) -> Optional[Incident]:
    logger.info(
        f"Adding alerts to incident {incident.id} in database, total {len(fingerprints)} alerts",
        extra={"tags": {"tenant_id": tenant_id, "incident_id": incident.id}},
    )

    with existed_or_new_session(session) as session:
        with session.no_autoflush:
            # Use a set for faster membership checks
            existing_fingerprints = set(
                session.exec(
                    select(LastAlert.fingerprint)
                    .join(
                        LastAlertToIncident,
                        and_(
                            LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                            LastAlertToIncident.fingerprint == LastAlert.fingerprint,
                        ),
                    )
                    .where(
                        LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                        LastAlertToIncident.tenant_id == tenant_id,
                        LastAlertToIncident.incident_id == incident.id,
                    )
                ).all()
            )

            new_fingerprints = {
                fingerprint
                for fingerprint in fingerprints
                if fingerprint not in existing_fingerprints
            }

            # filter out unlinked alerts
            if exclude_unlinked_alerts:
                unlinked_alerts = set(
                    session.exec(
                        select(LastAlert.fingerprint)
                        .join(
                            LastAlertToIncident,
                            and_(
                                LastAlertToIncident.tenant_id == LastAlert.tenant_id,
                                LastAlertToIncident.fingerprint
                                == LastAlert.fingerprint,
                            ),
                        )
                        .where(
                            LastAlertToIncident.deleted_at != NULL_FOR_DELETED_AT,
                            LastAlertToIncident.tenant_id == tenant_id,
                            LastAlertToIncident.incident_id == incident.id,
                        )
                    ).all()
                )
                new_fingerprints = new_fingerprints - unlinked_alerts

            if not new_fingerprints:
                return incident

            alert_to_incident_entries = [
                LastAlertToIncident(
                    fingerprint=str(fingerprint),  # it may sometime be UUID...
                    incident_id=incident.id,
                    tenant_id=tenant_id,
                    is_created_by_ai=is_created_by_ai,
                )
                for fingerprint in new_fingerprints
            ]

            for idx, entry in enumerate(alert_to_incident_entries):
                session.add(entry)
                if (idx + 1) % 100 == 0:
                    logger.info(
                        f"Added {idx + 1}/{len(alert_to_incident_entries)} alerts to incident {incident.id} in database",
                        extra={
                            "tags": {"tenant_id": tenant_id, "incident_id": incident.id}
                        },
                    )
                    session.flush()
            session.commit()

            alerts_data_for_incident = get_alerts_data_for_incident(
                tenant_id, new_fingerprints, session
            )

            new_sources = list(
                set(incident.sources if incident.sources else [])
                | set(alerts_data_for_incident["sources"])
            )
            new_affected_services = list(
                set(incident.affected_services if incident.affected_services else [])
                | set(alerts_data_for_incident["services"])
            )
            if not incident.forced_severity:
                # If incident has alerts already, use the max severity between existing and new alerts,
                # otherwise use the new alerts max severity
                new_severity = (
                    max(
                        incident.severity,
                        alerts_data_for_incident["max_severity"].order,
                    )
                    if incident.alerts_count
                    else alerts_data_for_incident["max_severity"].order
                )
            else:
                new_severity = incident.severity

            if not override_count:
                alerts_count = (
                    select(count(LastAlertToIncident.fingerprint)).where(
                        LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                        LastAlertToIncident.tenant_id == tenant_id,
                        LastAlertToIncident.incident_id == incident.id,
                    )
                ).scalar_subquery()
            else:
                alerts_count = alerts_data_for_incident["count"]

            # alert.last_received was relocated to lastalert; aggregate
            # over occurrence timestamps for the incident start/last-seen window.
            last_received_field = Alert.timestamp

            started_at, last_seen_at = session.exec(
                select(func.min(last_received_field), func.max(last_received_field))
                .join(
                    LastAlertToIncident,
                    and_(
                        LastAlertToIncident.tenant_id == Alert.tenant_id,
                        LastAlertToIncident.fingerprint == Alert.fingerprint,
                    ),
                )
                .where(
                    LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                    LastAlertToIncident.tenant_id == tenant_id,
                    LastAlertToIncident.incident_id == incident.id,
                )
            ).one()

            if isinstance(started_at, str):
                started_at = parse(started_at)

            if isinstance(last_seen_at, str):
                last_seen_at = parse(last_seen_at)

            incident_id = incident.id

            for attempt in range(max_retries):
                try:
                    session.exec(
                        update(Incident)
                        .where(
                            Incident.id == incident_id,
                            Incident.tenant_id == tenant_id,
                        )
                        .values(
                            alerts_count=alerts_count,
                            last_seen_time=last_seen_at,
                            start_time=started_at,
                            affected_services=new_affected_services,
                            severity=new_severity,
                            sources=new_sources,
                        )
                    )
                    session.commit()
                    break
                except StaleDataError as ex:
                    if "expected to update" in ex.args[0]:
                        logger.info(
                            f"Phantom read detected while updating incident `{incident_id}`, retry #{attempt}"
                        )
                        session.rollback()
                        continue
                    else:
                        raise
            session.add(incident)
            session.refresh(incident)

            return incident



def create_incident_from_dto(
    tenant_id: str,
    incident_dto: IncidentDtoIn | IncidentDto,
    generated_from_ai: bool = False,
    session: Optional[Session] = None,
) -> Optional[Incident]:
    """
    Creates an incident for a specified tenant based on the provided incident data transfer object (DTO).

    Args:
        tenant_id (str): The unique identifier of the tenant for whom the incident is being created.
        incident_dto (IncidentDtoIn | IncidentDto): The data transfer object containing incident details.
            Can be an instance of `IncidentDtoIn` or `IncidentDto`.
        generated_from_ai (bool, optional): Specifies whether the incident was generated by Keep's AI. Defaults to False.

    Returns:
        Optional[Incident]: The newly created `Incident` object if successful, otherwise `None`.
    """

    if issubclass(type(incident_dto), IncidentDto) and generated_from_ai:
        # NOTE: we do not use dto's alerts, alert count, start time etc
        #       because we want to re-use the BL of creating incidents
        #       where all of these are calculated inside add_alerts_to_incident
        incident_dict = {
            "user_summary": incident_dto.user_summary,
            "generated_summary": incident_dto.description,
            "user_generated_name": incident_dto.user_generated_name,
            "ai_generated_name": incident_dto.dict().get("name"),
            "assignee": incident_dto.assignee,
            "is_predicted": False,  # its not a prediction, but an AI generation
            "is_candidate": False,  # confirmed by the user :)
            "is_visible": True,  # confirmed by the user :)
            "incident_type": IncidentType.AI.value,
        }

    elif issubclass(type(incident_dto), IncidentDto):
        # we will reach this block when incident is pulled from a provider
        incident_dict = incident_dto.to_db_incident().dict()
        if "incident_type" not in incident_dict:
            incident_dict["incident_type"] = IncidentType.MANUAL.value
    else:
        # We'll reach this block when a user creates an incident
        incident_dict = incident_dto.dict()
        # Keep existing incident_type if present, default to MANUAL if not
        if "incident_type" not in incident_dict:
            incident_dict["incident_type"] = IncidentType.MANUAL.value

    if incident_dto.severity is not None:
        incident_dict["severity"] = incident_dto.severity.order

    return create_incident_from_dict(tenant_id, incident_dict, session)

def delete_incident_by_id(
    tenant_id: str, incident_id: UUID, session: Optional[Session] = None
) -> bool:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with existed_or_new_session(session) as session:
        incident = session.exec(
            select(Incident).filter(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
            )
        ).first()

        session.execute(
            update(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.id == incident.id,
            )
            .values({"status": IncidentStatus.DELETED.value})
        )

        session.commit()
        return True

def get_all_alerts_by_fingerprints(
    tenant_id: str, fingerprints: List[str], session: Optional[Session] = None
) -> List[Alert]:
    with existed_or_new_session(session) as session:
        query = (
            select(Alert)
            .filter(Alert.tenant_id == tenant_id)
            .filter(Alert.fingerprint.in_(fingerprints))
            .order_by(Alert.timestamp.desc())
        )
        return session.exec(query).all()

def get_incident_by_id(
    tenant_id: str,
    incident_id: str | UUID,
    with_alerts: bool = False,
    session: Optional[Session] = None,
) -> Optional[Incident]:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id, should_raise=True)
    with existed_or_new_session(session) as session:
        query = (
            session.query(
                Incident,
                AlertEnrichment,
            )
            .outerjoin(
                AlertEnrichment,
                and_(
                    Incident.tenant_id == AlertEnrichment.tenant_id,
                    cast(col(Incident.id), String)
                    == foreign(AlertEnrichment.alert_fingerprint),
                ),
            )
            .filter(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
            )
        )
        incident_with_enrichments = query.first()
        if incident_with_enrichments:
            incident, enrichments = incident_with_enrichments
            if with_alerts:
                enrich_incidents_with_alerts(
                    tenant_id,
                    [incident],
                    session,
                )
            if enrichments:
                incident.set_enrichments(enrichments.enrichments)
        else:
            incident = None

    return incident

# TODO: remove this function    
def get_incident_unique_fingerprint_count(
    tenant_id: str, incident_id: str | UUID
) -> int:
    with Session(engine) as session:
        return session.execute(
            select(func.count(1))
            .select_from(LastAlertToIncident)
            .where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident_id,
            )
        ).scalar()

def is_first_incident_alert_resolved(
    incident: Incident, session: Optional[Session] = None
) -> bool:
    return is_edge_incident_alert_resolved(incident, func.min, session)


def is_edge_incident_alert_resolved(
    incident: Incident, direction: Callable, session: Optional[Session] = None
) -> bool:
    if incident.alerts_count == 0:
        return False

    with existed_or_new_session(session) as session:
        # Enriched status override lives on LastAlert.status
        enriched_status_field = LastAlert.status
        status_field = Alert.status

        finerprint, enriched_status, status = session.exec(
            select(Alert.fingerprint, enriched_status_field, status_field)
            .select_from(Alert)
            .outerjoin(
                LastAlert,
                and_(
                    Alert.tenant_id == LastAlert.tenant_id,
                    Alert.fingerprint == LastAlert.fingerprint,
                ),
            )
            .join(
                LastAlertToIncident,
                and_(
                    LastAlertToIncident.tenant_id == Alert.tenant_id,
                    LastAlertToIncident.fingerprint == Alert.fingerprint,
                ),
            )
            .where(LastAlertToIncident.incident_id == incident.id)
            .group_by(Alert.fingerprint)
            .having(func.max(Alert.timestamp))
            .order_by(direction(Alert.timestamp))
        ).first()

        return enriched_status == AlertStatus.RESOLVED.value or (
            enriched_status is None and status == AlertStatus.RESOLVED.value
        )

def is_last_incident_alert_resolved(
    incident: Incident, session: Optional[Session] = None
) -> bool:
    return is_edge_incident_alert_resolved(incident, func.max, session)

def get_int_severity(input_severity: int | str) -> int:
    if isinstance(input_severity, int):
        return input_severity
    else:
        return IncidentSeverity(input_severity).order


def remove_alerts_to_incident_by_incident_id(
    tenant_id: str, incident_id: str | UUID, fingerprints: List[str]
) -> Optional[int]:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with Session(engine) as session:
        incident = session.exec(
            select(Incident).where(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
            )
        ).first()

        if not incident:
            return None

        # Removing alerts-to-incident relation for provided alerts_ids
        deleted = (
            session.query(LastAlertToIncident)
            .where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident.id,
                col(LastAlertToIncident.fingerprint).in_(fingerprints),
            )
            .update(
                {
                    "deleted_at": datetime.now(datetime.now().astimezone().tzinfo),
                }
            )
        )
        session.commit()

        # Getting aggregated data for incidents for alerts which just was removed
        alerts_data_for_incident = get_alerts_data_for_incident(
            tenant_id, fingerprints, session=session
        )

        service_field = Alert.service

        # checking if services of removed alerts are still presented in alerts
        # which still assigned with the incident
        existed_services_query = (
            select(func.distinct(service_field))
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident_id,
                service_field.in_(alerts_data_for_incident["services"]),
            )
        )
        services_existed = session.exec(existed_services_query)

        # checking if sources (providers) of removed alerts are still presented in alerts
        # which still assigned with the incident
        existed_sources_query = (
            select(col(Alert.provider_type).distinct())
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident_id,
                col(Alert.provider_type).in_(alerts_data_for_incident["sources"]),
            )
        )
        sources_existed = session.exec(existed_sources_query)

        severity_field = Alert.severity
        # checking if severities of removed alerts are still presented in alerts
        # which still assigned with the incident
        updated_severities_query = (
            select(severity_field)
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .filter(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.incident_id == incident_id,
            )
        )
        updated_severities_result = session.exec(updated_severities_query)
        updated_severities = [
            get_int_severity(severity) for severity in updated_severities_result
        ]

        # Making lists of services and sources to remove from the incident
        services_to_remove = [
            service
            for service in alerts_data_for_incident["services"]
            if service not in services_existed
        ]
        sources_to_remove = [
            source
            for source in alerts_data_for_incident["sources"]
            if source not in sources_existed
        ]

        # last_received was relocated from alert to lastalert.
        last_received_field = LastAlert.last_received

        started_at, last_seen_at = session.exec(
            select(func.min(last_received_field), func.max(last_received_field))
            .select_from(LastAlert)
            .join(
                LastAlertToIncident,
                and_(
                    LastAlert.tenant_id == LastAlertToIncident.tenant_id,
                    LastAlert.fingerprint == LastAlertToIncident.fingerprint,
                ),
            )
            .join(Alert, LastAlert.alert_id == Alert.id)
            .where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident.id,
            )
        ).one()

        # filtering removed entities from affected services and sources in the incident
        new_affected_services = [
            service
            for service in incident.affected_services
            if service not in services_to_remove
        ]
        new_sources = [
            source for source in incident.sources if source not in sources_to_remove
        ]

        if not incident.forced_severity:
            new_severity = (
                max(updated_severities)
                if updated_severities
                else IncidentSeverity.LOW.order
            )
        else:
            new_severity = incident.severity

        if isinstance(started_at, str):
            started_at = parse(started_at)

        if isinstance(last_seen_at, str):
            last_seen_at = parse(last_seen_at)

        alerts_count = (
            select(count(LastAlertToIncident.fingerprint)).where(
                LastAlertToIncident.deleted_at == NULL_FOR_DELETED_AT,
                LastAlertToIncident.tenant_id == tenant_id,
                LastAlertToIncident.incident_id == incident.id,
            )
        ).subquery()

        session.exec(
            update(Incident)
            .where(
                Incident.id == incident_id,
                Incident.tenant_id == tenant_id,
            )
            .values(
                alerts_count=alerts_count,
                last_seen_time=last_seen_at,
                start_time=started_at,
                affected_services=new_affected_services,
                severity=new_severity,
                sources=new_sources,
            )
        )
        session.commit()
        session.add(incident)
        session.refresh(incident)

        return deleted


@retry_on_db_error
def update_incident_from_dto_by_id(
    tenant_id: str,
    incident_id: str | UUID,
    updated_incident_dto: IncidentDtoIn | IncidentDto,
    generated_by_ai: bool = False,
) -> Optional[Incident]:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)

    with Session(engine) as session:
        incident = session.exec(
            select(Incident).where(
                Incident.tenant_id == tenant_id,
                Incident.id == incident_id,
            )
        ).first()

        if not incident:
            return None

        if issubclass(type(updated_incident_dto), IncidentDto):
            # We execute this when we update an incident received from the provider
            updated_data = updated_incident_dto.to_db_incident().model_dump()
        else:
            # When a user updates an Incident
            updated_data = updated_incident_dto.dict()

        for key, value in updated_data.items():
            # Update only if the new value is different from the current one
            if hasattr(incident, key) and getattr(incident, key) != value:
                if isinstance(value, Enum):
                    setattr(incident, key, value.value)
                else:
                    if value is not None:
                        setattr(incident, key, value)

        if "same_incident_in_the_past_id" in updated_data:
            incident.same_incident_in_the_past_id = updated_data[
                "same_incident_in_the_past_id"
            ]

        if generated_by_ai:
            incident.generated_summary = updated_incident_dto.user_summary
        else:
            incident.user_summary = updated_incident_dto.user_summary

        session.commit()
        session.refresh(incident)

        return incident
        
def update_incident_severity(
    tenant_id: str, incident_id: UUID, severity: IncidentSeverity
) -> Optional[Incident]:
    if isinstance(incident_id, str):
        incident_id = __convert_to_uuid(incident_id)
    with Session(engine) as session:
        incident = session.exec(
            select(Incident)
            .where(Incident.tenant_id == tenant_id)
            .where(Incident.id == incident_id)
        ).first()

        if not incident:
            logger.error(
                f"Incident not found for tenant {tenant_id} and incident {incident_id}",
                extra={"tenant_id": tenant_id},
            )
            return

        incident.severity = severity.order
        incident.forced_severity = True
        session.add(incident)
        session.commit()
        session.refresh(incident)

        return incident

def get_alerts_by_status(
    status: AlertStatus, session: Optional[Session] = None
) -> List[Alert]:
    with existed_or_new_session(session) as session:
        status_field = Alert.status
        query = select(Alert).where(status_field == status.value)
        return session.exec(query).all()

def get_maintenance_windows_started(
    session: Optional[Session] = None,
) -> List[MaintenanceWindowRule]:
    """
    It will return all windows started, i.e start_time < currentTime
    """
    with existed_or_new_session(session) as session:
        query = select(MaintenanceWindowRule).where(
            MaintenanceWindowRule.start_time <= datetime.now(tz=timezone.utc)
        )
        return session.exec(query).all()



def recover_prev_alert_status(alert: Alert, session: Optional[Session] = None):
    """
    It'll restore the previous status of the alert.
    """
    with existed_or_new_session(session) as session:
        try:
            status = alert.status
            prev_status = alert.previous_status
            alert.status = prev_status
            alert.previous_status = status
        except KeyError:
            logger.warning(f"Alert {alert.id} does not have previous status.")
        session.add(alert)
        session.commit()



def set_maintenance_windows_trace(
    alert: Alert,
    maintenance_w: MaintenanceWindowRule,
    session: Optional[Session] = None,
):
    mw_id = str(maintenance_w.id)
    if not alert.maintenance_windows_trace:
        alert.maintenance_windows_trace = []
    if mw_id in alert.maintenance_windows_trace:
        return
    with existed_or_new_session(session) as session:
        if mw_id not in alert.maintenance_windows_trace:
            alert.maintenance_windows_trace = alert.maintenance_windows_trace + [mw_id]
        flag_modified(alert, "maintenance_windows_trace")
        session.add(alert)
        session.commit()

def get_custom_deduplication_rule(tenant_id, provider_id, provider_type):
    with Session(engine) as session:
        rule = session.exec(
            select(AlertDeduplicationRule)
            .where(AlertDeduplicationRule.tenant_id == tenant_id)
            .where(AlertDeduplicationRule.provider_id == provider_id)
            .where(AlertDeduplicationRule.provider_type == provider_type)
        ).one_or_none()
        return rule

def is_linked_provider(tenant_id: str, provider_id: str) -> bool:
    with Session(engine) as session:
        query = session.query(Alert.provider_id)

        # Add FORCE INDEX hint only for MySQL
        if engine.dialect.name == "mysql":
            query = query.with_hint(Alert, "FORCE INDEX (idx_alert_tenant_provider)")

        linked_provider = (
            query.outerjoin(Provider, Alert.provider_id == Provider.id)
            .filter(
                Alert.tenant_id == tenant_id,
                Alert.provider_id == provider_id,
                Provider.id == None,
            )
            .first()
        )

    return linked_provider is not None


def get_consumer_providers() -> List[Provider]:
    # get all the providers that installed as consumers
    with Session(engine) as session:
        providers = session.exec(
            select(Provider).where(Provider.consumer == True)
        ).all()
    return providers


def get_installed_providers(tenant_id: str) -> List[Provider]:
    with Session(engine) as session:
        providers = session.exec(
            select(Provider).where(Provider.tenant_id == tenant_id)
        ).all()
    return providers


def get_linked_providers(tenant_id: str) -> List[Tuple[str, str, datetime]]:
    # Alert table may be too huge, so cutting the query without mercy
    LIMIT_BY_ALERTS = 10000

    with Session(engine) as session:
        alerts_subquery = (
            select(Alert)
            .filter(Alert.tenant_id == tenant_id, Alert.provider_type != "group")
            .limit(LIMIT_BY_ALERTS)
            .subquery()
        )

        providers = session.exec(
            select(
                alerts_subquery.c.provider_type,
                alerts_subquery.c.provider_id,
                func.max(alerts_subquery.c.timestamp).label("last_alert_timestamp"),
            )
            .select_from(alerts_subquery)
            .filter(~exists().where(Provider.id == alerts_subquery.c.provider_id))
            .group_by(alerts_subquery.c.provider_type, alerts_subquery.c.provider_id)
        ).all()

    return providers


def get_provider_by_type_and_id(
    tenant_id: str, provider_type: str, provider_id: Optional[str]
) -> Provider:
    with Session(engine) as session:
        query = select(Provider).where(
            Provider.tenant_id == tenant_id,
            Provider.type == provider_type,
            Provider.id == provider_id,
        )
        provider = session.exec(query).first()
    return provider

def get_all_provisioned_providers(tenant_id: str) -> List[Provider]:
    with Session(engine) as session:
        providers = session.exec(
            select(Provider)
            .where(Provider.tenant_id == tenant_id)
            .where(Provider.provisioned == True)
        ).all()
    return list(providers)

def get_provider_logs(
    tenant_id: str, provider_id: str, limit: int = 100
) -> List[ProviderExecutionLog]:
    with Session(engine) as session:
        logs = (
            session.query(ProviderExecutionLog)
            .filter(
                ProviderExecutionLog.tenant_id == tenant_id,
                ProviderExecutionLog.provider_id == provider_id,
            )
            .order_by(desc(ProviderExecutionLog.timestamp))
            .limit(limit)
            .all()
        )
    return logs

def get_all_deduplication_rules(tenant_id):
    with Session(engine) as session:
        rules = session.exec(
            select(AlertDeduplicationRule).where(
                AlertDeduplicationRule.tenant_id == tenant_id
            )
        ).all()
    return rules

def delete_deduplication_rule(rule_id: str, tenant_id: str) -> bool:
    rule_uuid = __convert_to_uuid(rule_id)
    if not rule_uuid:
        return False

    with Session(engine) as session:
        rule = session.exec(
            select(AlertDeduplicationRule)
            .where(AlertDeduplicationRule.id == rule_uuid)
            .where(AlertDeduplicationRule.tenant_id == tenant_id)
        ).first()
        if not rule:
            return False

        session.delete(rule)
        session.commit()
    return True


def update_deduplication_rule(
    tenant_id: str,
    rule_id: str,
    name: str,
    description: str,
    provider_id: str | None,
    provider_type: str,
    last_updated_by: str,
    enabled: bool,
    fingerprint_fields: list[str],
    full_deduplication: bool,
    ignore_fields: list[str],
    priority: int,
) -> bool:
    rule_uuid = __convert_to_uuid(rule_id)
    if not rule_uuid:
        return False
    with Session(engine) as session:
        statement = select(AlertDeduplicationRule).where(
            AlertDeduplicationRule.id == rule_uuid,
            AlertDeduplicationRule.tenant_id == tenant_id,
        )
        rule = session.exec(statement).first()
        if not rule:
            return False

        rule.name = name
        rule.description = description
        rule.provider_id = provider_id
        rule.provider_type = provider_type
        rule.last_updated_by = last_updated_by
        rule.enabled = enabled
        rule.fingerprint_fields = fingerprint_fields
        rule.full_deduplication = full_deduplication
        rule.ignore_fields = ignore_fields
        rule.priority = priority
        rule.last_seen = datetime.utcnow()

        session.add(rule)
        session.commit()
    return True


def get_api_key(api_key: str, include_deleted: bool = False) -> TenantApiKey:
    with Session(engine) as session:
        api_key_hashed = hashlib.sha256(api_key.encode()).hexdigest()
        statement = select(TenantApiKey).where(TenantApiKey.key_hash == api_key_hashed)
        if not include_deleted:
            statement = statement.where(TenantApiKey.is_deleted != True)
        tenant_api_key = session.exec(statement).first()
    return tenant_api_key


def update_key_last_used(
    tenant_id: str,
    reference_id: str,
    max_retries=3,
) -> str:
    """
    Updates API key last used.

    Args:
        session (Session): _description_
        tenant_id (str): _description_
        reference_id (str): _description_

    Returns:
        str: _description_
    """
    with Session(engine) as session:
        # Get API Key from database
        statement = (
            select(TenantApiKey)
            .where(TenantApiKey.reference_id == reference_id)
            .where(TenantApiKey.tenant_id == tenant_id)
        )

        tenant_api_key_entry = session.exec(statement).first()

        # Update last used
        if not tenant_api_key_entry:
            # shouldn't happen but somehow happened to specific tenant so logging it
            logger.error(
                "API key not found",
                extra={"tenant_id": tenant_id, "unique_api_key_id": reference_id},
            )
            return
        tenant_api_key_entry.last_used = datetime.utcnow()

        for attempt in range(max_retries):
            try:
                session.add(tenant_api_key_entry)
                session.commit()
                break
            except StaleDataError as ex:
                if "expected to update" in ex.args[0]:
                    logger.info(
                        f"Phantom read detected while updating API key `{reference_id}`, retry #{attempt}"
                    )
                    session.rollback()
                    continue
                else:
                    raise

def get_deduplication_rule_by_id(tenant_id, rule_id: str):
    rule_uuid = __convert_to_uuid(rule_id)
    if not rule_uuid:
        return None

    with Session(engine) as session:
        rules = session.exec(
            select(AlertDeduplicationRule)
            .where(AlertDeduplicationRule.tenant_id == tenant_id)
            .where(AlertDeduplicationRule.id == rule_uuid)
        ).first()
    return rules


def create_deduplication_rule(
    tenant_id: str,
    name: str,
    description: str,
    provider_id: str | None,
    provider_type: str,
    created_by: str,
    enabled: bool = True,
    fingerprint_fields: list[str] = [],
    full_deduplication: bool = False,
    ignore_fields: list[str] = [],
    priority: int = 0,
    is_provisioned: bool = False,
):
    with Session(engine) as session:
        new_rule = AlertDeduplicationRule(
            tenant_id=tenant_id,
            name=name,
            description=description,
            provider_id=provider_id,
            provider_type=provider_type,
            last_updated_by=created_by,  # on creation, last_updated_by is the same as created_by
            created_by=created_by,
            enabled=enabled,
            fingerprint_fields=fingerprint_fields,
            full_deduplication=full_deduplication,
            ignore_fields=ignore_fields,
            priority=priority,
            is_provisioned=is_provisioned,
        )
        session.add(new_rule)
        session.commit()
        session.refresh(new_rule)
    return new_rule

