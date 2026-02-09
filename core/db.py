"""
Keep main database module.

This module contains the CRUD database functions for Keep.
"""

import logging
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Iterator, List, Optional

from dateutil.tz import tz
from dotenv import find_dotenv, load_dotenv
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from psycopg2.errors import NoActiveSqlTransaction
from retry import retry
from sqlalchemy import (
    and_,
    select,
    update,
)
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import subqueryload
from sqlmodel import Session, select, text

from models.db.preset import PresetDto, StaticPresetsId

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
from config.consts import KEEP_AUDIT_EVENTS_ENABLED
from core.db_utils import (
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


def get_session_sync() -> Session:
    """
    Creates a database session.

    Returns:
        Session: A database session
    """
    return Session(engine)


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
):
    """
    Enrich an alert with the provided enrichments.

    Args:
        session (Session): The database session.
        tenant_id (str): The tenant ID to filter the alert enrichments by.
        fingerprint (str): The alert fingerprint to filter the alert enrichments by.
        enrichments (dict): The enrichments to add to the alert.
        force (bool): Whether to force the enrichment to be updated. This is used to dispose enrichments if necessary.
    """
    enrichment = get_enrichment_with_session(session, tenant_id, fingerprint)
    if enrichment:
        # if force - override exisitng enrichments. being used to dispose enrichments if necessary
        if force:
            new_enrichment_data = enrichments
        else:
            new_enrichment_data = {**enrichment.enrichments, **enrichments}
        # Preserve existing note if incoming note is empty/None/not provided
        incoming_note = enrichments.get("note")
        if not incoming_note or (
            isinstance(incoming_note, str) and not incoming_note.strip()
        ):
            existing_note = enrichment.enrichments.get("note")
            if existing_note:
                new_enrichment_data["note"] = existing_note
        # Remove keys with None values (e.g., status=None when undismissing)
        # This allows the alert to revert to its original value from event data
        for key, value in list(enrichments.items()):
            if value is None and key in new_enrichment_data:
                del new_enrichment_data[key]

        # When forcing update (e.g. making enrichments permanent/disposing),
        # ensure we don't accidentally keep status if it's not in the new enrichments
        if force and "status" not in enrichments and "status" in enrichment.enrichments:
            # If we are forcing and status is NOT in the new enrichments, it means we want to remove it
            # But new_enrichment_data = enrichments (line 1303), so it's already not there.
            # However, we need to make sure we don't re-add it from existing if we are forcing?
            # No, if force=True, new_enrichment_data IS enrichments.
            # So if 'status' is not in 'enrichments', it won't be in 'new_enrichment_data'.
            # BUT, we have logic above that preserves note.
            pass
        # SQLAlchemy doesn't support updating JSON fields, so we need to do it manually
        # https://github.com/sqlalchemy/sqlalchemy/discussions/8396#discussion-4308891
        stmt = (
            update(AlertEnrichment)
            .where(AlertEnrichment.id == enrichment.id)
            .values(enrichments=new_enrichment_data)
        )
        session.execute(stmt)
        if audit_enabled:
            # add audit event
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
            # add audit event
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
    with_alert_instance_enrichment=False,
) -> List[Alert]:
    """
    Get all alerts for a given fingerprint.

    Args:
        tenant_id (str): The tenant_id to filter the alerts by.
        fingerprint (str): The fingerprint to filter the alerts by.

    Returns:
        List[Alert]: A list of Alert objects.
    """
    with Session(engine) as session:
        # Create the query using select() instead of session.query()
        query = select(Alert).options(subqueryload(Alert.alert_enrichment))

        if with_alert_instance_enrichment:
            query = query.options(subqueryload(Alert.alert_instance_enrichment))

        # Filter by tenant_id
        query = query.where(Alert.tenant_id == tenant_id)

        query = query.where(Alert.fingerprint == fingerprint)

        query = query.order_by(Alert.timestamp.desc())

        if status:
            query = query.where(
                get_json_extract_field(session, Alert.event, "status") == status
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
    tenant_id: str, alert: Alert, session: Optional[Session] = None, max_retries=3
) -> None:
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
                    tzinfo=tz.UTC
                ) < alert.timestamp.replace(tzinfo=tz.UTC):
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
                    session.add(last_alert)

                elif not last_alert:
                    logger.info(f"No last alert for `{fingerprint}`, creating new")
                    last_alert = LastAlert(
                        tenant_id=tenant_id,
                        fingerprint=alert.fingerprint,
                        timestamp=alert.timestamp,
                        first_timestamp=alert.timestamp,
                        alert_id=alert.id,
                        alert_hash=alert.alert_hash,
                    )
                    session.add(last_alert)

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
            except NoActiveSqlTransaction as ex:
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
