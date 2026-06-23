"""
This module is responsible for creating the database and tables when the application starts.

The reason to split this code from db.py is that the functions here are invoked from the master process
when the application starts, while the functions in db.py are invoked from the worker processes.

This is important because if the master process init the engine, it will be forked to the worker processes,
and the engine will be shared among all the processes, causing issues with the connections.

** This happens because the engine is not fork-safe, and the connections are not thread-safe. **

The mitigation is to create different engines for each process, and the master process should only be responsible
for creating the database and tables, while the worker processes should only be responsible for creating the sessions.
"""

import hashlib
import logging
import os
import time

import alembic.command
import alembic.config
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from src.core.db.db import engine

# This import is required to create the tables
from src.models.roles import Admin as AdminRole

# if Keep is not multitenant, let's import the User table too:
from src.models.db.user import User  # pylint: disable=import-outside-toplevel

from src.contextmanager.contextmanager import ContextManager
from src.secretmanager.secretmanagerfactory import SecretManagerFactory
from src.models.db.tenant import TenantApiKey, Tenant
from src.models.db.alert import Alert, AlertField, AlertRaw, AlertAudit, CommentMention, AlertDeduplicationRule, AlertDeduplicationEvent, LastAlert, IncidentEnrichment, LastAlertToIncident
from src.models.db.enrichment_event import EnrichmentEvent, EnrichmentLog
from src.models.db.extraction import ExtractionRule
from src.models.db.incident import Incident
from src.models.db.maintenance_window import MaintenanceWindowRule
from src.models.db.mapping import MappingRule
from src.models.db.preset import Preset, Tag, PresetTagLink
from src.models.db.provider import Provider, ProviderExecutionLog
from src.models.db.rule import Rule
from src.models.db.topology import TopologyService, TopologyApplication, TopologyServiceApplication, TopologyServiceDependency
from sqlmodel import SQLModel
from src.config.consts import DEFAULT_PASSWORD, DEFAULT_USERNAME, KEEP_FORCE_RESET_DEFAULT_PASSWORD

logger = logging.getLogger(__name__)


def try_create_single_tenant(tenant_id: str, create_default_user=True) -> None:
    """
    Creates the single tenant and the default user if they don't exist.
    """
    
    with Session(engine) as session:
        try:
            # check if the tenant exist:
            tenant = session.exec(select(Tenant).where(Tenant.id == tenant_id)).first()
            if not tenant:
                # Do everything related with single tenant creation in here
                logger.info("Creating single tenant")
                session.add(Tenant(id=tenant_id, name="Single Tenant"))
            else:
                logger.info("Single tenant already exists")

            # now let's create the default user

            # check if at least one user exists:
            user: User | None = session.exec(select(User)).first()
            # if no users exist, let's create the default user
            if not user and create_default_user:
                logger.info("Creating default user")

                default_password = hashlib.sha256(DEFAULT_PASSWORD.encode()).hexdigest()
                default_user = User(
                    username=DEFAULT_USERNAME,
                    password_hash=default_password,
                    role=AdminRole.get_name(),
                )
                session.add(default_user)
                logger.info("Default user created")
            # else, if the user want to force the refresh of the default user password
            elif KEEP_FORCE_RESET_DEFAULT_PASSWORD and user:
                # update the password of the default user
                logger.info("Forcing reset of default user password")
                default_password = hashlib.sha256(DEFAULT_PASSWORD.encode()).hexdigest()
                user.password_hash = default_password
                if user.username != DEFAULT_USERNAME:
                    logger.info(
                        "Default user username updated",
                        extra={
                            "username": user.username,
                            "new_username": DEFAULT_USERNAME,
                        },
                    )
                    user.username = DEFAULT_USERNAME
                logger.info("Default user password updated")
            # provision default api keys
            if os.environ.get("KEEP_DEFAULT_API_KEYS", ""):
                logger.info("Provisioning default api keys")
                default_api_keys = os.environ.get("KEEP_DEFAULT_API_KEYS").split(",")
                for default_api_key in default_api_keys:
                    try:
                        api_key_name, api_key_role, api_key_secret = (
                            default_api_key.strip().split(":")
                        )
                    except ValueError:
                        logger.error(
                            "Invalid format for default api key. Expected format: name:role:secret"
                        )
                    # Create the default api key for the default user
                    api_key = session.exec(
                        select(TenantApiKey).where(
                            TenantApiKey.reference_id == api_key_name
                        )
                    ).first()
                    if api_key:
                        logger.info(f"Api key {api_key_name} already exists")
                        continue
                    logger.info(f"Provisioning api key {api_key_name}")
                    hashed_api_key = hashlib.sha256(
                        api_key_secret.encode("utf-8")
                    ).hexdigest()
                    new_installation_api_key = TenantApiKey(
                        tenant_id=tenant_id,
                        reference_id=api_key_name,
                        key_hash=hashed_api_key,
                        is_system=True,
                        created_by="system",
                        role=api_key_role,
                    )
                    session.add(new_installation_api_key)
                    # write to the secret manager
                    context_manager = ContextManager(tenant_id=tenant_id)
                    secret_manager = SecretManagerFactory.get_secret_manager(
                        context_manager
                    )
                    try:
                        secret_manager.write_secret(
                            secret_name=f"{tenant_id}-{api_key_name}",
                            secret_value=api_key_secret,
                        )
                    # probably 409 if the secret already exists, but we don't want to fail on that
                    except Exception:
                        logger.exception(
                            f"Failed to write secret for api key {api_key_name}"
                        )
                    logger.info(f"Api key {api_key_name} provisioned")
                logger.info("Api keys provisioned")

            # commit the changes
            session.commit()
            logger.info("Single tenant created")
        except IntegrityError:
            # Tenant already exists
            logger.exception("Failed to provision single tenant")
            raise
        except Exception:
            logger.exception("Failed to create single tenant")


# Tables provisioned by keep-api-gateway's alembic migrations whose presence
# signals the shared schema is ready. `alembic_version` proves the gateway (the
# single schema owner) has run, `alert` is a core table this consumer needs.
_SCHEMA_READY_TABLES = ("alembic_version", "alert")
_SCHEMA_WAIT_TIMEOUT = int(os.environ.get("KEEP_SCHEMA_WAIT_TIMEOUT", "180"))
_SCHEMA_WAIT_INTERVAL = int(os.environ.get("KEEP_SCHEMA_WAIT_INTERVAL", "2"))


def _wait_for_schema():
    """Block until keep-api-gateway has provisioned the shared DB schema.

    keep-api-gateway is the SINGLE owner of the database schema — it is the only
    service that ships alembic migrations. This consumer must not build the
    schema itself: doing so via SQLModel.metadata.create_all() races the
    gateway's `alembic upgrade head` on an empty shared DB and collides in
    pg_type (duplicate key (typname)=(tenant)), and it also bypasses migration
    history (create_all materializes the current model and never stamps
    alembic_version). Wait for the gateway to finish, then run as a consumer.
    """
    deadline = time.monotonic() + _SCHEMA_WAIT_TIMEOUT
    while True:
        try:
            tables = set(sa_inspect(engine).get_table_names())
            missing = [t for t in _SCHEMA_READY_TABLES if t not in tables]
            if not missing:
                logger.info("DB schema is ready (owned by keep-api-gateway)")
                return
            logger.info(
                "Waiting for keep-api-gateway to provision the DB schema; "
                "missing tables: %s",
                missing,
            )
        except Exception as exc:
            logger.warning("Waiting for the DB to become reachable: %s", exc)
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Timed out waiting for keep-api-gateway to provision the DB "
                f"schema (waited {_SCHEMA_WAIT_TIMEOUT}s for {_SCHEMA_READY_TABLES})"
            )
        time.sleep(_SCHEMA_WAIT_INTERVAL)


def migrate_db():
    """
    Ensure the DB schema is ready before this service runs.

    keep-api-gateway owns the schema on the shared server DB, so this service
    waits for it rather than building it (see _wait_for_schema). On SQLite
    (tests / standalone single-process dev) there is no shared owner and no
    possible race, so build the tables locally as before.
    """
    if os.environ.get("SKIP_DB_CREATION", "false") == "true":
        logger.info("Skipping DB schema init...")
        return None

    if engine.dialect.name == "sqlite":
        logger.info("SQLite engine — creating tables locally")
        SQLModel.metadata.create_all(engine)
        logger.info("Finished creating tables")
        return None

    logger.info("Waiting for keep-api-gateway to provision the DB schema...")
    _wait_for_schema()
    logger.info("DB schema ready")
