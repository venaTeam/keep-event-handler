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
import threading
import time

import alembic.command
import alembic.config
from sqlalchemy import inspect as sa_inspect, text
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


_SCHEMA_WAIT_TIMEOUT = int(os.environ.get("KEEP_SCHEMA_WAIT_TIMEOUT", "180"))
_SCHEMA_WAIT_INTERVAL = int(os.environ.get("KEEP_SCHEMA_WAIT_INTERVAL", "2"))
# How many consecutive polls the gateway's alembic head must stay unchanged
# before we treat its `alembic upgrade head` run as finished.
_SCHEMA_STABLE_CHECKS = int(os.environ.get("KEEP_SCHEMA_STABLE_CHECKS", "3"))
# Backoff between whole schema-wait attempts, after the change from
# exit-on-timeout to retry-forever.
_SCHEMA_RETRY_BACKOFF_START = int(os.environ.get("KEEP_SCHEMA_RETRY_BACKOFF_START", "5"))
_SCHEMA_RETRY_BACKOFF_MAX = int(os.environ.get("KEEP_SCHEMA_RETRY_BACKOFF_MAX", "60"))
# Core tables that must exist before the schema counts as ready. Quiescence
# alone is not enough: if the gateway is DOWN, its (stale) head is trivially
# stable, and this consumer would proceed against a not-yet-migrated schema.
_SCHEMA_REQUIRED_TABLES = [
    t.strip()
    for t in os.environ.get(
        "KEEP_SCHEMA_REQUIRED_TABLES", "tenant,provider,alert,lastalert"
    ).split(",")
    if t.strip()
]
# Optional exact revision to wait for. Stronger than quiescence — it is the
# only guard that distinguishes "the gateway finished" from "the gateway never
# started". Unset by default because the gateway ships migrations this repo's
# own chain does not contain, so no head can be hardcoded here; set it per
# release when the deploy knows the target revision.
_SCHEMA_EXPECTED_REVISION = os.environ.get("KEEP_SCHEMA_EXPECTED_REVISION") or None

# Set by the entrypoint's startup signal handler so a SIGTERM during the wait
# aborts promptly instead of blocking for the whole grace period.
_abort_event = threading.Event()


class SchemaWaitTimeout(RuntimeError):
    """One schema-wait attempt timed out. Retryable — never fatal."""


class SchemaWaitAborted(RuntimeError):
    """The wait gave up because shutdown was requested.

    Distinct from success on purpose: returning normally would let migrate_db
    log "DB schema ready" and let init_services carry on against a schema that
    was never verified.
    """


def request_schema_wait_abort():
    """Ask an in-flight schema wait to give up (SIGTERM during startup)."""
    _abort_event.set()


def schema_wait_aborted() -> bool:
    return _abort_event.is_set()


def _missing_required_tables(inspector) -> list:
    existing = set(inspector.get_table_names())
    return [t for t in _SCHEMA_REQUIRED_TABLES if t not in existing]


def _gateway_alembic_head():
    """Return the alembic revision currently stamped on the shared DB, or None if
    keep-api-gateway has not created/stamped `alembic_version` yet."""
    inspector = sa_inspect(engine)
    if "alembic_version" not in inspector.get_table_names():
        return None
    with engine.connect() as conn:
        row = conn.execute(text("SELECT version_num FROM alembic_version")).first()
    return row[0] if row else None


def _wait_for_schema():
    """Block until keep-api-gateway has FINISHED provisioning the shared schema.

    keep-api-gateway is the SINGLE owner of the database schema — it is the only
    service that ships alembic migrations. This consumer must not build the
    schema itself: doing so via SQLModel.metadata.create_all() races the
    gateway's `alembic upgrade head` on an empty shared DB and collides in
    pg_type (duplicate key (typname)=(tenant)), and it also bypasses migration
    history (create_all materializes the current model and never stamps
    alembic_version). Wait for the gateway to finish, then run as a consumer.

    Readiness is detected by quiescence of the gateway's alembic head: the
    gateway advances `alembic_version` after each migration, so once the revision
    stops changing across several consecutive polls its migration run is complete
    and every column is in place. Checking only that core tables exist is NOT
    enough — the gateway creates alembic_version/alert early but adds columns
    such as provider.provider_metadata in *later* migrations, so a
    table-existence check lets this consumer query a not-yet-created column on a
    cold boot. We also can't compare against a fixed head revision, because the
    gateway ships migrations (product-BI metrics) that this consumer's own
    migration chain does not contain — so its head differs from ours.
    """
    deadline = time.monotonic() + _SCHEMA_WAIT_TIMEOUT
    last_head = None
    stable = 0
    while True:
        if _abort_event.is_set():
            raise SchemaWaitAborted("schema wait aborted (shutdown requested)")
        try:
            missing = _missing_required_tables(sa_inspect(engine))
            if missing:
                # Catches an empty or half-built database before any head
                # comparison can call it "stable".
                last_head, stable = None, 0
                logger.info(
                    "Waiting for keep-api-gateway: required tables missing %s",
                    missing,
                )
                head = None
            else:
                head = _gateway_alembic_head()

            if head is not None and _SCHEMA_EXPECTED_REVISION:
                # An exact match beats quiescence: a stale head on a down
                # gateway is perfectly quiescent, and this is what tells the
                # two apart.
                if head == _SCHEMA_EXPECTED_REVISION:
                    logger.info(
                        "DB schema is ready (alembic head %s matches "
                        "KEEP_SCHEMA_EXPECTED_REVISION)",
                        head,
                    )
                    return
                logger.info(
                    "keep-api-gateway alembic head %s != expected %s; waiting",
                    head,
                    _SCHEMA_EXPECTED_REVISION,
                )
                last_head, stable = head, 0
            elif head is None:
                last_head, stable = None, 0
                logger.info(
                    "Waiting for keep-api-gateway to initialize the DB schema "
                    "(alembic_version not stamped yet)"
                )
            elif head == last_head:
                stable += 1
                if stable >= _SCHEMA_STABLE_CHECKS:
                    logger.info(
                        "DB schema is ready (owned by keep-api-gateway; alembic "
                        "head %s stable across %s checks)",
                        head,
                        stable,
                    )
                    return
                logger.info(
                    "keep-api-gateway alembic head %s steady (%s/%s)",
                    head,
                    stable,
                    _SCHEMA_STABLE_CHECKS,
                )
            else:
                logger.info(
                    "keep-api-gateway migrations still advancing "
                    "(alembic head -> %s); waiting for them to settle",
                    head,
                )
                last_head, stable = head, 1
        except Exception as exc:
            logger.warning("Waiting for the DB to become reachable: %s", exc)
            last_head, stable = None, 0
        if time.monotonic() >= deadline:
            raise SchemaWaitTimeout(
                "Timed out waiting for keep-api-gateway to provision the DB "
                f"schema (waited {_SCHEMA_WAIT_TIMEOUT}s; last alembic head "
                f"{last_head!r})"
            )
        # Interruptible: a SIGTERM during the wait must not sit out the sleep.
        if _abort_event.wait(_SCHEMA_WAIT_INTERVAL):
            raise SchemaWaitAborted("schema wait aborted (shutdown requested)")


def migrate_db():
    """
    Ensure the DB schema is ready before this service runs.

    keep-api-gateway owns the schema on the shared server DB, so this service
    waits for it rather than building it (see _wait_for_schema). On SQLite
    (tests / standalone single-process dev) there is no shared owner and no
    possible race, so build the tables locally as before.

    A wait that times out is RETRIED with capped backoff, indefinitely. It used
    to raise, which reached consumer_main and called sys.exit(1) — killing the
    pod at exactly the moment the cluster needed it up, because a full sync is
    when the gateway's migrations are slowest to settle. A slow gateway must
    make this consumer slow, not dead: the pod stays alive reporting "alive,
    not ready", and the startupProbe budget decides when to give up on it.
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
    backoff = _SCHEMA_RETRY_BACKOFF_START
    while not _abort_event.is_set():
        try:
            _wait_for_schema()
            logger.info("DB schema ready")
            return None
        except SchemaWaitAborted:
            break
        except SchemaWaitTimeout as exc:
            logger.warning(
                "Schema not ready yet (%s); retrying in %ss", exc, backoff
            )
            if _abort_event.wait(backoff):
                break
            backoff = min(backoff * 2, _SCHEMA_RETRY_BACKOFF_MAX)

    # Never return normally here: the schema was NOT verified, and the callers
    # above (provider load, tenant creation, provisioning) would otherwise run
    # against a database that may not be migrated.
    logger.info("Stopped waiting for the DB schema (shutdown requested)")
    raise SchemaWaitAborted("startup aborted while waiting for the DB schema")
