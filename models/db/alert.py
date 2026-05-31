from sqlmodel import JSON, TEXT, Column, DateTime, Field, Index, Relationship, SQLModel, String, Integer, Boolean
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
from sqlalchemy import ForeignKey, ForeignKeyConstraint, UniqueConstraint
from uuid import UUID, uuid4
from sqlalchemy_utils import UUIDType
from datetime import datetime
from pydantic import PrivateAttr
from typing import List, TYPE_CHECKING
from models.db.tenant import Tenant
from core.db.helpers import NULL_FOR_DELETED_AT, DATETIME_COLUMN_TYPE

if TYPE_CHECKING:
    from models.db.incident import Incident



class AlertField(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(foreign_key="tenant.id", index=True)
    field_name: str = Field(index=True)
    provider_id: str | None = Field(index=True)
    provider_type: str | None = Field(index=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "field_name", name="uq_tenant_field"),
        Index("ix_alert_field_tenant_id", "tenant_id"),
        Index("ix_alert_field_tenant_id_field_name", "tenant_id", "field_name"),
        Index(
            "ix_alert_field_provider_id_provider_type", "provider_id", "provider_type"
        ),
    )

    class Config:
        arbitrary_types_allowed = True


class AlertRaw(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(foreign_key="tenant.id", index=True)
    raw_alert: dict = Field(sa_column=Column(JSON().with_variant(PG_JSONB, "postgresql")))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    provider_type: str | None = Field(default=None)
    error: bool = Field(default=False, index=True)
    error_message: str | None = Field(default=None)
    dismissed: bool = Field(default=False)
    dismissed_at: datetime | None = Field(default=None)
    dismissed_by: str | None = Field(default=None)

    __table_args__ = (
        Index("ix_alert_raw_tenant_id_error", "tenant_id", "error"),
        Index("ix_alert_raw_tenant_id_timestamp", "tenant_id", "timestamp"),
    )

    class Config:
        arbitrary_types_allowed = True

class AlertAudit(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    fingerprint: str
    tenant_id: str = Field(foreign_key="tenant.id", nullable=False)
    # when
    timestamp: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    # who
    user_id: str = Field(nullable=False)
    # what
    action: str = Field(nullable=False)
    description: str = Field(sa_column=Column(TEXT))

    mentions: list["CommentMention"] = Relationship(
        back_populates="alert_audit", sa_relationship_kwargs={"lazy": "selectin"}
    )

    __table_args__ = (
        Index("ix_alert_audit_tenant_id", "tenant_id"),
        Index("ix_alert_audit_fingerprint", "fingerprint"),
        Index("ix_alert_audit_tenant_id_fingerprint", "tenant_id", "fingerprint"),
        Index("ix_alert_audit_timestamp", "timestamp"),
    )

class CommentMention(SQLModel, table=True):
    """Many-to-many relationship table for users mentioned in comments."""

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    comment_id: UUID = Field(
        sa_column=Column(
            UUIDType(binary=False),
            ForeignKey("alertaudit.id", ondelete="CASCADE"),
            nullable=False,
        )
    )
    mentioned_user_id: str = Field(nullable=False)
    tenant_id: str = Field(foreign_key="tenant.id", nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)

    alert_audit: AlertAudit = Relationship(
        back_populates="mentions", sa_relationship_kwargs={"lazy": "selectin"}
    )


class AlertDeduplicationRule(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(foreign_key="tenant.id")
    name: str = Field(index=True)
    description: str
    provider_id: str | None = Field(default=None)  # None for default rules
    provider_type: str
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    last_updated_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str
    enabled: bool = Field(default=True)
    fingerprint_fields: list[str] = Field(sa_column=Column(JSON().with_variant(PG_JSONB, "postgresql")), default=[])
    full_deduplication: bool = Field(default=False)
    ignore_fields: list[str] = Field(sa_column=Column(JSON().with_variant(PG_JSONB, "postgresql")), default=[])
    priority: int = Field(default=0)  # for future use
    is_provisioned: bool = Field(default=False)

    class Config:
        arbitrary_types_allowed = True


class AlertDeduplicationEvent(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(foreign_key="tenant.id", index=True)
    timestamp: datetime = Field(
        sa_column=Column(DATETIME_COLUMN_TYPE, nullable=False),
        default_factory=datetime.utcnow,
    )
    deduplication_rule_id: UUID  # TODO: currently rules can also be implicit (like default) so they won't exists on db Field(foreign_key="alertdeduplicationrule.id", index=True)
    deduplication_type: str = Field()  # 'full' or 'partial'
    date_hour: datetime = Field(
        sa_column=Column(DATETIME_COLUMN_TYPE),
        default_factory=lambda: datetime.utcnow().replace(
            minute=0, second=0, microsecond=0
        ),
    )
    # these are only soft reference since it could be linked provider
    provider_id: str | None = Field()
    provider_type: str | None = Field()

    __table_args__ = (
        Index(
            "ix_alert_deduplication_event_provider_id",
            "provider_id",
        ),
        Index(
            "ix_alert_deduplication_event_provider_type",
            "provider_type",
        ),
        Index(
            "ix_alert_deduplication_event_provider_id_date_hour",
            "provider_id",
            "date_hour",
        ),
        Index(
            "ix_alert_deduplication_event_provider_type_date_hour",
            "provider_type",
            "date_hour",
        ),
    )

    class Config:
        arbitrary_types_allowed = True

class Alert(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(foreign_key="tenant.id")
    tenant: Tenant = Relationship()
    # index=True added because we query top 1000 alerts order by timestamp.
    # On a large dataset, this will be slow without an index.
    #            with 1M alerts, we see queries goes from >30s to 0s with the index
    #            todo: on MSSQL, the index is "nonclustered" index which cannot be controlled by SQLModel
    timestamp: datetime = Field(
        sa_column=Column(DATETIME_COLUMN_TYPE, index=True, nullable=False),
        default_factory=lambda: datetime.utcnow().replace(
            microsecond=int(datetime.utcnow().microsecond / 1000) * 1000
        ),
    )
    provider_type: str
    provider_id: str | None
    # === Source 1: External User Fields (11) ===
    application: str | None = Field(sa_column=Column(String(200), nullable=True))
    object: str | None = Field(sa_column=Column(String(200), nullable=True))
    node_name: str | None = Field(sa_column=Column(String(200), nullable=True))
    severity: str | None = Field(sa_column=Column(String(50), nullable=True))
    message: str | None = Field(sa_column=Column(String(800), nullable=True))
    operator: str | None = Field(sa_column=Column(String(100), nullable=True))
    time_created: str | None = Field(sa_column=Column(String(50), nullable=True))
    network: str | None = Field(default="nh", sa_column=Column(String(50), nullable=True, default="nh"))
    timezone: str | None = Field(default="Asia/Jerusalem", sa_column=Column(String(50), nullable=True, default="Asia/Jerusalem"))
    custom_key: str | None = Field(sa_column=Column(String(255), nullable=True))
    expiry_in_minutes: int | None = Field(sa_column=Column(Integer, nullable=True))

    # === Source 2: Appchi System Fields (5) ===
    source: str | None = Field(sa_column=Column(String(255), nullable=True))
    service: str | None = Field(sa_column=Column(String(255), nullable=True))
    key_field: str | None = Field(sa_column=Column(String(255), nullable=True))
    name: str | None = Field(sa_column=Column(String(255), nullable=True))
    status: str | None = Field(sa_column=Column(String(50), nullable=True))
    description: str | None = Field(sa_column=Column(TEXT, nullable=True))

    # === Source 3: Keep Platform Fields ===
    is_full_duplicate: bool | None = Field(default=False, sa_column=Column(Boolean, nullable=True, default=False))
    is_partial_duplicate: bool | None = Field(default=False, sa_column=Column(Boolean, nullable=True, default=False))
    duplicate_reason: str | None = Field(sa_column=Column(String(255), nullable=True))

    fingerprint: str = Field(index=True)  # Add the fingerprint field with an index

    # alert_hash is different than fingerprint, it is a hash of the alert itself
    #            and it is used for deduplication.
    #            alert can be different but have the same fingerprint (e.g. different "firing" and "resolved" will have the same fingerprint but not the same alert_hash)
    alert_hash: str | None

    _incidents: List["Incident"] = PrivateAttr(default_factory=list)

    __table_args__ = (
        Index(
            "ix_alert_tenant_fingerprint_timestamp",
            "tenant_id",
            "fingerprint",
            "timestamp",
        ),
        Index("idx_fingerprint_timestamp", "fingerprint", "timestamp"),
        Index(
            "idx_alert_tenant_timestamp_fingerprint",
            "tenant_id",
            "timestamp",
            "fingerprint",
        ),
        # Index to optimize linked provider queries (is_linked_provider function)
        # These queries look for alerts with specific tenant_id and provider_id combinations
        # where the provider doesn't exist in the provider table
        # Without this index, the query scans 400k+ rows and takes ~2s
        # With this index, the query takes ~0.4s
        Index(
            "idx_alert_tenant_provider",
            "tenant_id",
            "provider_id",
        ),
    )

    class Config:
        arbitrary_types_allowed = True


class LastAlert(SQLModel, table=True):
    tenant_id: str = Field(foreign_key="tenant.id", nullable=False, primary_key=True)
    fingerprint: str = Field(primary_key=True, index=True)
    alert_id: UUID = Field(foreign_key="alert.id")
    timestamp: datetime = Field(nullable=False, index=True)
    first_timestamp: datetime = Field(nullable=False, index=True)
    alert_hash: str | None = Field(nullable=True, index=True)

    # === Phase 2: user enrichment state (relocated from alertenrichment) ===
    status: str | None = Field(default=None, sa_column=Column(String(50), nullable=True, info={"enrichable": True}))
    status_disposable: bool = Field(
        default=False,
        sa_column=Column(Boolean, nullable=False, server_default="false", info={"enrichable": True}),
    )
    dismiss_mode: str | None = Field(default=None, sa_column=Column(String(20), nullable=True, info={"enrichable": True}))
    dismissed_until: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True, info={"enrichable": True})
    )
    assignee: str | None = Field(default=None, sa_column=Column(String(255), nullable=True, info={"enrichable": True}))
    note: str | None = Field(default=None, sa_column=Column(TEXT, nullable=True, info={"enrichable": True}))
    deleted: bool = Field(
        default=False,
        sa_column=Column(Boolean, nullable=False, server_default="false", info={"enrichable": True}),
    )

    # === Phase 2: ticket linkage (assign-ticket modal) ===
    ticket_type: str | None = Field(default=None, sa_column=Column(String(50), nullable=True, info={"enrichable": True}))
    ticket_url: str | None = Field(default=None, sa_column=Column(String(500), nullable=True, info={"enrichable": True}))
    ticket_provider_id: str | None = Field(default=None, sa_column=Column(String(255), nullable=True, info={"enrichable": True}))

    # === Phase 2: system tracking fields (relocated from alert) ===
    last_received: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    firing_counter: int = Field(
        default=0, sa_column=Column(Integer, nullable=False, server_default="0")
    )
    unresolved_counter: int = Field(
        default=0, sa_column=Column(Integer, nullable=False, server_default="0")
    )
    started_at: str | None = Field(default=None, sa_column=Column(String(255), nullable=True))
    firing_start_time: str | None = Field(
        default=None, sa_column=Column(String(255), nullable=True)
    )
    firing_start_time_since_last_resolved: str | None = Field(
        default=None, sa_column=Column(String(255), nullable=True)
    )

    __table_args__ = (
        # Original indexes from MySQL
        Index("idx_lastalert_tenant_timestamp", "tenant_id", "first_timestamp"),
        Index("idx_lastalert_tenant_timestamp_new", "tenant_id", "timestamp"),
        Index(
            "idx_lastalert_tenant_ordering",
            "tenant_id",
            "first_timestamp",
            "alert_id",
            "fingerprint",
        ),
        {},
    )

class AlertEnrichment(SQLModel, table=True):
    """
    TODO: we need to rename this table to EntityEnrichment since it's not only for alerts anymore.
    @tb: for example, we use it also for Incidents now.
    """

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(foreign_key="tenant.id")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    alert_fingerprint: str = Field(unique=True)
    enrichments: dict = Field(sa_column=Column(JSON().with_variant(PG_JSONB, "postgresql")))

    class Config:
        arbitrary_types_allowed = True

class LastAlertToIncident(SQLModel, table=True):
    tenant_id: str = Field(foreign_key="tenant.id", nullable=False, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    fingerprint: str = Field(primary_key=True)
    incident_id: UUID = Field(
        sa_column=Column(
            UUIDType(binary=False),
            ForeignKey("incident.id", ondelete="CASCADE"),
            primary_key=True,
        )
    )

    is_created_by_ai: bool = Field(default=False)

    deleted_at: datetime = Field(
        default_factory=None,
        nullable=True,
        primary_key=True,
        default=NULL_FOR_DELETED_AT,
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "fingerprint"],
            ["lastalert.tenant_id", "lastalert.fingerprint"],
        ),
        Index(
            "idx_lastalerttoincident_tenant_fingerprint",
            "tenant_id",
            "fingerprint",
            "deleted_at",
        ),
        Index(
            "idx_tenant_deleted_fingerprint", "tenant_id", "deleted_at", "fingerprint"
        ),
        {},
    )
