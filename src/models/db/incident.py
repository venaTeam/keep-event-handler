import enum
from enum import Enum
from src.core.db.helpers import DismissMode, is_dismiss_active
from src.models.alert import SeverityBaseInterface
from uuid import UUID, uuid4
from sqlalchemy import DateTime, String
from sqlalchemy_utils import UUIDType
from datetime import datetime
from typing import Optional, List
from sqlmodel import (
    JSON,
    TEXT,
    Column,
    Field,
    Index,
    Relationship,
    SQLModel,
    func,
    select,
    text,
)

from pydantic import PrivateAttr
from retry import retry
from sqlalchemy import ForeignKey
from sqlalchemy.exc import IntegrityError
from src.models.db.rule import ResolveOn
from src.models.db.tenant import Tenant


class IncidentType(str, enum.Enum):
    MANUAL = "manual"  # Created manually by users
    AI = "ai"  # Created by AI
    RULE = "rule"  # Created by rules engine
    TOPOLOGY = "topology"  # Created by topology processor

class IncidentSeverity(SeverityBaseInterface):
    CRITICAL = ("critical", 5)
    HIGH = ("high", 4)
    WARNING = ("warning", 3)
    INFO = ("info", 2)
    LOW = ("low", 1)

    def from_number(n):
        for severity in IncidentSeverity:
            if severity.order == n:
                return severity
        raise ValueError(f"No IncidentSeverity with order {n}")

# Alerts and incidents model dismissal identically, so they share one enum and
# one "is it still in force" rule (src/core/db/helpers.py).
class IncidentDismissMode(str, Enum):
    PERMANENT = DismissMode.PERMANENT.value
    DISMISS_UNTIL = DismissMode.DISMISS_UNTIL.value


class IncidentStatus(Enum):
    # Active incident
    FIRING = "firing"
    # Incident has been resolved
    RESOLVED = "resolved"
    # Incident has been acknowledged but not resolved
    ACKNOWLEDGED = "acknowledged"
    # Incident was merged with another incident
    MERGED = "merged"
    # Incident is dismissed, permanently or until a deadline. NEVER stored in
    # `Incident.status` — it is derived from dismiss_mode/dismissed_until so a
    # time-boxed dismissal can expire without anything rewriting the row. See
    # `Incident.get_effective_status`.
    SUPPRESSED = "suppressed"

    @classmethod
    def get_active(cls, return_values=False) -> List[str | enum.Enum]:
        statuses = [cls.FIRING, cls.ACKNOWLEDGED]
        if return_values:
            return [s.value for s in statuses]
        return statuses

    @classmethod
    def get_closed(cls, return_values=False) -> List[str | enum.Enum]:
        statuses = [cls.RESOLVED, cls.MERGED]
        if return_values:
            return [s.value for s in statuses]
        return statuses


class Incident(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(foreign_key="tenant.id")
    tenant: Tenant = Relationship()

    # Auto-incrementing number per tenant
    running_number: Optional[int] = Field(default=None)

    user_generated_name: str | None = Field(sa_column=Column(TEXT))
    ai_generated_name: str | None = Field(sa_column=Column(TEXT))

    user_summary: str = Field(sa_column=Column(TEXT))
    generated_summary: str = Field(sa_column=Column(TEXT))

    assignee: str | None
    severity: int = Field(default=IncidentSeverity.CRITICAL.order)
    forced_severity: bool = Field(default=False)

    status: str = Field(default=IncidentStatus.FIRING.value, index=True)

    # === Dismiss state ===
    # Mirrors the typed dismiss columns on LastAlert. Deliberately kept OUT of
    # `status`: storing "suppressed" there would leave a time-boxed dismissal
    # stuck suppressed after it expired, since nothing sweeps the table.
    # The columns themselves are created by keep-api-gateway's Alembic lineage,
    # which owns the schema for this database — there is no migration here.
    dismiss_mode: str | None = Field(
        default=None,
        sa_column=Column(String(20), nullable=True),
    )
    dismissed_until: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True, index=True),
    )

    creation_time: datetime = Field(default_factory=datetime.utcnow)

    # Start/end should be calculated from first/last alerts
    # But I suppose to have this fields as cache, to prevent extra requests
    start_time: datetime | None
    end_time: datetime | None
    last_seen_time: datetime | None

    is_predicted: bool = Field(default=False)
    is_candidate: bool = Field(default=False)
    is_visible: bool = Field(default=True)

    alerts_count: int = Field(default=0)
    affected_services: list = Field(sa_column=Column(JSON), default_factory=list)
    sources: list = Field(sa_column=Column(JSON), default_factory=list)

    rule_id: UUID | None = Field(
        sa_column=Column(
            UUIDType(binary=False),
            ForeignKey("rule.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )

    # Note: IT IS NOT A UNIQUE IDENTIFIER (as in alerts)
    rule_fingerprint: str = Field(default="", sa_column=Column(TEXT))
    # This is the fingerprint of the incident generated by the underlying tool
    # It's not a unique identifier in the DB (constraint), but when we have the same incident from some tools, we can use it to detect duplicates
    fingerprint: str | None = Field(default=None, sa_column=Column(TEXT))

    incident_type: str = Field(default=IncidentType.MANUAL.value)
    # for topology incidents
    incident_application: UUID | None = Field(default=None)
    resolve_on: str = ResolveOn.ALL.value

    same_incident_in_the_past_id: UUID | None = Field(
        sa_column=Column(
            UUIDType(binary=False),
            ForeignKey("incident.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )

    same_incident_in_the_past: Optional["Incident"] = Relationship(
        back_populates="same_incidents_in_the_future",
        sa_relationship_kwargs=dict(
            remote_side="Incident.id",
            foreign_keys="[Incident.same_incident_in_the_past_id]",
        ),
    )

    same_incidents_in_the_future: List["Incident"] = Relationship(
        back_populates="same_incident_in_the_past",
        sa_relationship_kwargs=dict(
            foreign_keys="[Incident.same_incident_in_the_past_id]",
        ),
    )

    merged_into_incident_id: UUID | None = Field(
        sa_column=Column(
            UUIDType(binary=False),
            ForeignKey("incident.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    merged_at: datetime | None = Field(default=None)
    merged_by: str | None = Field(default=None)
    merged_into: Optional["Incident"] = Relationship(
        back_populates="merged_incidents",
        sa_relationship_kwargs=dict(
            remote_side="Incident.id",
            foreign_keys="[Incident.merged_into_incident_id]",
        ),
    )
    merged_incidents: List["Incident"] = Relationship(
        back_populates="merged_into",
        sa_relationship_kwargs=dict(
            foreign_keys="[Incident.merged_into_incident_id]",
        ),
    )

    # @tb: _alerts is Alert, not explicitly typed because of circular dependency
    _alerts: List = PrivateAttr(default_factory=list)
    _enrichments: dict = PrivateAttr(default={})

    class Config:
        arbitrary_types_allowed = True

    __table_args__ = (
        Index(
            "ix_incident_tenant_running_number",
            "tenant_id",
            "running_number",
            unique=True,
            postgresql_where=text("running_number IS NOT NULL"),  # For PostgreSQL
            sqlite_where=text("running_number IS NOT NULL"),  # For SQLite
        ),
    )

    @property
    def alerts(self):
        if hasattr(self, "_alerts"):
            return self._alerts
        else:
            return []

    @property
    def enrichments(self):
        return getattr(self, "_enrichments", {})

    def set_enrichments(self, enrichments):
        self._enrichments = enrichments

    def is_dismiss_active(self, now: datetime | None = None) -> bool:
        """Whether this incident's dismissal is in force right now.

        A permanent dismissal always is. A time-boxed one only until
        `dismissed_until` passes — and nothing rewrites the row at that moment,
        so callers must ask rather than trust a stored status.
        """
        return is_dismiss_active(self.dismiss_mode, self.dismissed_until, now)

    def get_effective_status(self, now: datetime | None = None) -> str:
        """The status to show callers: `suppressed` while a dismissal is live,
        otherwise the underlying stored status it will revert to."""
        if self.is_dismiss_active(now):
            return IncidentStatus.SUPPRESSED.value
        return self.status


@retry(exceptions=(IntegrityError,), tries=3, delay=0.1, backoff=2, jitter=(0, 0.1))
def get_next_running_number(session, tenant_id: str) -> int:
    """Get the next running number for a tenant."""
    try:
        # Get the maximum running number for the tenant
        result = session.exec(
            select(func.max(Incident.running_number)).where(
                Incident.tenant_id == tenant_id
            )
        ).first()

        # If no incidents exist yet, start from 1
        next_number = (result or 0) + 1
        return next_number
    except IntegrityError:
        session.rollback()
        # Refresh the session's view of the data
        session.expire_all()
        raise
