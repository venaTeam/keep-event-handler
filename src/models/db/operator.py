from datetime import datetime
from uuid import uuid4

from sqlmodel import Field, SQLModel, UniqueConstraint


class Operator(SQLModel, table=True):
    # Keep-owned routing key. `name` is the value carried on alert.operator and
    # routes an alert to its tenant. `group` is the Keycloak group the operator
    # belongs to and is globally unique -- a group backs at most one operator,
    # across every tenant. `apikey` is a server-generated id issued at creation.
    # See VENA-5596 design §3.2 / spec-tenant-creation-api.md.
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(index=True)
    group: str = Field(index=True)
    # An operator is always attached to a tenant -- it is created for an existing
    # tenant (POST /operators), never orphaned.
    tenant_id: str = Field(foreign_key="tenant.id")
    apikey: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("name", name="uq_operator_name"),
        UniqueConstraint("group", name="uq_operator_group"),
        UniqueConstraint("apikey", name="uq_operator_apikey"),
    )