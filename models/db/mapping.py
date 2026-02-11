from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String
from sqlmodel import JSON, Column, Field, SQLModel


class MappingRule(SQLModel, table=True):
    id: Optional[int] = Field(primary_key=True, default=None)
    tenant_id: str = Field(foreign_key="tenant.id")
    priority: int = Field(default=0, nullable=False)
    name: str = Field(max_length=255, nullable=False)
    description: Optional[str] = Field(max_length=2048)
    file_name: Optional[str] = Field(max_length=255)
    created_by: Optional[str] = Field(max_length=255)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    disabled: bool = Field(default=False)
    # Whether this rule should override existing attributes in the alert
    override: bool = Field(default=True)
    condition: Optional[str] = Field(max_length=2000)
    # The type of this mapping rule
    type: str = Field(
        sa_column=Column(
            String(255),
            name="type",
            server_default="csv",
        ),
        max_length=255,
    )
    # The attributes to match against (e.g. [["service","region"], ["pod"]])
    # Within a list it's AND, between lists it's OR: (service AND pod) OR pod
    matchers: list[list[str]] = Field(sa_column=Column(JSON))
    # The rows of the CSV file [{service: "service1", region: "region1", ...}, ...]
    rows: Optional[list[dict]] = Field(
        sa_column=Column(JSON),
    )  # max_length=204800)
    updated_by: Optional[str] = Field(max_length=255, default=None)
    last_updated_at: datetime = Field(default_factory=datetime.utcnow)
    # Multi-level mapping fields
    is_multi_level: bool = Field(default=False)
    new_property_name: Optional[str] = Field(max_length=255)
    prefix_to_remove: Optional[str] = Field(max_length=255)

