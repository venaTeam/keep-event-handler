from typing import Any

from pydantic import BaseModel

from models.alert import AlertDto, AlertWithIncidentLinkMetadataDto
from models.db.enrichment_event import EnrichmentEvent
from models.incident import IncidentDto


class PaginatedResultsDto(BaseModel):
    limit: int = 25
    offset: int = 0
    count: int
    items: list[Any]


class IncidentsPaginatedResultsDto(PaginatedResultsDto):
    items: list[IncidentDto]


class AlertPaginatedResultsDto(PaginatedResultsDto):
    items: list[AlertDto]


class EnrichmentEventPaginatedResultsDto(PaginatedResultsDto):
    items: list[EnrichmentEvent]


class AlertWithIncidentLinkMetadataPaginatedResultsDto(PaginatedResultsDto):
    items: list[AlertWithIncidentLinkMetadataDto]
