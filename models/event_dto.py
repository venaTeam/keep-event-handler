from pydantic import BaseModel
from typing import Optional, Dict, Any
from enum import Enum

class EventType(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"

class EventDTO(BaseModel):
    tenant_id: str
    event: Dict[str, Any]
    trace_id: Optional[str] = None
    provider_type: Optional[str] = None
    provider_id: Optional[str] = None
    fingerprint: Optional[str] = None
    api_key_name: Optional[str] = None
    provider_name: Optional[str] = None
    timestamp_forced: Optional[str] = None
    notify_client: bool = True
    event_type: Optional[EventType] = EventType.ALERT
