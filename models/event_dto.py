from pydantic import BaseModel, validator
from typing import Optional, Dict, Any

class EventDTO(BaseModel):
    tenant_id: str
    event: Dict[str, Any]
    trace_id: Optional[str] = None
    provider_type: Optional[str] = None
    provider_id: Optional[str] = None
    fingerprint: Optional[Any] = None
    api_key_name: Optional[str] = None
    provider_name: Optional[str] = None
    timestamp_forced: Optional[str] = None
    notify_client: bool = True
    
    @validator("fingerprint", pre=True)
    def validate_fingerprint(cls, v):
        if v is not None:
            return str(v)
        return v
