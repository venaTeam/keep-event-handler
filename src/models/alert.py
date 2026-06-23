from enum import Enum
import uuid
import json
import hashlib
import urllib
import logging
import datetime
from typing import Any, Dict, Optional
import pytz
from pydantic import AnyHttpUrl, BaseModel, Extra, Field, root_validator, validator

logger = logging.getLogger(__name__)

def get_fingerprint(fingerprint, values):
    # if its none, use the name
    if fingerprint is None:
        fingerprint_payload = values.get("name")
        # if the alert name is None, than use the entire payload
        if not fingerprint_payload:
            logger.warning("No name to alert, using the entire payload")
            fingerprint_payload = json.dumps(values)
        fingerprint = hashlib.sha256(fingerprint_payload.encode()).hexdigest()
    # take only the first 255 characters
    else:
        fingerprint = fingerprint[:255]
    return fingerprint

    
class AlertStatus(Enum):
    # Active alert
    FIRING = "firing"
    # Alert has been resolved
    RESOLVED = "resolved"
    # Alert has been acknowledged but not resolved
    ACKNOWLEDGED = "acknowledged"
    # Alert is suppressed due to various reasons
    SUPPRESSED = "suppressed"
    # No Data
    PENDING = "pending"
    # Affected by Maintenance Windows
    MAINTENANCE = "maintenance"

class AlertEnvironment(str, Enum):
    PRODUCTION = "production"
    INTEGRATION = "integration"
    LOAD = "load"
    DEVELOPMENT = "development"
    TEST = "test"

class DeduplicationRuleRequestDto(BaseModel):
    name: str
    description: Optional[str] = None
    provider_type: str
    provider_id: Optional[str] = None
    fingerprint_fields: list[str]
    full_deduplication: bool = False
    ignore_fields: Optional[list[str]] = None

class DeduplicationRuleDto(BaseModel):
    id: str | None 
    name: str
    description: str
    default: bool
    distribution: list[dict]  # list of {hour: int, count: int}
    provider_id: str | None  # None for default rules
    provider_type: str
    last_updated: str | None
    last_updated_by: str | None
    created_at: str | None
    created_by: str | None
    ingested: int
    dedup_ratio: float
    enabled: bool
    fingerprint_fields: list[str]
    full_deduplication: bool
    ignore_fields: list[str]
    is_provisioned: bool

class SeverityBaseInterface(Enum):
    def __new__(cls, severity_name, severity_order):
        obj = object.__new__(cls)
        obj._value_ = severity_name
        obj.severity_order = severity_order
        return obj

    @property
    def order(self):
        return self.severity_order

    def __str__(self):
        return self._value_

    @classmethod
    def from_number(cls, n):
        for severity in cls:
            if severity.order == n:
                return severity
        raise ValueError(f"No AlertSeverity with order {n}")

    def __lt__(self, other):
        if isinstance(other, SeverityBaseInterface):
            return self.order < other.order
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, SeverityBaseInterface):
            return self.order <= other.order
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, SeverityBaseInterface):
            return self.order > other.order
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, SeverityBaseInterface):
            return self.order >= other.order
        return NotImplemented


class AlertSeverity(SeverityBaseInterface):
    CRITICAL = ("critical", 5)
    HIGH = ("high", 4)
    WARNING = ("warning", 3)
    INFO = ("info", 2)
    LOW = ("low", 1)



class AlertDto(BaseModel):
    id: str | None
    name: str
    status: AlertStatus
    severity: AlertSeverity
    last_received: str = Field(default=None, alias="lastReceived")
    firing_start_time: str | None = Field(default=None, alias="firingStartTime")
    firing_start_time_since_last_resolved: str | None = Field(default=None, alias="firingStartTimeSinceLastResolved")
    firing_counter: int = Field(default=0, alias="firingCounter")
    unresolved_counter: int = Field(default=0, alias="unresolvedCounter")
    is_full_duplicate: bool | None = Field(default=False, alias="isFullDuplicate")
    is_partial_duplicate: bool | None = Field(default=False, alias="isPartialDuplicate")
    duplicate_reason: str | None = Field(default=None, alias="duplicateReason")
    source: list[str] | None = []
    service: str | None = None
    application: str | None = None
    object: str | None = None
    node_name: str | None = None
    operator: str | None = None
    time_created: str | None = None
    network: str | None = None
    timezone: str | None = None
    custom_key: str | None = None
    expiry_in_minutes: int | None = None
    key_field: str | None = None
    component: str | None = None
    site: str | None = None
    impact: str | None = None
    runbook_url: str | None = None
    alert_rule_url: str | None = None
    description: str | None = None
    fingerprint: str | None = (
        None  # The fingerprint of the alert (used for alert de-duplication)
    )
    dismiss_until: str | None = Field(default=None, alias="dismissUntil")  # The time until the alert is dismissed
    assignee: str | None = None  # The assignee of the alert
    provider_id: str | None = Field(default=None, alias="providerId")  # The provider id
    provider_type: str | None = Field(default=None, alias="providerType")  # The provider type
    note: str | None = None  # The note of the alert
    started_at: str | None = Field(
        default=None, alias="startedAt"  # The time the alert started
    )
    environment: str = Field(default=AlertEnvironment.PRODUCTION.value)




    incident: str | None = None

    @validator("id", pre=True)
    def parse_id(cls, v):
        if v is not None:
            return str(v)
        return v

    @validator("source", pre=True)
    def parse_source(cls, v):
        if isinstance(v, str):
            try:
                import json
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
            return [v]
        return v



    def __str__(self) -> str:
        # Convert the model instance to a dictionary
        model_dict = self.dict()
        return json.dumps(model_dict, indent=4, default=str)

    def __eq__(self, other):
        if isinstance(other, AlertDto):
            # Convert both instances to dictionaries
            dict_self = self.dict()
            dict_other = other.dict()

            # Fields to exclude from comparison since they are bit different in different db's
            # todo: solve it in a better way
            exclude_fields = {"last_received", "started_at", "event_id"}

            # Remove excluded fields from both dictionaries
            for field in exclude_fields:
                dict_self.pop(field, None)
                dict_other.pop(field, None)

            # Compare the dictionaries
            return dict_self == dict_other
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @validator("fingerprint", pre=True, always=True)
    def assign_fingerprint_if_none(cls, fingerprint, values):
        return get_fingerprint(fingerprint, values)

    @validator("last_received", pre=True, always=True)
    def validate_last_received(cls, last_received):
        def convert_to_iso_format(date_string):
            try:
                dt = datetime.datetime.fromisoformat(date_string)
                dt_utc = dt.astimezone(pytz.UTC)
                return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            except ValueError:
                return None

        def parse_unix_timestamp(timestamp_string):
            try:
                # Remove trailing 'Z' if present
                timestamp_string = timestamp_string.rstrip("Z")
                # Convert string to float
                timestamp = float(timestamp_string)
                # Create datetime from timestamp
                dt = datetime.datetime.fromtimestamp(
                    timestamp, tz=datetime.timezone.utc
                )
                return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            except (ValueError, TypeError):
                return None

        if not last_received:
            return datetime.datetime.now(datetime.timezone.utc).isoformat()

        # ORM column is TIMESTAMPTZ — datetime arrives directly from SQLAlchemy
        if isinstance(last_received, datetime.datetime):
            dt_utc = (
                last_received.astimezone(pytz.UTC)
                if last_received.tzinfo is not None
                else last_received.replace(tzinfo=pytz.UTC)
            )
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Try to convert the date to iso format
        # see: https://github.com/keephq/keep/issues/1397
        iso_date = convert_to_iso_format(last_received)
        if iso_date:
            return iso_date

        # Try to parse as UNIX timestamp
        unix_date = parse_unix_timestamp(last_received)
        if unix_date:
            return unix_date

        raise ValueError(f"Invalid date format: {last_received}")

    @root_validator(pre=True)
    def set_default_values(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        # Check and set id:
        if not values.get("id"):
            values["id"] = str(uuid.uuid4())

        # Component <-> Object sync (mutually exclusive in payload per spec)
        component = values.get("component")
        obj = values.get("object")
        if component is not None and obj is None:
            values["object"] = component
        elif obj is not None and component is None:
            values["component"] = obj
        elif component is not None and obj is not None and component != obj:
            # Conflict — component takes precedence per spec
            values["object"] = component

        # Check and set default severity
        severity = values.get("severity")
        try:
            # if severity is int, convert it to AlertSeverity
            if isinstance(severity, int):
                values["severity"] = AlertSeverity.from_number(severity)
            else:
                values["severity"] = AlertSeverity(severity)
        except ValueError:
            logging.warning(
                f"Invalid severity value: {severity}, setting default.",
                extra={"event": values},
            )
            values["severity"] = AlertSeverity.INFO

        # Check and set default status
        status = values.get("status")
        try:
            values["status"] = AlertStatus(status)
        except ValueError:
            logging.warning(
                f"Invalid status value: {status}, setting default.",
                extra={"event": values},
            )
            values["status"] = AlertStatus.FIRING

        # Check and set default environment
        environment = values.get("environment")
        try:
            values["environment"] = AlertEnvironment(environment).value
        except ValueError:
            values["environment"] = AlertEnvironment.PRODUCTION.value

        # this is code duplication of enrichment_helpers.py and should be refactored
        last_received = values.get("last_received", None)
        if not last_received:
            last_received = datetime.datetime.now(datetime.timezone.utc).isoformat()
            values["last_received"] = last_received

        assignees = values.pop("assignees", None)
        # In some cases (for example PagerDuty) the assignees is list of dicts and we don't handle it atm.
        if assignees and isinstance(assignees, dict):
            # Try exact match first
            assignee = assignees.get(last_received)
            if not assignee:
                # Try normalized match
                try:
                    dt = datetime.datetime.fromisoformat(last_received.rstrip("Z"))
                    normalized_dt = dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
                    if not normalized_dt.endswith("Z"):
                        normalized_dt += "Z"
                    assignee = assignees.get(normalized_dt)
                except Exception:
                    pass
            values["assignee"] = assignee
        values.pop("deletedAt", None)
        return values

    # after root_validator to ensure that the values are set
    @root_validator(pre=False)
    def validate_status(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        return values

    class Config:
        allow_population_by_field_name = True
        extra = Extra.allow
        schema_extra = {
            "examples": [
                {
                    "id": "1234",
                    "name": "Pod 'api-service-production' lacks memory",
                    "status": "firing",
                    "last_received": "2021-01-01T00:00:00.000Z",
                    "environment": "production",
                    "duplicate_reason": None,
                    "service": "backend",
                    "source": ["prometheus"],
                    "description": "Due to the lack of memory, the pod 'api-service-production' is experiencing high error rate",
                    "severity": "critical",
                    "pushed": True,
                    "url": "https://www.keephq.dev?alertId=1234",
                    "labels": {
                        "pod": "api-service-production",
                        "region": "us-east-1",
                        "cpu": "88",
                        "memory": "100Mi",
                    },
                    "ticket_url": "https://www.keephq.dev?enrichedTicketId=456",
                    "fingerprint": "1234",
                }
            ]
        }
        use_enum_values = True
        json_encoders = {
            # Converts enums to their values for JSON serialization
            Enum: lambda v: v.value,
        }

class AlertWithIncidentLinkMetadataDto(AlertDto):
    is_created_by_ai: bool = False

    @classmethod
    def from_db_instance(cls, db_alert, db_alert_to_incident, payload=None):
        # Accept a pre-merged payload (with enrichments applied) so callers
        # don't silently lose enrichment overrides like resolved status.
        if payload is None:
            payload = db_alert.dict()

        return cls(
            is_created_by_ai=db_alert_to_incident.is_created_by_ai,
            **payload,
        )