"""Stable B5 values shared by the producer, metrics, and DLQ envelope."""

from enum import StrEnum


class PublishOutcome(StrEnum):
    MATCHED = "matched"
    DLQ = "dlq"
    UNRESOLVED = "unresolved"


class DeliveryResult(StrEnum):
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"


class DlqRecordType(StrEnum):
    DELIVERY = "delivery"
    CONTRACT_REJECTION = "contract_rejection"


class DlqHeader(StrEnum):
    VERSION = "matched-dlq-version"
    RECORD_TYPE = "record-type"
    ORIGINAL_TOPIC = "original-topic"
    ERROR_CLASS = "error-class"
    ERROR_DETAIL = "error-detail"


DEFAULT_DLQ_TOPIC = "matched-alerts-dlq"
