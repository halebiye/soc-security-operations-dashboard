"""Input contract, timestamp normalization, and synthetic-data boundary."""

from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import ip_address, ip_network

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DOCUMENTATION_NETWORKS = tuple(
    ip_network(cidr) for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def safe_ip(value: str) -> str:
    address = ip_address(value)
    if not any(address in network for network in DOCUMENTATION_NETWORKS):
        raise ValueError("Only documentation-range synthetic IP addresses are accepted")
    return str(address)


def utc_datetime(value: str | datetime) -> datetime:
    if not isinstance(value, (str, datetime)):
        raise ValueError("Timestamp must be an ISO 8601 string or datetime")
    date = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if date.tzinfo is None or date.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone offset or Z")
    return date.astimezone(timezone.utc)


def iso_utc(value: str | datetime) -> str:
    # Uniform width makes indexed SQLite TEXT timestamp comparisons correct.
    return utc_datetime(value).isoformat(timespec="microseconds")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(StrEnum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    CLOSED = "Closed"


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    timestamp: datetime
    source_ip: str
    username: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=100)
    service: str = Field(min_length=1, max_length=60)
    event_type: str
    synthetic: bool

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, value):
        return utc_datetime(value)

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, value):
        return safe_ip(value)

    @field_validator("event_type")
    @classmethod
    def validate_type(cls, value):
        if value not in {"authentication_success", "authentication_failure"}:
            raise ValueError("Supported event types: authentication_success, authentication_failure")
        return value

    @field_validator("synthetic", mode="before")
    @classmethod
    def require_synthetic(cls, value):
        if value is not True and value != "true":
            raise ValueError("synthetic must be true; real log ingestion is not supported")
        return True

    @field_validator("username", "hostname", "service")
    @classmethod
    def reject_control_characters(cls, value):
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Control characters are not allowed")
        return value

    def record(self) -> dict:
        record = self.model_dump()
        record["timestamp"] = iso_utc(self.timestamp)
        return record


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1)
    status: Status | None = None
    note: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def require_change(self):
        if self.note is not None:
            self.note = self.note.strip()
        if self.status is None and not self.note:
            raise ValueError("Provide a status or a nonempty note")
        return self


class AlertFilters(BaseModel):
    severity: Severity | None = None
    status: Status | None = None
    source_ip: str | None = None
    username: str | None = Field(default=None, max_length=100)
    rule_id: str | None = Field(default=None, pattern=r"^SOC-00[1-7]$")
    q: str | None = Field(default=None, max_length=200)
    start: datetime | None = None
    end: datetime | None = None

    @field_validator("source_ip")
    @classmethod
    def validate_source(cls, value):
        return safe_ip(value) if value else None

    @field_validator("start", "end", mode="before")
    @classmethod
    def normalize_date(cls, value):
        return utc_datetime(value) if value is not None else None

    @model_validator(mode="after")
    def ordered_dates(self):
        if self.start and self.end and self.start > self.end:
            raise ValueError("Start must be before or equal to end")
        return self
