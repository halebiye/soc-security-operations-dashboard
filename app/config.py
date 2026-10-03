"""Validated configuration; no secrets or external threat feeds."""

import json
import os
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, model_validator

ROOT = Path(__file__).resolve().parent.parent


class DetectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    failure_threshold: int = Field(default=5, ge=2, le=1000)
    failure_window_seconds: int = Field(default=300, ge=1, le=86400)
    success_window_seconds: int = Field(default=600, ge=1, le=86400)
    spray_account_threshold: int = Field(default=4, ge=2, le=1000)
    spray_window_seconds: int = Field(default=600, ge=1, le=86400)
    spike_threshold: int = Field(default=20, ge=2, le=10000)
    spike_window_seconds: int = Field(default=60, ge=1, le=86400)
    aggregation_seconds: int = Field(default=900, ge=60, le=86400)
    privileged_accounts: list[str] = Field(default_factory=lambda: ["root", "admin", "svc_backup"])
    suspicious_ips: list[str] = Field(default_factory=lambda: ["203.0.113.66"])
    business_timezone: str = "Europe/Istanbul"
    business_start_hour: int = Field(default=9, ge=0, le=23)
    business_end_hour: int = Field(default=18, ge=1, le=24)
    business_weekdays: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4])

    @model_validator(mode="after")
    def validate_settings(self):
        from app.models import safe_ip

        try:
            ZoneInfo(self.business_timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("Unknown business timezone") from exc
        if self.business_start_hour >= self.business_end_hour:
            raise ValueError("Business start must precede end (overnight schedules unsupported)")
        if not self.business_weekdays or any(d not in range(7) for d in self.business_weekdays):
            raise ValueError("Business weekdays must be between 0 and 6")
        self.suspicious_ips = [safe_ip(ip) for ip in self.suspicious_ips]
        self.privileged_accounts = [name.casefold() for name in self.privileged_accounts]
        return self


def load_config(path: Path | None = None) -> DetectionConfig:
    target = path or Path(os.getenv("SOC_CONFIG_PATH", str(ROOT / "config/detection.json")))
    return DetectionConfig.model_validate(json.loads(target.read_text(encoding="utf-8")))


def database_path() -> Path:
    return Path(os.getenv("SOC_DB_PATH", str(ROOT / "data/soc.sqlite3")))
