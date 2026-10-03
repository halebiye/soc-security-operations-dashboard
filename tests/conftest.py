from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import DetectionConfig
from app.main import create_app
from app.models import SecurityEvent


@pytest.fixture
def config():
    return DetectionConfig()


@pytest.fixture
def make_event():
    counter = 0

    def make(
        seconds=0,
        event_type="authentication_failure",
        source_ip="198.51.100.42",
        username="muhammed",
        hostname="vpn-gw-01",
        service="vpn",
        **overrides,
    ):
        nonlocal counter
        counter += 1
        event = {
            "event_id": f"test-{counter:05d}",
            "timestamp": (
                datetime(2026, 10, 1, 9, tzinfo=timezone.utc) + timedelta(seconds=seconds)
            ).isoformat(),
            "event_type": event_type,
            "source_ip": source_ip,
            "username": username,
            "hostname": hostname,
            "service": service,
            "synthetic": True,
            **overrides,
        }
        return {"id": counter, **SecurityEvent.model_validate(event).record()}

    return make


@pytest.fixture
def client(tmp_path, config):
    with TestClient(create_app(tmp_path / "test.sqlite3", config)) as test_client:
        yield test_client


@pytest.fixture
def headers():
    return {"X-SOC-Client": "dashboard"}
