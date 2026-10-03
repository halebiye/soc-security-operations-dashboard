import csv
import io
import json

import pytest

from app.demo import generate_events
from app.ingestion import EVENT_FIELDS, MAX_UPLOAD_BYTES, ImportErrorDetail, parse_upload
from app.models import SecurityEvent, iso_utc


def sample():
    return generate_events()[0]


def test_csv_json_normalize_identically():
    event = sample()
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=EVENT_FIELDS)
    writer.writeheader()
    writer.writerow({**event, "synthetic": "true"})
    assert parse_upload(stream.getvalue().encode(), "test.csv") == parse_upload(
        json.dumps([event]).encode(), "test.json"
    )


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("192.0.2.1", "192.0.2.1"),
        ("198.51.100.42", "198.51.100.42"),
        ("203.0.113.66", "203.0.113.66"),
        ("2001:0db8:0000::1", "2001:db8::1"),
    ],
)
def test_documentation_ipv4_ipv6(ip, expected):
    assert SecurityEvent.model_validate({**sample(), "source_ip": ip}).source_ip == expected


@pytest.mark.parametrize(
    "update",
    [
        {"source_ip": "8.8.8.8"},
        {"source_ip": "127.0.0.1"},
        {"source_ip": "10.0.0.1"},
        {"source_ip": "not-an-ip"},
        {"synthetic": False},
        {"synthetic": 1},
        {"synthetic": "false"},
        {"timestamp": "2026-10-01T12:00:00"},
        {"timestamp": "bad"},
        {"timestamp": 123},
        {"event_type": "process_start"},
        {"username": ""},
        {"hostname": "host\nname"},
        {"service": "vpn\x00"},
        {"password": "must-not-be-accepted"},
        {"event_id": "unsafe id"},
    ],
)
def test_invalid_row_rejects_whole_import_without_echoing_secrets(update):
    content = json.dumps([sample(), {**sample(), **update}]).encode()
    with pytest.raises(ImportErrorDetail, match="Event 2") as error:
        parse_upload(content, "test.json")
    assert "must-not-be-accepted" not in str(error.value)


@pytest.mark.parametrize(
    "content,filename",
    [
        (b"[]", "test.json"),
        (b"{}", "test.json"),
        (b"{invalid", "test.json"),
        (b"\xff\xff", "test.json"),
        (b"header\nvalue", "test.csv"),
        (b"anything", "test.exe"),
    ],
)
def test_invalid_file(content, filename):
    with pytest.raises(ImportErrorDetail):
        parse_upload(content, filename)


def test_upload_size_limit():
    with pytest.raises(ImportErrorDetail, match="5 MiB"):
        parse_upload(b"a" * (MAX_UPLOAD_BYTES + 1), "test.json")


def test_event_count_limit():
    with pytest.raises(ImportErrorDetail, match="5000"):
        parse_upload(json.dumps([sample()] * 5001).encode(), "test.json")


def test_duplicate_csv_column_rejected():
    content = (",".join(EVENT_FIELDS + ("event_id",)) + "\n").encode()
    with pytest.raises(ImportErrorDetail, match="Duplicate CSV"):
        parse_upload(content, "test.csv")


def test_bom_unicode_and_timezone_normalization():
    event = {**sample(), "username": "محمد", "timestamp": "2026-10-01T12:00:00+03:00"}
    row = parse_upload(b"\xef\xbb\xbf" + json.dumps([event]).encode(), "TEST.JSON")[0]
    assert row["username"] == "محمد"
    assert row["timestamp"] == "2026-10-01T09:00:00.000000+00:00"
    assert iso_utc("2026-10-01T09:00:00.000001Z") > row["timestamp"]
