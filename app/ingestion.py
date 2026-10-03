"""Parse entire bounded uploads before opening a write transaction."""

import csv
import io
import json

from pydantic import ValidationError

from app.models import SecurityEvent

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_IMPORT_EVENTS = 5000
MAX_STORED_EVENTS = 20000
EVENT_FIELDS = tuple(SecurityEvent.model_fields)


class ImportErrorDetail(ValueError):
    """A safe, actionable ingestion error suitable for API clients."""


def parse_upload(content: bytes, filename: str) -> list[dict]:
    if len(content) > MAX_UPLOAD_BYTES:
        raise ImportErrorDetail("Maximum file size is 5 MiB")
    extension = filename.rsplit(".", 1)[-1].lower()
    try:
        text = content.decode("utf-8-sig")
        if extension == "json":
            rows = json.loads(text)
            if not isinstance(rows, list):
                raise ImportErrorDetail("JSON must be an array of event objects")
        elif extension == "csv":
            reader = csv.DictReader(io.StringIO(text))
            if reader.fieldnames is None or set(reader.fieldnames) != set(EVENT_FIELDS):
                raise ImportErrorDetail("CSV header must contain exactly: " + ", ".join(EVENT_FIELDS))
            if len(reader.fieldnames) != len(EVENT_FIELDS):
                raise ImportErrorDetail("Duplicate CSV header names are not allowed")
            rows = list(reader)
        else:
            raise ImportErrorDetail("Upload a .csv or .json file")
    except (UnicodeDecodeError, json.JSONDecodeError, csv.Error) as exc:
        raise ImportErrorDetail("Invalid UTF-8 or malformed CSV/JSON") from exc

    if not rows or len(rows) > MAX_IMPORT_EVENTS:
        raise ImportErrorDetail("Each import must contain 1–5000 events")
    normalized = []
    for index, row in enumerate(rows, 1):
        try:
            normalized.append(SecurityEvent.model_validate(row).record())
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_url=False, include_context=False)
            summary = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'row'}: {e['msg']}" for e in errors[:3])
            raise ImportErrorDetail(f"Event {index}: {summary}") from exc
    return normalized
