# Local API reference

Base URL: `http://127.0.0.1:8000`. Machine-readable schema: `/openapi.json`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/health` | Process/database readiness and application version |
| GET | `/api/meta` | Rules, settings, configuration hash, ingestion limits |
| GET | `/api/dashboard` | Full dataset aggregates and chart data |
| GET | `/api/events` | Event search and pagination |
| GET | `/api/alerts` | Filtered alert queue and pagination |
| GET | `/api/alerts/{id}` | Full evidence, configuration, and activity journal |
| PATCH | `/api/alerts/{id}` | Change status and/or append a note |
| POST | `/api/ingest` | Multipart file upload with a `file` field |
| POST | `/api/demo` | Idempotently import built-in synthetic events |
| POST | `/api/detections/run` | Replay current detection configuration |
| GET | `/api/imports` | Latest 20 successful import records |
| GET | `/api/reports/json` | Full filtered JSON report |
| GET | `/api/reports/html` | Standalone HTML report |
| GET | `/api/reports/markdown` | Markdown report |
| GET | `/api/samples/csv` | Download the safe CSV sample |
| GET | `/api/samples/json` | Download the safe JSON sample |

## Read queries

Alerts and reports accept `severity`, `status`, `source_ip`, `username`, `rule_id`, `q`, `start`, and `end`. All filters combine with AND. Source and username search membership in all evidence; the username comparison is case-sensitive. `q` is a case-insensitive literal substring in rule name, explanation, host, and service. It does not interpret SQL wildcards.

Dates need a timezone or `Z`, have inclusive endpoints, and match `last_seen` evidence time. Alert pagination accepts `limit=1..100` and `offset>=0`. The queue sorts severity first, then last evidence descending. Reports use the same filters and export **all** matching rows regardless of pagination.

Events accept `q` over IP/account/host/service/event ID, `event_type` (`authentication_success` or `authentication_failure`), and the same pagination bounds. The event explorer sorts latest event time first.

```bash
curl 'http://127.0.0.1:8000/api/alerts?severity=critical&status=New'
curl 'http://127.0.0.1:8000/api/alerts?rule_id=SOC-004&username=staff_01'
```

## Mutation requests

Mutations require `X-SOC-Client: dashboard`. Cross-origin mutations are rejected; no permissive CORS is enabled. This is a local request-integrity boundary, not authentication.

```bash
curl -X POST -H 'X-SOC-Client: dashboard' http://127.0.0.1:8000/api/demo
curl -X POST -H 'X-SOC-Client: dashboard' \
  -F 'file=@sample_data/security_events.csv' http://127.0.0.1:8000/api/ingest
```

Get the case before updating it and use the returned `version`:

```bash
curl http://127.0.0.1:8000/api/alerts/7
curl -X PATCH -H 'X-SOC-Client: dashboard' -H 'Content-Type: application/json' \
  -d '{"version":1,"status":"Investigating","note":"Reviewed matched evidence; ownership validation pending."}' \
  http://127.0.0.1:8000/api/alerts/7
```

Case IDs depend on the dataset, so inspect the queue rather than hard-coding ID 7. The API uses integer IDs and displays a friendly `ALR-0007` label. A status update with the same current status and no note is a no-op; it does not add an artificial journal entry.

## Error semantics

| HTTP status | Meaning |
| --- | --- |
| 400 | Untrusted Host header |
| 403 | Missing mutation header or disallowed Origin |
| 404 | Unknown alert or route |
| 409 | Stale analyst case revision |
| 422 | Invalid schema, query, file, format, event conflict, or dataset limit |

Validation errors report field-level reasons and do not echo uploaded event contents. Invalid ingestion does not leave partial events or import rows.
