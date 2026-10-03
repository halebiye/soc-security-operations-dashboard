import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.config import ROOT
from app.ingestion import ImportErrorDetail, parse_upload
from app.main import create_app
from app.models import AlertFilters, CaseUpdate
from app.storage import Repository


def seed(client, headers):
    response = client.post("/api/demo", headers=headers)
    assert response.status_code == 201
    return response.json()


def test_empty_health_summary_and_static_security(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/api/dashboard").json()["total_events"] == 0
    assert client.get("/api/alerts").json() == {"total": 0, "items": []}
    for path in ["/", "/alerts/1", "/static/app.js", "/static/styles.css", "/static/vendor/chart.umd.min.js"]:
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "script-src 'self'" in response.headers["content-security-policy"]
    assert client.get("/openapi.json").status_code == 200
    assert len(client.get("/api/meta").json()["rules"]) == 7


def test_demo_idempotence_and_csv_json_deduplication(client, headers):
    assert seed(client, headers)["alerts_created"] == 18
    duplicate = seed(client, headers)
    assert duplicate["imported"] == duplicate["alerts_created"] == 0
    assert duplicate["duplicates"] == 553
    for extension in ["csv", "json"]:
        path = ROOT / f"sample_data/security_events.{extension}"
        response = client.post("/api/ingest", headers=headers, files={"file": (path.name, path.read_bytes())})
        assert response.status_code == 201
        assert response.json()["duplicates"] == 553
        assert client.get(f"/api/samples/{extension}").status_code == 200
    s = client.get("/api/dashboard").json()
    assert (
        s["total_events"],
        s["total_alerts"],
        s["critical_alerts"],
        s["failed_logins"],
        s["unique_sources"],
    ) == (553, 18, 2, 94, 38)
    assert sum(row["success"] + row["failure"] for row in s["events_over_time"]) == 553
    assert s["severity"] == {"critical": 2, "high": 14, "medium": 2, "low": 0}
    assert len(client.get("/api/imports").json()["items"]) == 4
    assert client.post("/api/detections/run", headers=headers).json()["alerts_created"] == 0


def test_case_notes_status_restart_and_stale_version(client, headers, config):
    seed(client, headers)
    alert = client.get("/api/alerts?severity=critical").json()["items"][0]
    payload = {
        "version": alert["version"],
        "status": "Investigating",
        "note": "Checked MFA; validation pending.",
    }
    response = client.patch(f"/api/alerts/{alert['id']}", json=payload, headers=headers)
    assert response.status_code == 200
    changed = response.json()
    assert changed["version"] == 2
    assert changed["status"] == "Investigating"
    assert [a["kind"] for a in changed["activity"]] == ["created", "status", "note"]
    assert client.patch(f"/api/alerts/{alert['id']}", json=payload, headers=headers).status_code == 409
    seed(client, headers)
    assert client.get(f"/api/alerts/{alert['id']}").json()["version"] == 2
    with TestClient(create_app(client.app.state.repository.path, config)) as restarted:
        saved = restarted.get(f"/api/alerts/{alert['id']}").json()
        assert saved["status"] == "Investigating"
        assert saved["activity"][-1]["content"] == payload["note"]
    closed = client.patch(
        f"/api/alerts/{alert['id']}", json={"version": 2, "status": "Closed"}, headers=headers
    ).json()
    assert closed["status"] == "Closed"
    reopened = client.patch(
        f"/api/alerts/{alert['id']}", json={"version": 3, "status": "Investigating"}, headers=headers
    ).json()
    assert reopened["status"] == "Investigating"


def test_each_alert_filter_and_aggregate_evidence_membership(client, headers):
    seed(client, headers)
    critical = client.get("/api/alerts", params={"severity": "critical"}).json()
    assert critical["total"] == 2
    assert client.get("/api/alerts?rule_id=SOC-004&username=staff_01").json()["total"] == 1
    assert client.get("/api/alerts?source_ip=198.51.100.42&username=muhammed").json()["total"] == 2
    assert client.get("/api/alerts?status=Closed").json()["total"] == 0
    assert client.get("/api/alerts?q=watchlist").json()["total"] == 1
    assert client.get("/api/alerts?q=%25").json()["total"] == 0
    assert client.get("/api/alerts", params={"q": "' OR 1=1 --"}).json()["total"] == 0
    alert = critical["items"][0]
    response = client.get(
        "/api/alerts", params={"severity": "critical", "start": alert["last_seen"], "end": alert["last_seen"]}
    )
    assert response.json()["total"] == 1
    assert client.get("/api/alerts?start=2027-01-01T00:00:00Z").json()["total"] == 0
    page = client.get("/api/alerts?limit=1&offset=1").json()
    assert page["total"] == 18 and len(page["items"]) == 1


@pytest.mark.parametrize(
    "query",
    [
        "severity=extreme",
        "status=Deleted",
        "rule_id=SOC-008",
        "limit=0",
        "limit=101",
        "offset=-1",
        "source_ip=8.8.8.8",
        "source_ip=bad",
        "start=bad",
        "end=2026-10-01T12:00:00",
        "start=2027-01-01T00:00:00Z&end=2026-01-01T00:00:00Z",
    ],
)
def test_invalid_filters_are_422(client, query):
    assert client.get("/api/alerts?" + query).status_code == 422


def test_event_search_pagination_and_unknown_case(client, headers):
    seed(client, headers)
    assert client.get("/api/events?q=muhammed").json()["total"] > 9
    assert client.get("/api/events?event_type=authentication_failure").json()["total"] == 94
    assert len(client.get("/api/events?limit=3&offset=3").json()["items"]) == 3
    assert client.get("/api/events?event_type=malware").status_code == 422
    assert client.get("/api/alerts/99999").status_code == 404
    assert (
        client.patch(
            "/api/alerts/99999", headers=headers, json={"version": 1, "status": "Closed"}
        ).status_code
        == 404
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"version": 1},
        {"version": 0, "status": "Closed"},
        {"version": 1, "status": "Deleted"},
        {"version": 1, "note": " "},
        {"version": 1, "note": "x" * 2001},
        {"version": 1, "status": "Closed", "analyst": "Other user"},
    ],
)
def test_invalid_case_changes(client, headers, payload):
    assert client.patch("/api/alerts/1", json=payload, headers=headers).status_code == 422


def test_mutation_boundary_and_trusted_host(client, headers):
    assert client.post("/api/demo").status_code == 403
    assert client.post("/api/demo", headers={**headers, "Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/demo", headers={**headers, "Origin": "http://testserver"}).status_code == 201
    assert client.get("/health", headers={"Host": "evil.example"}).status_code == 400


def test_invalid_ingestion_no_partial_state(client, headers):
    response = client.post("/api/ingest", headers=headers, files={"file": ("bad.json", b"[{}]")})
    assert response.status_code == 422
    assert client.get("/api/dashboard").json()["total_events"] == 0
    assert client.get("/api/imports").json()["items"] == []


def test_event_id_conflict_rolls_back_prior_rows(client, headers):
    seed(client, headers)
    events = json.loads((ROOT / "sample_data/security_events.json").read_text())
    payload = [{**events[0], "event_id": "new-row"}, {**events[1], "username": "conflicting-content"}]
    response = client.post(
        "/api/ingest", headers=headers, files={"file": ("conflict.json", json.dumps(payload).encode())}
    )
    assert response.status_code == 422
    assert client.get("/api/dashboard").json()["total_events"] == 553
    assert client.get("/api/events?q=new-row").json()["total"] == 0


def test_ingestion_and_detection_are_one_transaction(client, config, monkeypatch, make_event):
    import app.storage as storage

    def broken_detector(*args):
        raise RuntimeError("Test-only detection failure")

    monkeypatch.setattr(storage, "detect", broken_detector)
    event = make_event()
    with pytest.raises(RuntimeError):
        client.app.state.repository.ingest([event], "test.json", config)
    assert client.get("/api/dashboard").json()["total_events"] == 0
    assert client.get("/api/imports").json()["items"] == []


def test_dataset_cap_rolls_back(client, config, monkeypatch, make_event):
    monkeypatch.setattr("app.storage.MAX_STORED_EVENTS", 2)
    with pytest.raises(ImportErrorDetail, match="limit"):
        client.app.state.repository.ingest([make_event(i) for i in range(3)], "test.json", config)
    assert client.get("/api/dashboard").json()["total_events"] == 0


def test_enriched_episode_preserves_analyst_work(client, config, make_event):
    repository = client.app.state.repository
    events = [make_event(i) for i in range(5)]
    repository.ingest(events, "part1.json", config)
    alert = repository.list_alerts(AlertFilters(rule_id="SOC-001"))["items"][0]
    repository.update_case(
        alert["id"], CaseUpdate(version=1, status="Closed", note="Reviewed the initial evidence.")
    )
    repository.ingest([make_event(10)], "part2.json", config)
    updated = repository.detail(alert["id"])
    assert updated["status"] == "Closed"
    assert updated["evidence_count"] == 6
    assert updated["version"] == 3
    assert updated["activity"][-1]["content"] == "Reviewed the initial evidence."
    assert repository.list_alerts(AlertFilters(rule_id="SOC-001"))["total"] == 1


def test_parallel_imports_are_serialized_and_idempotent(tmp_path, config):
    repository = Repository(tmp_path / "parallel.sqlite3")
    repository.initialize()
    events = parse_upload((ROOT / "sample_data/security_events.json").read_bytes(), "test.json")
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: repository.ingest(events, "test.json", config), range(2)))
    assert sum(result["imported"] for result in results) == 553
    assert sum(result["alerts_created"] for result in results) == 18
    assert repository.summary()["total_events"] == 553
