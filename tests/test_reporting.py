import json

import pytest

from app.models import AlertFilters
from app.reporting import render_report


def test_every_export_contains_full_matching_evidence_and_journal(client, headers):
    client.post("/api/demo", headers=headers)
    critical = client.get("/api/alerts?severity=critical").json()["items"][0]
    client.patch(
        f"/api/alerts/{critical['id']}",
        headers=headers,
        json={
            "version": 1,
            "status": "Investigating",
            "note": "MFA validation pending; user contacted in simulation.",
        },
    )
    for extension in ["html", "markdown", "json"]:
        response = client.get(f"/api/reports/{extension}?severity=critical")
        assert response.status_code == 200
        assert "attachment" in response.headers["content-disposition"]
        assert "MFA validation pending" in response.text
        assert "demo-" in response.text
        assert "T1110.001" in response.text
    data = client.get("/api/reports/json?severity=critical").json()
    assert data["alert_count"] == 2
    assert data["dataset_summary"]["total_events"] == 553
    assert all(a["severity"] == "critical" for a in data["alerts"])
    assert all(len(a["evidence"]) == a["evidence_count"] for a in data["alerts"])
    assert all(a["mitre_attack"][0]["id"] == "T1110.001" for a in data["alerts"])
    assert data["synthetic_only"] is True


def test_html_and_markdown_escape_untrusted_note_and_account(client, config, make_event):
    repository = client.app.state.repository
    event = make_event(
        username="<script>alert(1)</script>",
        event_type="authentication_success",
        timestamp="2026-10-03T00:00:00Z",
    )
    repository.ingest([event], "test.json", config)
    alert = repository.list_alerts(AlertFilters())["items"][0]
    from app.models import CaseUpdate

    repository.update_case(
        alert["id"], CaseUpdate(version=1, note='<img src=x onerror="alert(1)"> [link](javascript:alert(1))')
    )
    for extension in ["html", "markdown"]:
        text = client.get(f"/api/reports/{extension}").text
        assert "<script>" not in text and "<img src=x" not in text
        assert "&lt;script&gt;" in text
    json_export = client.get("/api/reports/json").json()
    assert json_export["alerts"][0]["evidence"][0]["username"] == event["username"]


def test_export_spans_all_pages(client, config, make_event):
    events = [make_event(i * 5, username="admin", event_type="authentication_success") for i in range(110)]
    client.app.state.repository.ingest(events, "test.json", config)
    assert len(client.get("/api/alerts?rule_id=SOC-003&limit=100").json()["items"]) == 100
    export = client.get("/api/reports/json?rule_id=SOC-003").json()
    assert export["alert_count"] == 110
    assert len(export["alerts"]) == 110


def test_empty_reports_and_unsupported_format(client):
    assert client.get("/api/reports/json").json()["alerts"] == []
    assert "No alerts match" in client.get("/api/reports/html").text
    assert client.get("/api/reports/pdf").status_code == 422
    with pytest.raises(ValueError):
        render_report({}, "pdf")


def test_reports_are_valid_utf8_json(client, config, make_event):
    event = make_event(username="محمد", event_type="authentication_success", timestamp="2026-10-03T00:00:00Z")
    client.app.state.repository.ingest([event], "test.json", config)
    content = client.get("/api/reports/json").content.decode("utf-8")
    assert "محمد" in content
    assert json.loads(content)["alert_count"] == 1
