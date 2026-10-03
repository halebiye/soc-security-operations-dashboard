import random

import pytest

from app.config import DetectionConfig
from app.demo import generate_events
from app.detection import catalog, config_hash, detect
from app.models import SecurityEvent


def matches(events, config, rule_id):
    return [alert for alert in detect(events, config) if alert["rule_id"] == rule_id]


def test_failure_threshold_and_full_evidence(make_event, config):
    events = [make_event(i * 10) for i in range(4)]
    assert not matches(events, config, "SOC-001")
    events.append(make_event(40))
    alerts = matches(events, config, "SOC-001")
    assert len(alerts) == 1
    assert alerts[0]["evidence_count"] == 5
    assert alerts[0]["evidence_ids"] == [event["id"] for event in events]
    assert "5 failed logins" in alerts[0]["explanation"]
    assert alerts[0]["recommendation"]


@pytest.mark.parametrize("last_second,expected", [(300, 1), (301, 0)])
def test_failure_window_inclusive_boundary(make_event, config, last_second, expected):
    events = [make_event(i) for i in range(4)] + [make_event(last_second)]
    assert len(matches(events, config, "SOC-001")) == expected


@pytest.mark.parametrize(
    "field,value",
    [("source_ip", "198.51.100.43"), ("username", "omar"), ("hostname", "vpn-gw-02"), ("service", "ssh")],
)
def test_failure_and_success_do_not_join_different_entities(make_event, config, field, value):
    events = [make_event(i) for i in range(5)]
    events.append(make_event(10, event_type="authentication_success", **{field: value}))
    assert not matches(events, config, "SOC-002")


@pytest.mark.parametrize("last_second,expected", [(600, 1), (601, 0)])
def test_success_window_boundary(make_event, config, last_second, expected):
    events = [make_event(i) for i in range(5)]
    events.append(make_event(last_second, event_type="authentication_success"))
    assert len(matches(events, config, "SOC-002")) == expected


def test_success_clears_failure_streak(make_event, config):
    events = [make_event(i) for i in range(5)]
    events += [
        make_event(10, event_type="authentication_success"),
        make_event(20, event_type="authentication_success"),
    ]
    alerts = matches(events, config, "SOC-002")
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["evidence_count"] == 6


@pytest.mark.parametrize(
    "username,event_type,expected",
    [
        ("ADMIN", "authentication_success", 1),
        ("root", "authentication_success", 1),
        ("svc_backup", "authentication_success", 1),
        ("user_admin", "authentication_success", 0),
        ("admin", "authentication_failure", 0),
    ],
)
def test_privileged_rule_is_exact_case_insensitive_success_only(
    make_event, config, username, event_type, expected
):
    assert len(matches([make_event(username=username, event_type=event_type)], config, "SOC-003")) == expected


def test_distinct_accounts_not_number_of_attempts(make_event, config):
    events = [make_event(i, username="one_account") for i in range(8)]
    assert not matches(events, config, "SOC-004")
    events += [make_event(20 + i, username=f"account_{i}") for i in range(3)]
    assert len(matches(events, config, "SOC-004")) == 1


def test_spray_sources_do_not_mix(make_event, config):
    events = [make_event(i, username=f"account_{i}", source_ip=f"198.51.100.{i + 1}") for i in range(4)]
    assert not matches(events, config, "SOC-004")


@pytest.mark.parametrize(
    "timestamp,expected",
    [
        ("2026-10-01T08:59:59+03:00", 1),
        ("2026-10-01T09:00:00+03:00", 0),
        ("2026-10-01T17:59:59+03:00", 0),
        ("2026-10-01T18:00:00+03:00", 1),
        ("2026-10-03T12:00:00+03:00", 1),
        ("2026-10-01T06:00:00Z", 0),
    ],
)
def test_business_hours_timezone_end_and_weekend(make_event, config, timestamp, expected):
    event = make_event(event_type="authentication_success", timestamp=timestamp)
    assert len(matches([event], config, "SOC-005")) == expected


def test_out_of_hours_failure_does_not_trigger(make_event, config):
    event = make_event(timestamp="2026-10-03T01:00:00Z")
    assert not matches([event], config, "SOC-005")


@pytest.mark.parametrize("source,expected", [("203.0.113.66", 1), ("203.0.113.67", 0)])
def test_synthetic_watchlist(make_event, config, source, expected):
    assert len(matches([make_event(source_ip=source)], config, "SOC-006")) == expected


@pytest.mark.parametrize("last_second,expected", [(60, 1), (61, 0)])
def test_spike_boundary_and_mixed_outcomes(make_event, config, last_second, expected):
    events = [make_event(i, event_type="authentication_success") for i in range(19)] + [
        make_event(last_second)
    ]
    assert len(matches(events, config, "SOC-007")) == expected


def test_rate_matches_aggregate_evidence_with_latest_trigger(make_event, config):
    events = [make_event(i, username=f"staff_{i}") for i in range(12)]
    alerts = matches(events, config, "SOC-004")
    assert len(alerts) == 1
    assert alerts[0]["evidence_count"] == 12
    assert alerts[0]["username"] == "staff_11"


def test_rolling_detection_crosses_aggregation_bucket(make_event, config):
    events = [make_event(890 + i * 5) for i in range(5)]
    alerts = matches(events, config, "SOC-001")
    assert len(alerts) == 1
    assert alerts[0]["evidence_count"] == 5


def test_equal_time_failures_before_success_and_deterministic_input_order(make_event, config):
    events = [make_event() for _ in range(5)] + [make_event(event_type="authentication_success")]
    expected = detect(events, config)
    random.Random(7).shuffle(events)
    assert detect(events, config) == expected
    assert len(matches(events, config, "SOC-002")) == 1


def test_config_changes_have_distinct_provenance(make_event, config):
    events = [make_event(i) for i in range(8)]
    other = config.model_copy(update={"failure_threshold": 6})
    assert config_hash(config) != config_hash(other)
    first = matches(events, config, "SOC-001")[0]
    second = matches(events, other, "SOC-001")[0]
    assert first["fingerprint"] != second["fingerprint"]
    assert first["rule_parameters"]["failure_threshold"] == 5


def test_demo_expected_counts_and_all_rules(config):
    events = [
        {"id": i, **SecurityEvent.model_validate(e).record()} for i, e in enumerate(generate_events(), 1)
    ]
    alerts = detect(events, config)
    assert len(events) == 553
    assert len(alerts) == 18
    assert {a["rule_id"] for a in alerts} == {r["id"] for r in catalog(config)}
    assert sum(a["severity"] == "critical" for a in alerts) == 2


@pytest.mark.parametrize(
    "update",
    [
        {"failure_threshold": 1},
        {"business_timezone": "No/Timezone"},
        {"business_start_hour": 19},
        {"business_weekdays": [7]},
        {"suspicious_ips": ["8.8.8.8"]},
    ],
)
def test_invalid_detection_config_rejected(update):
    with pytest.raises(ValueError):
        DetectionConfig(**update)
