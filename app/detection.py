"""Pure, explainable detection replay; never performs network activity.

Rolling windows are inclusive. Rate-rule matches are combined into a stable
UTC 15-minute episode per entity; single-login rules use the event identity.
"""

import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime
from zoneinfo import ZoneInfo

from app.config import DetectionConfig
from app.models import utc_datetime

RULES = [
    {
        "id": "SOC-001",
        "name": "Repeated failed authentication",
        "severity": "high",
        "description": "A source repeatedly fails to authenticate to the same account, host, and service.",
        "recommendation": "Check the source and account with the owner. Review lockouts, MFA, and nearby logins; consider containment only after validation.",
        "false_positives": "Stale saved passwords, scheduled tasks, or a user struggling to sign in.",
        "mitre_attack": [{"id": "T1110.001", "name": "Password Guessing", "mapping": "direct"}],
        "mitre_attack_note": "Repeated failures against one account align with password-guessing behavior.",
    },
    {
        "id": "SOC-002",
        "name": "Success after repeated failures",
        "severity": "critical",
        "description": "A successful login follows repeated failures for the same source, account, host, and service.",
        "recommendation": "Prioritize triage. Verify the user's session, MFA result, and subsequent activity. Escalate a confirmed unexpected session and document the evidence.",
        "false_positives": "A legitimate user who finally enters the correct password.",
        "mitre_attack": [{"id": "T1110.001", "name": "Password Guessing", "mapping": "direct"}],
        "mitre_attack_note": "Repeated failures followed by success are a strong authentication pattern for password guessing triage.",
    },
    {
        "id": "SOC-003",
        "name": "Privileged account login",
        "severity": "high",
        "description": "An explicitly configured privileged account authenticates successfully.",
        "recommendation": "Validate the approved admin change window and source host. Check MFA and the actions performed in this session.",
        "false_positives": "Approved administration or a service account running an expected job.",
        "mitre_attack": [{"id": "T1078", "name": "Valid Accounts", "mapping": "contextual"}],
        "mitre_attack_note": "A privileged login can be legitimate; ATT&CK mapping is contextual until account misuse is validated.",
    },
    {
        "id": "SOC-004",
        "name": "Multiple accounts targeted",
        "severity": "high",
        "description": "One source generates authentication failures against several distinct accounts.",
        "recommendation": "Review account diversity, timing, and source ownership. Look for successful logins and check whether this is an approved identity test or a broken client.",
        "false_positives": "A shared gateway or a misconfigured application using several accounts.",
        "mitre_attack": [{"id": "T1110.003", "name": "Password Spraying", "mapping": "direct"}],
        "mitre_attack_note": "One source failing across multiple accounts aligns with password-spraying behavior.",
    },
    {
        "id": "SOC-005",
        "name": "Login outside business hours",
        "severity": "medium",
        "description": "A successful login occurs outside the configured local work schedule.",
        "recommendation": "Confirm the user's timezone, shift, travel, and on-call schedule. Correlate with source history and other alerts before escalating.",
        "false_positives": "On-call engineers, remote staff, and planned maintenance.",
        "mitre_attack": [{"id": "T1078", "name": "Valid Accounts", "mapping": "contextual"}],
        "mitre_attack_note": "Unusual login timing can support valid-account-abuse triage but is not behavior-specific by itself.",
    },
    {
        "id": "SOC-006",
        "name": "Synthetic watchlist activity",
        "severity": "high",
        "description": "An authentication event comes from a configured synthetic watchlist IP.",
        "recommendation": "Inspect all activity from this source and related sessions. This local watchlist is a simulation, not live threat intelligence or a reputation verdict.",
        "false_positives": "Outdated watchlist entries or an approved simulation.",
        "mitre_attack": [],
        "mitre_attack_note": "Indicator-based source correlation has no direct behavior-specific ATT&CK technique mapping.",
    },
    {
        "id": "SOC-007",
        "name": "Authentication volume spike",
        "severity": "high",
        "description": "Total authentication volume meets a fixed threshold in a rolling window.",
        "recommendation": "Compare sources, outcome ratios, and service ownership. Check for a batch job, an outage, or a suspicious burst; a threshold alone does not prove an attack.",
        "false_positives": "Shift changes, application retries, or scheduled bulk authentication.",
        "mitre_attack": [{"id": "T1110", "name": "Brute Force", "mapping": "contextual"}],
        "mitre_attack_note": "Authentication volume alone is a broad heuristic; map to Brute Force only as contextual triage evidence.",
    },
]


def rule_metadata(rule_id: str) -> dict:
    """Return copy-safe analyst metadata for one detection rule."""
    for rule in RULES:
        if rule["id"] == rule_id:
            return {
                "mitre_attack": [dict(item) for item in rule.get("mitre_attack", [])],
                "mitre_attack_note": rule.get("mitre_attack_note", ""),
            }
    return {"mitre_attack": [], "mitre_attack_note": "No ATT&CK mapping is defined for this rule."}


def catalog(config: DetectionConfig) -> list[dict]:
    parameters = {
        "SOC-001": f"≥{config.failure_threshold} failures / {config.failure_window_seconds}s, same source + account + host + service",
        "SOC-002": f"Success after ≥{config.failure_threshold} failures / {config.success_window_seconds}s, same source + account + host + service",
        "SOC-003": "Successful login: " + ", ".join(config.privileged_accounts),
        "SOC-004": f"≥{config.spray_account_threshold} distinct failed accounts / {config.spray_window_seconds}s, same source",
        "SOC-005": f"Success outside {config.business_start_hour:02d}:00–{config.business_end_hour:02d}:00 {config.business_timezone}; weekdays {config.business_weekdays}",
        "SOC-006": "Any authentication from: " + ", ".join(config.suspicious_ips),
        "SOC-007": f"≥{config.spike_threshold} authentication events / {config.spike_window_seconds}s, across all sources",
    }
    return [{**rule, "parameters": parameters[rule["id"]], "version": config.version} for rule in RULES]


def config_hash(config: DetectionConfig) -> str:
    return hashlib.sha256(json.dumps(config.model_dump(), sort_keys=True).encode()).hexdigest()


def detect(events: list[dict], config: DetectionConfig) -> list[dict]:
    """Return findings without modifying events, cases, or the database."""
    rules = {rule["id"]: rule for rule in RULES}
    findings: dict[str, dict] = {}
    failures: dict[tuple, deque] = defaultdict(deque)
    spray: dict[str, deque] = defaultdict(deque)
    volume: deque = deque()
    work_tz = ZoneInfo(config.business_timezone)
    fingerprint_config = config_hash(config)

    def trim(queue: deque, now: datetime, seconds: int):
        while queue and (now - queue[0][0]).total_seconds() > seconds:
            queue.popleft()

    def emit(
        rule_id: str, evidence: list[dict], entity: tuple, now: datetime, reason: str, single: bool = False
    ):
        trigger = evidence[-1]
        episode = trigger["event_id"] if single else str(int(now.timestamp()) // config.aggregation_seconds)
        identity = json.dumps([rule_id, entity, episode, fingerprint_config], separators=(",", ":"))
        key = hashlib.sha256(identity.encode()).hexdigest()
        match = findings.setdefault(
            key,
            {
                "fingerprint": key,
                "rule_id": rule_id,
                "rule_name": rules[rule_id]["name"],
                "severity": rules[rule_id]["severity"],
                "source_ip": trigger["source_ip"],
                "username": trigger["username"],
                "hostname": trigger["hostname"],
                "service": trigger["service"],
                "first_seen": evidence[0]["timestamp"],
                "last_seen": trigger["timestamp"],
                "explanation": reason,
                "recommendation": rules[rule_id]["recommendation"],
                "rule_version": config.version,
                "config_hash": fingerprint_config,
                "rule_parameters": config.model_dump(),
                "evidence_ids": set(),
            },
        )
        match["evidence_ids"].update(event["id"] for event in evidence)
        match["first_seen"] = min(match["first_seen"], evidence[0]["timestamp"])
        if trigger["timestamp"] >= match["last_seen"]:
            match["last_seen"] = trigger["timestamp"]
            match["explanation"] = reason
            for field in ("source_ip", "username", "hostname", "service"):
                match[field] = trigger[field]

    # Failure-before-success is deterministic at identical timestamps.
    ordered = sorted(events, key=lambda e: (e["timestamp"], e["event_type"], e["event_id"]))
    for event in ordered:
        now = utc_datetime(event["timestamp"])
        identity = (event["source_ip"], event["username"], event["hostname"], event["service"])
        queue = failures[identity]
        trim(queue, now, max(config.failure_window_seconds, config.success_window_seconds))
        if event["event_type"] == "authentication_failure":
            queue.append((now, event))
            recent = [e for when, e in queue if (now - when).total_seconds() <= config.failure_window_seconds]
            if len(recent) >= config.failure_threshold:
                emit(
                    "SOC-001",
                    recent,
                    identity,
                    now,
                    f"{len(recent)} failed logins within {config.failure_window_seconds}s for {event['username']} from {event['source_ip']} to {event['hostname']}/{event['service']}.",
                )
            source_queue = spray[event["source_ip"]]
            trim(source_queue, now, config.spray_window_seconds)
            source_queue.append((now, event))
            accounts = {e["username"] for _, e in source_queue}
            if len(accounts) >= config.spray_account_threshold:
                emit(
                    "SOC-004",
                    [e for _, e in source_queue],
                    (event["source_ip"],),
                    now,
                    f"Source {event['source_ip']} failed against {len(accounts)} distinct accounts within {config.spray_window_seconds}s. The displayed account is the latest triggering account.",
                )
        else:
            prior = [e for when, e in queue if (now - when).total_seconds() <= config.success_window_seconds]
            if len(prior) >= config.failure_threshold:
                emit(
                    "SOC-002",
                    prior + [event],
                    identity,
                    now,
                    f"Successful login for {event['username']} after {len(prior)} failures from the same source to the same host/service within {config.success_window_seconds}s.",
                    single=True,
                )
            # A success ends a failure streak; later successes cannot reuse it.
            queue.clear()
            if event["username"].casefold() in config.privileged_accounts:
                emit(
                    "SOC-003",
                    [event],
                    identity,
                    now,
                    f"Configured privileged account {event['username']} authenticated successfully.",
                    single=True,
                )
            local = now.astimezone(work_tz)
            if (
                local.weekday() not in config.business_weekdays
                or not config.business_start_hour <= local.hour < config.business_end_hour
            ):
                emit(
                    "SOC-005",
                    [event],
                    identity,
                    now,
                    f"Login at {local.strftime('%A %H:%M %Z')} is outside the configured {config.business_start_hour:02d}:00–{config.business_end_hour:02d}:00 work schedule in {config.business_timezone}.",
                    single=True,
                )

        if event["source_ip"] in config.suspicious_ips:
            emit(
                "SOC-006",
                [event],
                (event["source_ip"],),
                now,
                f"Source {event['source_ip']} is on the configured synthetic watchlist; this is not a live reputation lookup.",
            )
        trim(volume, now, config.spike_window_seconds)
        volume.append((now, event))
        if len(volume) >= config.spike_threshold:
            emit(
                "SOC-007",
                [e for _, e in volume],
                ("all-sources",),
                now,
                f"{len(volume)} authentication events across all sources within {config.spike_window_seconds}s (configured threshold: {config.spike_threshold}). Displayed source/account describe the latest trigger.",
            )

    output = []
    for finding in findings.values():
        finding["evidence_ids"] = sorted(finding["evidence_ids"])
        finding["evidence_count"] = len(finding["evidence_ids"])
        output.append(finding)
    return sorted(output, key=lambda f: (f["last_seen"], f["rule_id"], f["fingerprint"]))
