"""SQLite repositories and transactions. SQL data is always parameterized."""

import hashlib
import json
import sqlite3
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter

from app.config import DetectionConfig
from app.detection import config_hash, detect, rule_metadata
from app.ingestion import MAX_STORED_EVENTS, ImportErrorDetail
from app.models import AlertFilters, CaseUpdate, iso_utc, utc_datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    hostname TEXT NOT NULL,
    service TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN ('authentication_success','authentication_failure')),
    synthetic INTEGER NOT NULL CHECK(synthetic = 1)
);
CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS events_source ON events(source_ip);
CREATE INDEX IF NOT EXISTS events_username ON events(username);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
    source_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    hostname TEXT NOT NULL,
    service TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    explanation TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    rule_parameters TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New' CHECK(status IN ('New','Investigating','Closed')),
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_time ON alerts(last_seen);
CREATE INDEX IF NOT EXISTS alerts_status_severity ON alerts(status,severity);
CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY(alert_id,event_id)
);
CREATE INDEX IF NOT EXISTS evidence_event ON alert_evidence(event_id);
CREATE TABLE IF NOT EXISTS activities (
    id INTEGER PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    timestamp TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('created','status','note')),
    analyst TEXT NOT NULL,
    content TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    filename TEXT NOT NULL,
    total INTEGER NOT NULL,
    inserted INTEGER NOT NULL,
    duplicates INTEGER NOT NULL,
    alerts_created INTEGER NOT NULL,
    config_hash TEXT NOT NULL,
    duration_ms REAL NOT NULL
);
"""


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def event_fingerprint(event: dict) -> str:
    payload = {key: value for key, value in event.items() if key not in {"id", "fingerprint"}}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class CaseConflict(ValueError):
    pass


class Repository:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connection(self, write: bool = False):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)
            version = connection.execute("SELECT version FROM schema_version").fetchone()[0]
            if version != 1:
                raise RuntimeError("Unsupported database schema; use a separate database")

    def _detect(self, connection, config: DetectionConfig) -> tuple[int, int]:
        events = [dict(row) for row in connection.execute("SELECT * FROM events ORDER BY timestamp,event_id")]
        findings = detect(events, config)
        created = 0
        timestamp = now_utc()
        fields = (
            "fingerprint",
            "rule_id",
            "rule_name",
            "severity",
            "source_ip",
            "username",
            "hostname",
            "service",
            "first_seen",
            "last_seen",
            "explanation",
            "recommendation",
            "rule_version",
            "config_hash",
            "rule_parameters",
        )
        for finding in findings:
            payload = [
                json.dumps(finding[key], sort_keys=True) if key == "rule_parameters" else finding[key]
                for key in fields
            ]
            cursor = connection.execute(
                f"INSERT OR IGNORE INTO alerts ({','.join(fields)},created_at,updated_at) "
                f"VALUES ({','.join('?' for _ in range(len(fields) + 2))})",
                payload + [timestamp, timestamp],
            )
            alert = connection.execute(
                "SELECT * FROM alerts WHERE fingerprint=?", (finding["fingerprint"],)
            ).fetchone()
            alert_id = alert["id"]
            if cursor.rowcount:
                created += 1
                connection.execute(
                    "INSERT INTO activities (alert_id,timestamp,kind,analyst,content) VALUES (?,?,'created','Detection engine',?)",
                    (alert_id, timestamp, "Alert created from synthetic event evidence."),
                )
            else:
                existing_ids = {
                    row[0]
                    for row in connection.execute(
                        "SELECT event_id FROM alert_evidence WHERE alert_id=?", (alert_id,)
                    )
                }
                refreshed_fields = (
                    "first_seen",
                    "last_seen",
                    "source_ip",
                    "username",
                    "hostname",
                    "service",
                    "explanation",
                )
                if set(finding["evidence_ids"]) - existing_ids or any(
                    finding[field] != alert[field] for field in refreshed_fields
                ):
                    # Evidence changes invalidate stale browser revisions while preserving case work.
                    connection.execute(
                        "UPDATE alerts SET first_seen=MIN(first_seen,?), last_seen=MAX(last_seen,?), "
                        "source_ip=?,username=?,hostname=?,service=?,explanation=?,updated_at=?,version=version+1 WHERE id=?",
                        (
                            finding["first_seen"],
                            finding["last_seen"],
                            finding["source_ip"],
                            finding["username"],
                            finding["hostname"],
                            finding["service"],
                            finding["explanation"],
                            timestamp,
                            alert_id,
                        ),
                    )
            connection.executemany(
                "INSERT OR IGNORE INTO alert_evidence (alert_id,event_id) VALUES (?,?)",
                [(alert_id, event_id) for event_id in finding["evidence_ids"]],
            )
        return created, len(findings)

    def ingest(self, events: list[dict], filename: str, config: DetectionConfig) -> dict:
        started = perf_counter()
        with self.connection(write=True) as connection:
            inserted = 0
            for event in events:
                fingerprint = event_fingerprint(event)
                existing = connection.execute(
                    "SELECT fingerprint FROM events WHERE event_id=?", (event["event_id"],)
                ).fetchone()
                if existing:
                    if existing["fingerprint"] != fingerprint:
                        raise ImportErrorDetail(
                            f"Event ID {event['event_id']} already exists with different content; import rolled back"
                        )
                    continue
                connection.execute(
                    "INSERT INTO events (event_id,fingerprint,timestamp,source_ip,username,hostname,service,event_type,synthetic) VALUES (?,?,?,?,?,?,?,?,1)",
                    (
                        event["event_id"],
                        fingerprint,
                        event["timestamp"],
                        event["source_ip"],
                        event["username"],
                        event["hostname"],
                        event["service"],
                        event["event_type"],
                    ),
                )
                inserted += 1
            total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if total > MAX_STORED_EVENTS:
                raise ImportErrorDetail("Local dataset limit is 20000 events; import rolled back")
            created, matched = self._detect(connection, config)
            duration = round((perf_counter() - started) * 1000, 2)
            connection.execute(
                "INSERT INTO imports (timestamp,filename,total,inserted,duplicates,alerts_created,config_hash,duration_ms) VALUES (?,?,?,?,?,?,?,?)",
                (
                    now_utc(),
                    Path(filename).name,
                    len(events),
                    inserted,
                    len(events) - inserted,
                    created,
                    config_hash(config),
                    duration,
                ),
            )
        return {
            "imported": inserted,
            "duplicates": len(events) - inserted,
            "alerts_created": created,
            "matches": matched,
            "duration_ms": duration,
        }

    def run_detections(self, config: DetectionConfig) -> dict:
        with self.connection(write=True) as connection:
            created, matched = self._detect(connection, config)
        return {"alerts_created": created, "matches": matched}

    @staticmethod
    def _where(filters: AlertFilters) -> tuple[str, list]:
        clauses, parameters = [], []
        for key in ("severity", "status", "rule_id"):
            value = getattr(filters, key)
            if value is not None:
                clauses.append(f"a.{key}=?")
                parameters.append(str(value))
        # Entity filters search every evidence event, including multi-account/global alerts.
        for key in ("source_ip", "username"):
            value = getattr(filters, key)
            if value is not None:
                clauses.append(
                    f"EXISTS (SELECT 1 FROM alert_evidence ae JOIN events e ON e.id=ae.event_id WHERE ae.alert_id=a.id AND e.{key}=?)"
                )
                parameters.append(value)
        if filters.q:
            # instr avoids SQL LIKE wildcard surprises for literal analyst searches.
            clauses.append(
                "(instr(lower(a.rule_name || ' ' || a.explanation || ' ' || a.hostname || ' ' || a.service),lower(?))>0)"
            )
            parameters.append(filters.q)
        for field, operator in (("start", ">="), ("end", "<=")):
            value = getattr(filters, field)
            if value:
                clauses.append(f"a.last_seen{operator}?")
                parameters.append(iso_utc(value))
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), parameters

    @staticmethod
    def _alert(row) -> dict:
        alert = dict(row)
        alert["display_id"] = f"ALR-{alert['id']:04d}"
        alert["rule_parameters"] = json.loads(alert["rule_parameters"])
        alert.update(rule_metadata(alert["rule_id"]))
        return alert

    def _list(self, connection, filters: AlertFilters, limit: int | None, offset: int) -> dict:
        where, parameters = self._where(filters)
        total = connection.execute("SELECT COUNT(*) FROM alerts a" + where, parameters).fetchone()[0]
        sql = (
            "SELECT a.*, (SELECT COUNT(*) FROM alert_evidence ae WHERE ae.alert_id=a.id) AS evidence_count FROM alerts a"
            + where
        )
        sql += " ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,a.last_seen DESC,a.id DESC"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            parameters = parameters + [limit, offset]
        return {"total": total, "items": [self._alert(row) for row in connection.execute(sql, parameters)]}

    def list_alerts(self, filters: AlertFilters, limit: int = 25, offset: int = 0) -> dict:
        with self.connection() as connection:
            return self._list(connection, filters, limit, offset)

    @staticmethod
    def _evidence(connection, alert_id: int) -> list[dict]:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT e.* FROM events e JOIN alert_evidence ae ON e.id=ae.event_id WHERE ae.alert_id=? ORDER BY e.timestamp,e.event_type,e.event_id",
                (alert_id,),
            )
        ]

    def _detail(self, connection, alert_id: int) -> dict | None:
        row = connection.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if row is None:
            return None
        alert = self._alert(row)
        alert["evidence"] = self._evidence(connection, alert_id)
        alert["evidence_count"] = len(alert["evidence"])
        alert["activity"] = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM activities WHERE alert_id=? ORDER BY id", (alert_id,)
            )
        ]
        return alert

    def detail(self, alert_id: int) -> dict | None:
        with self.connection() as connection:
            return self._detail(connection, alert_id)

    def update_case(self, alert_id: int, update: CaseUpdate) -> dict | None:
        with self.connection(write=True) as connection:
            alert = connection.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if alert is None:
                return None
            if alert["version"] != update.version:
                raise CaseConflict("This alert changed since you opened it. Reload the alert before saving.")
            timestamp = now_utc()
            status = str(update.status) if update.status else alert["status"]
            changed = status != alert["status"] or bool(update.note)
            if changed:
                connection.execute(
                    "UPDATE alerts SET status=?,version=version+1,updated_at=? WHERE id=?",
                    (status, timestamp, alert_id),
                )
                if status != alert["status"]:
                    connection.execute(
                        "INSERT INTO activities (alert_id,timestamp,kind,analyst,content) VALUES (?,?,'status','Local analyst',?)",
                        (alert_id, timestamp, f"{alert['status']} → {status}"),
                    )
                if update.note:
                    connection.execute(
                        "INSERT INTO activities (alert_id,timestamp,kind,analyst,content) VALUES (?,?,'note','Local analyst',?)",
                        (alert_id, timestamp, update.note),
                    )
            return self._detail(connection, alert_id)

    def list_events(
        self, q: str = "", event_type: str | None = None, limit: int = 25, offset: int = 0
    ) -> dict:
        clauses, parameters = [], []
        if q:
            clauses.append(
                "instr(lower(source_ip || ' ' || username || ' ' || hostname || ' ' || service || ' ' || event_id),lower(?))>0"
            )
            parameters.append(q)
        if event_type:
            clauses.append("event_type=?")
            parameters.append(event_type)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connection() as connection:
            total = connection.execute("SELECT COUNT(*) FROM events" + where, parameters).fetchone()[0]
            rows = connection.execute(
                "SELECT * FROM events" + where + " ORDER BY timestamp DESC,event_id DESC LIMIT ? OFFSET ?",
                parameters + [limit, offset],
            )
            return {"total": total, "items": [dict(row) for row in rows]}

    def _summary(self, connection) -> dict:
        events = [
            dict(row)
            for row in connection.execute("SELECT timestamp,event_type FROM events ORDER BY timestamp")
        ]
        types = Counter(event["event_type"] for event in events)
        severity = {key: 0 for key in ("critical", "high", "medium", "low")}
        severity.update(
            {
                row[0]: row[1]
                for row in connection.execute("SELECT severity,COUNT(*) FROM alerts GROUP BY severity")
            }
        )
        statuses = {key: 0 for key in ("New", "Investigating", "Closed")}
        statuses.update(
            {
                row[0]: row[1]
                for row in connection.execute("SELECT status,COUNT(*) FROM alerts GROUP BY status")
            }
        )
        series = []
        start = end = None
        step = 3600
        if events:
            start, end = events[0]["timestamp"], events[-1]["timestamp"]
            anchor = utc_datetime(start).replace(minute=0, second=0, microsecond=0)
            span = (utc_datetime(end) - anchor).total_seconds()
            step = max(3600, int(span // (240 * 3600) + 1) * 3600)
            buckets = defaultdict(Counter)
            for event in events:
                index = int((utc_datetime(event["timestamp"]) - anchor).total_seconds() // step)
                buckets[index][event["event_type"]] += 1
            for index in range(int(span // step) + 1):
                counts = buckets[index]
                series.append(
                    {
                        "timestamp": iso_utc(anchor + timedelta(seconds=index * step)),
                        "success": counts["authentication_success"],
                        "failure": counts["authentication_failure"],
                    }
                )

        def top(column, failures_only=False):
            where = " WHERE event_type='authentication_failure'" if failures_only else ""
            return [
                {"label": row[0], "count": row[1]}
                for row in connection.execute(
                    f"SELECT {column},COUNT(*) FROM events{where} GROUP BY {column} ORDER BY COUNT(*) DESC,{column} LIMIT 5"
                )
            ]

        latest = connection.execute("SELECT * FROM imports ORDER BY id DESC LIMIT 1").fetchone()
        return {
            "total_events": len(events),
            "total_alerts": sum(severity.values()),
            "critical_alerts": severity["critical"],
            "failed_logins": types["authentication_failure"],
            "successful_logins": types["authentication_success"],
            "unique_sources": connection.execute("SELECT COUNT(DISTINCT source_ip) FROM events").fetchone()[
                0
            ],
            "severity": severity,
            "statuses": statuses,
            "events_over_time": series,
            "bucket_seconds": step,
            "top_sources": top("source_ip"),
            "targeted_accounts": top("username", True),
            "first_event": start,
            "last_event": end,
            "latest_import": dict(latest) if latest else None,
        }

    def summary(self) -> dict:
        with self.connection() as connection:
            return self._summary(connection)

    def report_data(self, filters: AlertFilters, config: DetectionConfig) -> dict:
        # A single read transaction keeps statistics/evidence/case journals consistent.
        with self.connection() as connection:
            results = self._list(connection, filters, None, 0)
            alerts = [self._detail(connection, alert["id"]) for alert in results["items"]]
            return {
                "project": "SOC Security Operations Dashboard",
                "schema_version": 1,
                "generated_at": now_utc(),
                "synthetic_only": True,
                "scope": "Matching historical alerts; dataset statistics cover all ingested events.",
                "filters": filters.model_dump(mode="json", exclude_none=True),
                "config_hash": config_hash(config),
                "config": config.model_dump(),
                "dataset_summary": self._summary(connection),
                "alert_count": len(alerts),
                "alerts": alerts,
            }
