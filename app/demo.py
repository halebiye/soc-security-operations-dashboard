"""Deterministic synthetic scenarios; no network traffic or attack simulation."""

import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.ingestion import EVENT_FIELDS


def generate_events() -> list[dict]:
    randomizer = random.Random(42)
    events = []
    base = datetime(2026, 10, 1, 6, 0, tzinfo=timezone.utc)  # Thursday, 09:00 Istanbul

    def add(
        seconds: float,
        source: str,
        user: str,
        outcome: str = "success",
        host: str = "idp-01",
        service: str = "sso",
    ):
        events.append(
            {
                "event_id": f"demo-{len(events) + 1:05d}",
                "timestamp": (base + timedelta(seconds=seconds)).isoformat(),
                "source_ip": source,
                "username": user,
                "hostname": host,
                "service": service,
                "event_type": f"authentication_{outcome}",
                "synthetic": True,
            }
        )

    accounts = [
        "muhammed",
        "ayse",
        "omar",
        "selin",
        "deniz",
        "sara",
        "yusuf",
        "elif",
        "hasan",
        "zeynep",
        "ali",
        "emre",
        "nour",
        "can",
        "lina",
        "kemal",
    ]
    for index in range(480):
        add(
            index * 60 + randomizer.randrange(0, 20),
            f"192.0.2.{randomizer.randrange(10, 41)}",
            randomizer.choice(accounts),
            "failure" if randomizer.random() < 0.09 else "success",
            randomizer.choice(["idp-01", "vpn-gw-01", "app-02"]),
            randomizer.choice(["sso", "vpn", "ssh"]),
        )

    # Repeated failures followed by a success, same correlation identity.
    for index in range(8):
        add(3 * 3600 + 10 * 60 + index * 15, "198.51.100.42", "muhammed", "failure", "vpn-gw-01", "vpn")
    add(3 * 3600 + 12 * 60, "198.51.100.42", "muhammed", host="vpn-gw-01", service="vpn")
    # A separate failed-only streak.
    for index in range(6):
        add(95 * 60 + index * 20, "198.51.100.88", "svc_reports", "failure", "app-02", "ssh")
    # Privileged and out-of-hours logins.
    add(4 * 3600 + 25 * 60, "192.0.2.20", "admin", host="linux-01", service="ssh")
    add(8 * 3600 + 5 * 60, "192.0.2.21", "svc_backup", host="backup-01", service="ssh")
    add(16 * 3600, "198.51.100.120", "selin", host="vpn-gw-01", service="vpn")
    add(17 * 3600, "198.51.100.121", "root", host="linux-01", service="ssh")
    # Multiple account failures from one source; no passwords are present.
    for index in range(12):
        add(5 * 3600 + 20 * 60 + index * 8, "203.0.113.77", f"staff_{index + 1:02d}", "failure")
    # Synthetic watchlist: five failures then success.
    for index in range(5):
        add(6 * 3600 + 45 * 60 + index * 7, "203.0.113.66", "omar", "failure")
    add(6 * 3600 + 46 * 60, "203.0.113.66", "omar")
    # Global volume threshold, mixed outcomes, high account diversity.
    for index in range(36):
        add(
            7 * 3600 + 5 * 60 + index,
            "203.0.113.180",
            f"burst_{index % 6 + 1}",
            "failure" if index % 3 else "success",
            "vpn-gw-01",
            "vpn",
        )
    return sorted(events, key=lambda event: (event["timestamp"], event["event_id"]))


def write_samples(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    events = generate_events()
    (directory / "security_events.json").write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    with (directory / "security_events.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=EVENT_FIELDS)
        writer.writeheader()
        writer.writerows({**event, "synthetic": "true"} for event in events)
