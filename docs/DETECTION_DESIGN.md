# Detection design and analyst semantics

## Event time, not ingestion time

Uploaded timestamps are parsed as timezone-aware datetimes, converted to UTC, and stored with a uniform microsecond-width ISO representation. Correlation uses event time. Creation timestamps in the case journal show when the local system processed a finding; they may differ from evidence times in a historical dataset.

Replay sorts by timestamp, event type, and event ID. At equal timestamps, failures sort before successes. This tie-break is deterministic but does not establish a causal order in real telemetry; real ingestion would need higher-resolution timestamps or source sequence numbers.

## Correlation identities

- SOC-001 and SOC-002: `(source_ip, username, hostname, service)`.
- SOC-004: source IP only; accounts may span hosts/services.
- SOC-006: source IP only.
- SOC-007: all sources; this is a dataset-wide fixed volume threshold.
- SOC-003 and SOC-005: one successful authentication event.

A login from another IP, account, host, or service cannot satisfy SOC-002 using an unrelated failure streak. Success clears the matching streak; subsequent successes do not repeatedly consume the same failures.

## Rolling windows

The engine retains chronological events in deques. It evicts an event when `now - oldest > window_seconds`; equality stays in the window. Example: failures at 09:00:00 and a threshold-triggering failure at 09:05:00 can belong to a 300-second window. At 09:05:01 the first failure expires.

SOC-001's queue is scoped to an identity, SOC-004 counts **distinct usernames**, and SOC-007 counts both success and failure events. Thresholds are fixed and configurable. SOC-007 is not statistical anomaly detection and does not learn a baseline.

## Stable episodes and evidence

After detecting a rolling match, rate rules use this key:

`SHA256(rule_id, entity, floor(trigger_epoch / aggregation_seconds), config_hash)`

At the defaults, matches for one entity/configuration in the same 15-minute UTC bucket update the same case. A rolling detection can cross a bucket boundary. If matching triggers fall into two buckets, two cases can exist even when their evidence overlaps. This explicit tradeoff keeps case identity stable when old events arrive out of order and avoids threshold-trigger IDs shifting every time the dataset grows.

The evidence link table holds the **union** of all matched windows in the episode. The narrative describes the latest triggering window, so its count can be smaller than the union count. For single-login rules, the triggering event ID replaces the episode bucket in the fingerprint.

Every finding contains the configuration snapshot and SHA-256. Changing any configured value produces a new configuration identity and can produce new historical findings for all rules on replay. Existing findings are retained, even if a new configuration would not match them; use the snapshot to understand historical results.

## Evidence and case work

Event contents are immutable for a given external event ID. A conflict rolls back the whole import. Reimports do not create events or findings again, although successful imports are recorded in import history.

New matching evidence can enrich a case. The case's revision increases; analyst notes and status stay intact. Closed cases do not reopen automatically. This is a deliberate simple workflow and a limitation for continuous monitoring; an analyst must review and reopen a Closed case when warranted. The app does not automatically declare or contain incidents.

SQLite uses write transactions with `BEGIN IMMEDIATE` and foreign keys. Case updates require the displayed revision. HTTP 409 means another writer changed the case; the UI retains the draft and asks the analyst to reload. The local journal is append-only through the app but is not tamper-proof against someone with database access.

## False positives and useful tuning

- Repeated failures: saved credentials, user mistakes, scheduled jobs.
- Success after failures: legitimate recovery after typing errors.
- Privileged logins: routine administration.
- Multiple accounts: a gateway, application retries, or a known identity simulation.
- Outside hours: on-call work and timezone/shift differences.
- Watchlist: fictional entries; no current threat-intelligence claim.
- Spikes: shift changes, outages, and bulk jobs.

Business hours use `zoneinfo`, weekdays numbered Monday=0 through Sunday=6, start inclusive and end exclusive. Overnight schedules are rejected. Changing a threshold should be motivated by representative normal behavior and reviewed false positives, not by a desire to make alerts disappear.

## Scalability limits

Each import replays up to 20,000 stored events. Some rule windows scan or combine retained evidence; worst-case work increases with dense windows. SQLite, synchronous replay, and full evidence/report exports are appropriate for a bounded local lab. This does not claim streaming throughput, distributed operation, protected production audit, or enterprise retention.

The dashboard explicitly shows the full ingested dataset, including historical data, rather than an arbitrary current-day filter that would hide the fixed sample dataset.
