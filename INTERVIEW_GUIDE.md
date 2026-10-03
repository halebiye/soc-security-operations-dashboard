# Interview guide

Use this with the running application. Rehearse in your own words and show the actual code. The project was built with AI assistance; be honest about that if asked, and demonstrate your understanding through evidence and a small modification.

## A 60-second introduction

“SOC Security Operations Dashboard is a local Mini SIEM for synthetic authentication data. It validates and normalizes CSV/JSON events, stores them in SQLite, and replays seven explainable rules. Each alert links to the matched events, an explanation, investigation guidance, and the configuration that produced it. An analyst can filter the queue, add notes, change status, and export a complete report. I used it to learn the path from telemetry to a documented analyst decision. Its boundaries are explicit: fixed thresholds, a bounded local dataset, no production authentication, and no offensive functionality.”

## A five-minute demonstration

1. **Overview:** show 553 events, 18 alerts, 2 critical alerts, 94 failures, and 38 sources. Explain that these numbers describe the synthetic sample, not a real organization.
2. **Queue:** filter to Critical. Open the `muhammed` case from `198.51.100.42`, or the `omar` case on the fictional watchlist.
3. **Evidence:** walk through the failures and subsequent success. Point out the same source/account/host/service correlation identity.
4. **Judgment:** explain that a genuine user may have mistyped a password. You would validate MFA, user ownership, session context, and subsequent activity before concluding compromise. Those enrichment sources are recommendations; the app does not collect them.
5. **Workflow:** set Investigating, append a note, and export the filtered report. Show that notes survive a restart and that stale revisions are rejected.
6. **Code:** open `detection.py`, one meaningful boundary test, and the SQLite transaction in `storage.py`.

## Questions and model answers

### 1. What is the difference between an event, alert, and incident?

An event is one normalized record. An alert is a rule match supported by one or more events. An incident is an assessed security situation requiring a response. This app tracks one alert per analyst case; it does not implement multi-alert incident grouping or automatically declare incidents.

### 2. Why did you use FastAPI?

It gives a clear API structure, typed request validation through Pydantic, file uploads, and a testable interface. The frontend is independent of the detection logic. I used normal synchronous endpoints for SQLite/CPU work; the asynchronous upload route hands ingestion to a worker thread after reading the bounded file.

### 3. Why SQLite?

It is portable, needs no separate database server, and provides transactions, constraints, indexes, and persistent evidence links. It is suitable for this bounded, local learning app. Multiple writers are serialized; a large or multi-user service would need different storage and correlation architecture.

### 4. How do you prevent duplicate events?

Each event has an external immutable `event_id`. A SHA-256 of normalized content verifies consistency. The same ID and same content is skipped; the same ID with changed content rejects the complete import. A new ID is a new event even if other fields match. This relies on stable IDs from the data producer.

### 5. Why do you normalize timestamps and IPs?

Equivalent offsets should refer to the same UTC instant, and equivalent IPv6 spellings should refer to the same source. Uniform microsecond-width UTC strings also make SQLite text timestamp comparisons reliable. Naive timestamps are rejected because guessing the timezone changes detection results.

### 6. What does “rolling window” mean?

At each event time, retain relevant earlier events within the configured duration. Evict events only when their age exceeds the limit. Five failures at most 300 seconds apart can trigger SOC-001. The exact endpoint is included; tests cover 300 and 301 seconds.

### 7. Why does SOC-002 require four identity fields?

Source IP, username, host, and service must match so failures for one session context do not justify a success-after-failures alert for another. This is a deliberate conservative correlation scope. A distributed attempt across several sources would require another rule.

### 8. Does a success after failures prove account compromise?

No. A legitimate user may eventually enter the correct password. Critical severity means prioritize investigation, not presume guilt. The synthetic event schema lacks MFA results, device history, session identifiers, and later activity, so the recommendation asks for that context.

### 9. How does multiple-account targeting differ from repeated failures?

SOC-001 counts failures against one identity. SOC-004 counts distinct failed usernames from one source. Ten failures against one account are not ten targeted accounts. The tests explicitly check this difference.

### 10. How do you reduce repeated alerts?

Rate matches are combined into stable UTC 15-minute buckets per rule/entity/configuration. The detection still uses rolling windows; the bucket controls case identity, not whether a threshold is crossed. Matched evidence is unioned across windows.

### 11. What are the bucket tradeoffs?

Nearby matching triggers on either side of a bucket boundary can produce two cases with overlapping evidence. The benefit is stable identity under replay and out-of-order imports. A streaming system would need event-time watermarks, late-event policy, and more advanced episode handling.

### 12. Why can evidence count exceed the number in the explanation?

The explanation describes the latest matching window. The case evidence is the union of all matching windows in that episode. Both are intentional; use the timestamps to distinguish the latest trigger from the broader evidence set.

### 13. How do configuration changes affect reproducibility?

Every alert stores the complete configuration and its SHA-256. A changed configuration produces a distinct identity on replay. Historical findings and case notes remain. The snapshot explains an old alert even when current settings have changed.

### 14. How do you avoid partial imports?

The file is fully parsed and validated before opening a write transaction. Event insertion, detection persistence, and import metadata then commit together. Errors roll back everything. Tests cover a conflicting event ID, dataset cap, and a detector failure after event insertion.

### 15. How do you stop two tabs from overwriting work?

The UI sends the case revision it opened. The database write transaction compares it to the current revision. A mismatch returns 409. The UI keeps the draft and offers reload. Revision checks protect the workflow but are not an authentication mechanism.

### 16. What is persistent about the analyst journal?

Status changes and notes are separate rows linked to an alert, with timestamps and local attribution. They survive database and server reuse. The app does not expose edit/delete operations for notes. Someone with filesystem access can still alter the database, so it is not a protected forensic audit trail.

### 17. How did you handle web security?

Typed validation, bounded imports, synthetic IP ranges, parameterized SQL, escaped UI text, autoescaped HTML reports, safe Markdown, CSP, trusted hosts, same-origin changes, and a required mutation header. The header is not secret. The system still has no authentication/RBAC and is restricted to a trusted local lab.

### 18. What did your tests actually verify?

The local build passed 103 Pytest tests with approximately 99% coverage of measured application modules, plus 25 real-browser checks. The checks cover every rule, window boundaries, negative cases, input errors, deduplication, rollback, filters, report escaping, persistence, stale updates, charts, and mobile layouts. CLI is excluded from the coverage metric and is separately smoke-tested. Docker/CI files are included; a Docker daemon was unavailable locally, and remote CI has not run yet.

### 19. Is the volume rule machine learning or anomaly detection?

No. It is a fixed threshold across all authentication events in a rolling 60-second window. It does not learn a normal baseline. A burst can be a scheduled job or an outage. A future improvement is baselining by service, time of day, and environment with documented evaluation.

### 20. What would you change first for production?

Clarify the authorized telemetry and privacy requirements; add authenticated identities and RBAC; design deployment/TLS/access control; replace full replay with incremental event-time processing; introduce migrations, retention, monitoring, and protected audit. Larger volumes would require different persistence and paged evidence/report generation.

## One code walkthrough to practice

1. Show `SecurityEvent` in `models.py`: identify required fields and validators.
2. Show `parse_upload`: explain why validation happens before persistence.
3. Show `Repository.ingest` and `connection(write=True)`: explain all-or-nothing writes.
4. Show the SOC-001/SOC-002 section in `detect`: trace five failures and one success.
5. Show `alert_evidence`: explain why evidence is normalized separately from the alert.
6. Show `CaseUpdate` and `update_case`: describe revision conflict handling.
7. Show a boundary test and run it: `python -m pytest tests/test_detection.py -k boundary -q`.

## Honest self-assessment

Before listing this prominently on your CV, explain it without reading this file, reproduce one alert from the sample, justify one false positive, change one threshold in an isolated lab, and show which test protects the affected behavior. If you cannot yet explain a component, call it a learning goal rather than claiming expertise.
