# SOC Security Operations Dashboard — Investigation Report

Generated: 2026-10-03T07:45:29.316183+00:00

**Synthetic data only. Detection matches require analyst validation.**

Matching historical alerts; dataset statistics cover all ingested events.

Filters: {&quot;severity&quot;: &quot;critical&quot;}

Matching alerts: **2**

Dataset: 553 events; 94 failures.

Current configuration SHA-256: eef76f605d477738a35ecca605d3a3555aa3689c0026bf96ddfe90d117274c29

## ALR-0007 · Success after repeated failures

**CRITICAL** · Investigating · 2026-10-01T12:46:00.000000+00:00

Rule: SOC-002 / v1.0

Source: 203.0.113.66 · Account: omar · Host: idp-01 · Service: sso

Successful login for omar after 5 failures from the same source to the same host/service within 600s.

**Recommendation:** Prioritize triage. Verify the user&\#x27;s session, MFA result, and subsequent activity. Escalate a confirmed unexpected session and document the evidence.

Rule snapshot SHA-256: eef76f605d477738a35ecca605d3a3555aa3689c0026bf96ddfe90d117274c29

| Event | Timestamp (UTC) | Source | Account | Host | Service | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| demo-00512 | 2026-10-01T12:45:00.000000+00:00 | 203.0.113.66 | omar | idp-01 | sso | authentication\_failure |
| demo-00513 | 2026-10-01T12:45:07.000000+00:00 | 203.0.113.66 | omar | idp-01 | sso | authentication\_failure |
| demo-00514 | 2026-10-01T12:45:14.000000+00:00 | 203.0.113.66 | omar | idp-01 | sso | authentication\_failure |
| demo-00515 | 2026-10-01T12:45:21.000000+00:00 | 203.0.113.66 | omar | idp-01 | sso | authentication\_failure |
| demo-00516 | 2026-10-01T12:45:28.000000+00:00 | 203.0.113.66 | omar | idp-01 | sso | authentication\_failure |
| demo-00517 | 2026-10-01T12:46:00.000000+00:00 | 203.0.113.66 | omar | idp-01 | sso | authentication\_success |

### Analyst activity

- 2026-10-03T07:45:29.313784+00:00 · Detection engine · Alert created from synthetic event evidence.
- 2026-10-03T07:45:29.315564+00:00 · Local analyst · New → Investigating
- 2026-10-03T07:45:29.315564+00:00 · Local analyst · Synthetic review: verified five failures followed by success for the same identity. MFA and user/session ownership are not available in this sample and need validation. No compromise conclusion is established.

## ALR-0003 · Success after repeated failures

**CRITICAL** · New · 2026-10-01T09:12:00.000000+00:00

Rule: SOC-002 / v1.0

Source: 198.51.100.42 · Account: muhammed · Host: vpn-gw-01 · Service: vpn

Successful login for muhammed after 8 failures from the same source to the same host/service within 600s.

**Recommendation:** Prioritize triage. Verify the user&\#x27;s session, MFA result, and subsequent activity. Escalate a confirmed unexpected session and document the evidence.

Rule snapshot SHA-256: eef76f605d477738a35ecca605d3a3555aa3689c0026bf96ddfe90d117274c29

| Event | Timestamp (UTC) | Source | Account | Host | Service | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| demo-00481 | 2026-10-01T09:10:00.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_failure |
| demo-00482 | 2026-10-01T09:10:15.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_failure |
| demo-00483 | 2026-10-01T09:10:30.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_failure |
| demo-00484 | 2026-10-01T09:10:45.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_failure |
| demo-00485 | 2026-10-01T09:11:00.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_failure |
| demo-00486 | 2026-10-01T09:11:15.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_failure |
| demo-00487 | 2026-10-01T09:11:30.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_failure |
| demo-00488 | 2026-10-01T09:11:45.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_failure |
| demo-00489 | 2026-10-01T09:12:00.000000+00:00 | 198.51.100.42 | muhammed | vpn-gw-01 | vpn | authentication\_success |

### Analyst activity

- 2026-10-03T07:45:29.313784+00:00 · Detection engine · Alert created from synthetic event evidence.
