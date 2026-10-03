# MITRE ATT&CK integration

SOC Security Operations Dashboard v1.2 enriches the detection catalog, alert detail API, analyst UI, and exported reports with MITRE ATT&CK technique context.

## Design goal

The integration helps an analyst answer: **“What adversary behavior is this detection related to?”** It does not turn a rule match into proof of compromise or proof that an ATT&CK technique occurred.

Mappings use three interpretations:

- **Direct** — the rule closely represents behavior described by the ATT&CK technique.
- **Contextual** — the rule can support triage for the technique, but the signal is not specific enough on its own.
- **No direct mapping** — the rule is indicator- or context-based rather than behavior-specific.

## Rule mapping

| Rule | Technique | Mapping |
| --- | --- | --- |
| SOC-001 | T1110.001 Password Guessing | Direct |
| SOC-002 | T1110.001 Password Guessing | Direct |
| SOC-003 | T1078 Valid Accounts | Contextual |
| SOC-004 | T1110.003 Password Spraying | Direct |
| SOC-005 | T1078 Valid Accounts | Contextual |
| SOC-006 | No direct technique mapping | Indicator-only |
| SOC-007 | T1110 Brute Force | Contextual |

## Why some mappings are contextual

A privileged login or an out-of-hours login may be completely legitimate. Likewise, an authentication-volume spike can be caused by retries, outages, or batch jobs. The dashboard therefore labels these as contextual instead of presenting an ATT&CK technique as a confirmed attacker action.

The synthetic watchlist rule intentionally has no behavior-specific ATT&CK mapping. A source indicator can raise investigation priority, but it does not describe what the source actually did.

## Where the mapping appears

- Detection Rule Library
- Alert Investigation page
- Alert Queue compact metadata
- `/api/meta` rule catalog
- `/api/alerts` and `/api/alerts/{id}`
- HTML, JSON, and Markdown investigation reports

## Data model boundary

ATT&CK metadata is rule metadata rather than case state. It is enriched from the current rule catalog when alerts are read, so v1.2 does **not** require a SQLite schema migration and does not rewrite historical analyst notes or case status.

## Analyst reminder

**ATT&CK mapping is classification context. Detection evidence and analyst validation still determine the case conclusion.**
