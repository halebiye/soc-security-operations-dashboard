# Security and scope

The intended boundary is a trusted user running a synthetic lab on loopback. No user accounts, public deployment, malware, network collection, scanning, exploitation, or automated response are implemented.

## Implemented controls

- IP literals are restricted to documentation networks; the `synthetic` flag is mandatory.
- Unknown event fields are rejected, including a supplied password field.
- Upload bytes, import rows, and stored dataset size are bounded.
- Timezone-aware timestamps and IP canonicalization are required.
- Stable event identities reject changed content and make reimports idempotent.
- Full import/detection transactions prevent partial writes.
- SQL data uses placeholders; fixed internal column names form query structure.
- JSON/text fields are escaped in the interface, Jinja2 HTML reports autoescape, and Markdown escapes embedded HTML and link delimiters.
- CSP restricts scripts/assets to local files; no CDN request is made by the interface.
- Host validation, same-origin mutation checks, and a required custom header reduce local cross-site request risks. The header is publicly known and is not a credential.
- SQLite foreign keys and optimistic revisions protect evidence links and case updates.
- Compose binds the host port to 127.0.0.1 and runs the container as a non-root user.

## Practical limitations

The app accepts no genuine operational telemetry. Documentation IPs and an attestation flag cannot establish that a username is fictional; users must keep all imported fields synthetic. Real personal data must not be submitted.

Local analyst attribution is fixed as `Local analyst`. Journal rows cannot be edited through the UI, but a person with filesystem access can alter the database. There is no RBAC, encrypted database, signed audit chain, protected multi-user identity, event retention policy, or secret management system.

Do not expose the development server publicly. Supporting production would require a separate deployment design with authentication and authorization, TLS, proxy/header configuration, private access, operational monitoring, retention and privacy controls, security testing, and a threat model appropriate to the environment.

Threshold matches are not confirmed incidents. Recommendations are manual investigation guidance, not enforcement. Closed cases stay Closed when evidence is enriched; revisit them manually. Synthetic watchlist membership does not imply real-world IP reputation.

## Dependencies

Chart.js is vendored so the dashboard works offline after dependency installation. Preserve its MIT notice. Runtime and development Python dependencies are versioned in requirements files; use an isolated virtual environment. Review updates and run tests before adopting a new dependency set.

## Reporting an issue

For this public portfolio project, describe the affected local feature, expected behavior, a safe synthetic reproduction, and the impact. Do not include credentials, private logs, or personal data in a public issue.
