# Recorded local verification

Verified on October 3, 2026 using Python 3.12.14 on Linux and Chromium Headless Shell 134.0.6998.35. These are the local build results; remote CI and other Python versions have not been run in this workspace.

| Check | Actual result |
| --- | --- |
| Pytest suite | **103 passed, 0 failures, 0 errors** |
| Measured application coverage | **98.78% (649 / 657 lines)** |
| Real-browser workflow checks | **25 passed** |
| Ruff lint | Passed |
| Ruff formatting | Passed |
| JavaScript syntax checks | Passed |
| Actual FastAPI/Uvicorn start | Passed; health endpoint queried over loopback |
| Actual server restart with persisted notes | Passed in browser workflow |
| CLI seed, duplicate CSV import, three export formats | Passed in an isolated database |
| CSV / JSON equivalence | Passed; 553 identical normalized events |
| Demo counts | 553 events; 18 alerts; 2 critical; 94 failures; 38 sources |
| Screenshot files | 8 genuine application captures, visually inspected |
| Docker build/runtime | Not run: no Docker CLI/daemon available |
| GitHub Actions | Supplied; execution pending repository publication |

Coverage includes the app modules and excludes `app/__main__.py`; CLI behavior is separately checked by `scripts/verify_release.py`. A Starlette warning indicates that its HTTPX-based TestClient integration is deprecated in the installed version; all tests still pass. This is recorded without hiding the warning.

## Evidence files

- `verification/pytest-results.xml`: JUnit results for the 103 tests.
- `verification/summary.json`: machine-readable test and coverage summary.
- `verification/browser-check.json`: the 25 browser assertions and browser version.
- `verification/release-check.json`: required files, CLI checks, sample equivalence, and PNG dimensions.
- `verification/vendor-integrity.json`: vendored Chart.js version and SHA-256.
- `../MANIFEST_SHA256.json`: SHA-256 for every source/document/media file included in the ZIP.

The browser test starts an isolated real server. It checks import, five actual chart datasets, severity filtering, evidence, status/notes, stale-tab conflict handling, event pagination, rule replay, report downloads, rejected invalid uploads, CSV deduplication, offline assets, mobile layouts, and persistence after a real server restart. Expected HTTP 409/422 validation responses and download-manager aborts are accounted for explicitly; unexpected errors or failed requests fail the check.

## Reproduce

```bash
python -m pip install -r requirements-dev.txt
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m pytest --cov=app --cov-report=term-missing
npm ci
npx playwright install chromium
npm test
python scripts/verify_release.py
```

Run the commands from the source root. Browser tooling is optional for ordinary application use. It starts on loopback port 8766 with a temporary database. `SOC_PYTHON`, `SOC_PLAYWRIGHT_MODULE`, and `SOC_CHROMIUM_PATH` provide optional verification-environment overrides; ordinary npm use does not require them.

## Example reports

`docs/example-reports/critical-investigation.html`, `.json`, and `.md` are produced by the real report renderer against the two critical synthetic cases and a truthful investigation note. They do not represent a confirmed compromise. Regenerate with `python scripts/create_example_reports.py`.

## What is not claimed

Production authentication/RBAC, real SOC deployment, live collection, real-world threat reputation, streaming throughput, protected forensic audit, and verified container execution are outside the recorded results. The project is a complete local synthetic-data portfolio application with explicit operational limits.
