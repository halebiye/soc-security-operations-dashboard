"""Create shipped example reports in a temporary, synthetic-only database."""

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import load_config  # noqa: E402
from app.ingestion import parse_upload  # noqa: E402
from app.models import AlertFilters, CaseUpdate  # noqa: E402
from app.reporting import render_report  # noqa: E402
from app.storage import Repository  # noqa: E402


def main():
    config = load_config(ROOT / "config/detection.json")
    output = ROOT / "docs/example-reports"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="soc-examples-") as directory:
        repository = Repository(Path(directory) / "example.sqlite3")
        repository.initialize()
        events = parse_upload((ROOT / "sample_data/security_events.json").read_bytes(), "sample.json")
        repository.ingest(events, "Synthetic scenario library", config)
        filters = AlertFilters(severity="critical")
        alert = repository.list_alerts(filters)["items"][0]
        repository.update_case(
            alert["id"],
            CaseUpdate(
                version=1,
                status="Investigating",
                note="Synthetic review: verified five failures followed by success for the same identity. "
                "MFA and user/session ownership are not available in this sample and need validation. "
                "No compromise conclusion is established.",
            ),
        )
        data = repository.report_data(filters, config)
        for output_format, extension in [("html", "html"), ("json", "json"), ("markdown", "md")]:
            content, _ = render_report(data, output_format)
            (output / f"critical-investigation.{extension}").write_text(content, encoding="utf-8")
    print("Created three real critical-alert reports from the synthetic sample.")


if __name__ == "__main__":
    main()
