"""Portable CLI: python -m app seed|import|export|generate-samples."""

import argparse
from pathlib import Path

from app.config import ROOT, database_path, load_config
from app.demo import write_samples
from app.ingestion import ImportErrorDetail, parse_upload
from app.models import AlertFilters
from app.reporting import render_report
from app.storage import Repository


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic-data SOC dashboard utilities")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("seed", help="Import built-in synthetic scenarios (idempotent)")
    subcommands.add_parser("generate-samples", help="Regenerate deterministic sample CSV and JSON")
    importer = subcommands.add_parser("import", help="Import a synthetic CSV/JSON file")
    importer.add_argument("file", type=Path)
    exporter = subcommands.add_parser("export", help="Write an unfiltered investigation report")
    exporter.add_argument("format", choices=["json", "html", "markdown"])
    exporter.add_argument("output", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "generate-samples":
        write_samples(ROOT / "sample_data")
        print("Generated deterministic synthetic sample files.")
        return
    repository = Repository(database_path())
    repository.initialize()
    config = load_config()
    if arguments.command in {"seed", "import"}:
        path = ROOT / "sample_data/security_events.json" if arguments.command == "seed" else arguments.file
        try:
            result = repository.ingest(parse_upload(path.read_bytes(), path.name), path.name, config)
        except (OSError, ImportErrorDetail) as exc:
            parser.exit(1, f"Import failed: {exc}\n")
        print(result)
    else:
        data = repository.report_data(AlertFilters(), config)
        content, _ = render_report(data, arguments.format)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(content, encoding="utf-8")
        print(f"Report saved: {arguments.output}")


if __name__ == "__main__":
    main()
