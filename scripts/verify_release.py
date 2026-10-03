"""Verify the shipped source, synthetic samples, CLI, and actual media assets."""

import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.demo import generate_events  # noqa: E402
from app.ingestion import parse_upload  # noqa: E402


def main():
    required = [
        "README.md",
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        ".gitignore",
        "Dockerfile",
        "compose.yaml",
        ".github/workflows/ci.yml",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "LINKEDIN_POST.md",
        "CV_PROJECT_ENTRY.md",
        "INTERVIEW_GUIDE.md",
        "LEARNING_GUIDE_AR.md",
        "package.json",
        "package-lock.json",
        "app/static/vendor/Chart.js-LICENSE.md",
        "docs/API.md",
        "docs/DETECTION_DESIGN.md",
        "docs/SECURITY.md",
        "portfolio/project.json",
    ]
    for filename in required:
        assert (ROOT / filename).is_file(), f"Missing deliverable: {filename}"
    csv = parse_upload((ROOT / "sample_data/security_events.csv").read_bytes(), "sample.csv")
    js = parse_upload((ROOT / "sample_data/security_events.json").read_bytes(), "sample.json")
    assert csv == js and len(js) == 553
    assert json.loads((ROOT / "sample_data/security_events.json").read_text()) == generate_events()
    media = []
    for filename in [
        "dashboard-desktop.png",
        "alert-queue.png",
        "alert-investigation.png",
        "event-explorer.png",
        "detection-rules.png",
        "reports.png",
        "dashboard-mobile.png",
        "investigation-mobile.png",
    ]:
        content = (ROOT / "docs/screenshots" / filename).read_bytes()
        assert content[:8] == b"\x89PNG\r\n\x1a\n", f"Invalid PNG: {filename}"
        width, height = struct.unpack(">II", content[16:24])
        assert width >= 390 and height >= 630
        media.append({"file": filename, "width": width, "height": height})
    with tempfile.TemporaryDirectory(prefix="soc-release-") as directory:
        environment = {**os.environ, "SOC_DB_PATH": str(Path(directory) / "cli.sqlite3")}

        def run(*args):
            return subprocess.run(
                [sys.executable, "-m", "app", *args],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()

        assert "'imported': 553" in run("seed")
        assert "'duplicates': 553" in run("import", "sample_data/security_events.csv")
        for output_format, extension in [("json", "json"), ("html", "html"), ("markdown", "md")]:
            output = Path(directory) / f"report.{extension}"
            run("export", output_format, str(output))
            assert output.stat().st_size > 1000
            if output_format == "json":
                assert json.loads(output.read_text())["alert_count"] == 18
    result = {
        "status": "passed",
        "required_files": len(required),
        "sample_events": 553,
        "sample_formats_equivalent": True,
        "cli_seed_import_exports": "passed",
        "screenshots": media,
    }
    (ROOT / "docs/verification/release-check.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
