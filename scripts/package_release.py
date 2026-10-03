"""Create a source-only ZIP and checksums; never include the working database."""

import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_PARTS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "test-results",
    "playwright-report",
    "htmlcov",
    "data",
    "dist",
    "build",
}
SKIP_NAMES = {".coverage", "coverage.xml", ".DS_Store", "Thumbs.db", "MANIFEST_SHA256.json"}
SKIP_SUFFIXES = {".pyc", ".db", ".sqlite3", ".log", ".zip"}


def main():
    files = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if (
            not path.is_file()
            or any(part in SKIP_PARTS or part.endswith(".egg-info") for part in relative.parts)
            or path.name in SKIP_NAMES
            or path.suffix in SKIP_SUFFIXES
            or path.name.startswith(".env")
            or ".sqlite3-" in path.name
        ):
            continue
        files.append(path)
    manifest = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    manifest_path = ROOT / "MANIFEST_SHA256.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    files.append(manifest_path)
    output = ROOT.parent / "SOC-Security-Operations-Dashboard.zip"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            archive.write(path, str(Path(ROOT.name) / path.relative_to(ROOT)))
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None
        assert not any(
            "/data/" in name or ".sqlite3" in name or "__pycache__" in name for name in archive.namelist()
        )
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(
        json.dumps(
            {"zip": str(output), "bytes": output.stat().st_size, "files": len(files), "sha256": digest},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
