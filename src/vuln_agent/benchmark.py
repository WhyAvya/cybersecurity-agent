"""Benchmark ground-truth validation helpers."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import urllib.request
from pathlib import Path

from .utils import normalize_cwe


REQUIRED_COLUMNS = {"test_id", "vulnerable", "cwe"}


def ground_truth_from_csv(csv_path: Path) -> dict[str, dict[str, object]]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"ground-truth CSV missing columns: {', '.join(sorted(missing))}")
        rows: dict[str, dict[str, object]] = {}
        for row in reader:
            test_id = (row.get("test_id") or "").strip()
            if not test_id:
                raise ValueError("ground-truth CSV contains an empty test_id")
            if test_id in rows:
                raise ValueError(f"duplicate test_id: {test_id}")
            vulnerable_text = str(row.get("vulnerable", "")).strip().lower()
            vulnerable = vulnerable_text in {"1", "true", "yes", "vulnerable"}
            rows[test_id] = {
                "vulnerable": vulnerable,
                "cwe": normalize_cwe(row.get("cwe")),
            }
    if not rows:
        raise ValueError("ground-truth CSV contains no rows")
    return rows


def write_ground_truth_json(csv_path: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(ground_truth_from_csv(csv_path), indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_checksum(path: Path, expected_sha256: str | None) -> str:
    actual = sha256_file(path)
    if expected_sha256 and actual.lower() != expected_sha256.lower():
        raise ValueError(f"checksum mismatch for {path}: expected {expected_sha256}, got {actual}")
    return actual


def bootstrap_benchmark(source: str, output_path: Path, expected_sha256: str | None = None) -> str:
    """Copy or download a benchmark artifact and verify its checksum."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=60) as response, output_path.open("wb") as handle:  # nosec B310
            shutil.copyfileobj(response, handle)
    else:
        shutil.copyfile(Path(source), output_path)
    return verify_checksum(output_path, expected_sha256)
