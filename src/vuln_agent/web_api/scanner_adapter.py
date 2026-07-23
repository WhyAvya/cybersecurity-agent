"""Thin scanner adapter that delegates to the canonical orchestrator."""

from __future__ import annotations

import json
from pathlib import Path

from vuln_agent.config import Settings
from vuln_agent.orchestrator import VulnerabilityOrchestrator

from .models import Artifact


def run_existing_scan(target: Path, output_dir: Path, mode: str, save_raw: bool, base_settings: Settings):
    settings = base_settings.model_copy(
        update={
            "allowed_scan_root": target.resolve(),
            "allow_scan_root_escape": False,
            "report_dir": output_dir.parent,
        }
    )
    return VulnerabilityOrchestrator(settings).scan(target, output_dir=output_dir, offline=False, mode=mode, save_raw=save_raw)


def result_payload(records, output_dir: Path, source_root: Path) -> dict:
    findings = [record.model_dump(mode="json") for record in records]
    files = {}
    for path in sorted(source_root.rglob("*.py")):
        if path.is_file() and not path.is_symlink():
            rel = path.relative_to(source_root).as_posix()
            files[rel] = path.read_text(encoding="utf-8", errors="replace")
    accepted = [item for item in findings if item.get("status") == "ACCEPTED"]
    review = [item for item in findings if item.get("status") == "NEEDS_REVIEW"]
    errors = [item for item in findings if item.get("status") == "ERROR"]
    manifest = {}
    manifest_path = output_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.pop("configuration", None)
    return {
        "status_label": _status_label(findings),
        "summary": {
            "files_scanned": len(files),
            "files_with_findings": len({item.get("relative_file") for item in findings}),
            "total_grouped_findings": len(findings),
            "potentially_vulnerable_findings": len(accepted),
            "review_required_findings": len(review),
            "semgrep_matches": sum(1 for item in findings if "semgrep" in item.get("detectors", [])),
            "llm_matches": sum(1 for item in findings if "llm" in item.get("detectors", [])),
            "detector_agreements": sum(1 for item in findings if item.get("agreement_status") == "detectors_agree"),
            "errors": len(errors),
        },
        "findings": findings,
        "source_files": files,
        "manifest": manifest,
    }


def list_artifacts(output_dir: Path) -> list[Artifact]:
    categories = {
        "scan_report.md": "Human-readable report",
        "scan_report.jsonl": "Machine-readable output",
        "raw_findings.jsonl": "Machine-readable output",
        "manifest.json": "Reproducibility metadata",
    }
    artifacts: list[Artifact] = []
    for path in output_dir.rglob("*"):
        if path.is_file():
            rel = path.relative_to(output_dir).as_posix()
            category = categories.get(rel, "Raw detector evidence" if rel.startswith("raw/") else "Reproducibility metadata")
            artifacts.append(Artifact(name=path.name, category=category, path=rel, size=path.stat().st_size))
    return artifacts


def _status_label(findings: list[dict]) -> str:
    if any(item.get("status") == "ERROR" for item in findings):
        return "Scan completed with errors"
    if any(item.get("status") == "NEEDS_REVIEW" for item in findings):
        return "Manual review recommended"
    if findings:
        return "Potential vulnerabilities detected"
    return "No findings detected"
