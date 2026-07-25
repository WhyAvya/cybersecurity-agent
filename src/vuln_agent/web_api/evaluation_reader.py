"""Read frozen evaluation artifacts without regenerating them."""

from __future__ import annotations

import csv
import json
from pathlib import Path

RUN_ID = "20260722T152729Z-ed7e47fb"


def read_frozen_evaluation(root: Path, explicit_run_path: str | Path | None = None) -> dict:
    run_dir = _resolve_run_dir(root, explicit_run_path)
    if explicit_run_path is not None:
        return _read_canonical_run(run_dir)
    if (root / "manifest.json").exists():
        return _read_canonical_run(root)
    run_dir = root / RUN_ID
    required = {
        "summary": run_dir / "TRUE_HYBRID_20_CASE_SUMMARY.md",
        "comparison": run_dir / "final_mode_comparison.csv",
        "agreement": run_dir / "hybrid_agreement_summary.csv",
        "errors": run_dir / "actual_error_summary.csv",
    }
    missing = [name for name, path in required.items() if not path.exists()]
    if missing:
        return {"available": False, "run_id": RUN_ID, "error": f"Missing frozen artifact files: {', '.join(missing)}", "path": "artifacts/evaluation/" + RUN_ID}
    with required["comparison"].open(newline="", encoding="utf-8") as handle:
        comparison = list(csv.DictReader(handle))
    with required["agreement"].open(newline="", encoding="utf-8") as handle:
        agreement = list(csv.DictReader(handle))
    with required["errors"].open(newline="", encoding="utf-8") as handle:
        errors = list(csv.DictReader(handle))
    return {
        "available": True,
        "run_id": RUN_ID,
        "label": "Frozen benchmark evaluation - not live scan performance",
        "summary_markdown": required["summary"].read_text(encoding="utf-8"),
        "mode_comparison": comparison,
        "hybrid_agreement": agreement,
        "runtime_errors": errors,
        "conclusion": "In this 20-case pilot, the true hybrid mode matched the LLM because Semgrep did not contribute additional positive detections. Semgrep showed higher precision and lower recall, while the LLM and hybrid showed higher recall with more false positives. The sample is small, and these results should not be interpreted as universal performance.",
    }


def _resolve_run_dir(root: Path, explicit_run_path: str | Path | None) -> Path:
    if explicit_run_path is None:
        return root
    candidate = Path(explicit_run_path)
    if candidate.is_absolute():
        return candidate
    if candidate.exists():
        return candidate
    return root / candidate


def _read_canonical_run(run_dir: Path) -> dict:
    required = {
        "manifest": run_dir / "manifest.json",
        "summary": run_dir / "metrics" / "summary.csv",
        "per_cwe": run_dir / "metrics" / "per_cwe.csv",
    }
    modes = ("semgrep", "llm", "semgrep_gated", "hybrid")
    for mode in modes:
        required[f"predictions_{mode}"] = run_dir / "predictions" / f"{mode}.jsonl"
    missing = [name for name, path in required.items() if not path.exists()]
    run_id = run_dir.name
    if missing:
        return {
            "available": False,
            "run_id": run_id,
            "error": f"Missing canonical evaluation artifact files: {', '.join(missing)}",
            "path": str(run_dir).replace("\\", "/"),
        }
    manifest = json.loads(required["manifest"].read_text(encoding="utf-8"))
    with required["summary"].open(newline="", encoding="utf-8") as handle:
        summary_rows = list(csv.DictReader(handle))
    with required["per_cwe"].open(newline="", encoding="utf-8") as handle:
        per_cwe_rows = list(csv.DictReader(handle))
    predictions = {
        mode: [json.loads(line) for line in required[f"predictions_{mode}"].read_text(encoding="utf-8").splitlines() if line.strip()]
        for mode in modes
    }
    return {
        "available": True,
        "run_id": str(manifest.get("run_id") or run_id),
        "label": "Canonical evaluation artifacts",
        "summary_markdown": _canonical_summary_markdown(manifest, summary_rows),
        "mode_comparison": summary_rows,
        "hybrid_agreement": _hybrid_agreement_rows(predictions.get("hybrid", [])),
        "runtime_errors": _runtime_error_rows(predictions),
        "per_cwe": per_cwe_rows,
        "manifest": manifest,
        "path": str(run_dir).replace("\\", "/"),
        "conclusion": "Metrics are derived from canonical manifest, metrics, and prediction artifacts for this configured evaluation run.",
    }


def _canonical_summary_markdown(manifest: dict, rows: list[dict[str, str]]) -> str:
    lines = [
        f"# Evaluation Run {manifest.get('run_id', '')}",
        "",
        f"Mode: `{manifest.get('mode', '')}`",
        f"Sample size: `{manifest.get('sample_size', '')}`",
        "",
        "| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('mode', '')} | {row.get('tp', '')} | {row.get('fp', '')} | {row.get('tn', '')} | {row.get('fn', '')} | "
            f"{row.get('precision', '')} | {row.get('recall', '')} | {row.get('f1', '')} | {row.get('accuracy', '')} |"
        )
    return "\n".join(lines)


def _hybrid_agreement_rows(rows: list[dict]) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get("detector_agreement") or row.get("decision_source") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"agreement": key, "count": count} for key, count in sorted(counts.items())]


def _runtime_error_rows(predictions: dict[str, list[dict]]) -> list[dict[str, object]]:
    errors = []
    for mode, rows in predictions.items():
        for row in rows:
            if row.get("error"):
                errors.append({"mode": mode, "test_id": row.get("test_id"), "error": row.get("error")})
    return errors
