"""Read frozen evaluation artifacts without regenerating them."""

from __future__ import annotations

import csv
from pathlib import Path

RUN_ID = "20260722T152729Z-ed7e47fb"


def read_frozen_evaluation(root: Path) -> dict:
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

