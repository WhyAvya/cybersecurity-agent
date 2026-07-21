import json
from pathlib import Path

import pytest

from vuln_agent.week5 import (
    build_case_rows,
    build_confusion_cases,
    build_failure_rows,
    build_hallucination_rows,
    calibration_rows,
    load_week4_artifact,
    run_derivation,
    sha256_file,
    validate_frozen_predictions,
)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def _make_artifact(tmp_path: Path, duplicate: bool = False) -> Path:
    root = tmp_path
    artifact = root / "artifacts" / "evaluation" / "frozen"
    raw_root = artifact / "raw_responses"
    source = root / "data" / "BenchmarkPython" / "testcode" / "Case000.py"
    source.parent.mkdir(parents=True)
    source.write_text("def handler():\n    safe_value = 'ok'\n    return safe_value\n", encoding="utf-8")
    raw_semgrep = raw_root / "semgrep" / "Case000.semgrep.json"
    raw_semgrep.parent.mkdir(parents=True)
    raw_semgrep.write_text(json.dumps({"results": [{"check_id": "rule.one"}]}), encoding="utf-8")
    raw_llm = raw_root / "llm" / "Case000.txt"
    raw_llm.parent.mkdir(parents=True)
    raw_llm.write_text(
        json.dumps(
            {
                "verdict": "TP",
                "confidence": 0.9,
                "normalized_cwe": "CWE-089",
                "reasoning_summary": "Uses `missing_identifier` on line 99 with validation.",
                "remediation": "",
                "source_evidence": "",
                "sink_evidence": "",
                "data_flow_evidence": "",
                "sanitization_evidence": "validation exists",
                "needs_more_context": False,
            }
        ),
        encoding="utf-8",
    )
    rows = []
    for index in range(60):
        case = f"Case{index:03d}"
        expected = index < 30
        predicted = index % 3 == 0
        rows.append(
            {
                "test_id": case,
                "expected_vulnerable": expected,
                "predicted_vulnerable": predicted,
                "expected_cwe": "CWE-089" if expected else "CWE-022",
                "predicted_cwe": "CWE-089" if predicted else "NONE",
                "confidence": 0.9 if predicted else 0.1,
                "latency_ms": index,
                "schema_valid": True,
                "raw_response": None,
                "source_file": "data/BenchmarkPython/testcode/Case000.py",
                "semgrep_finding_count": 1 if predicted else 0,
                "semgrep_rule_ids": ["rule.one"] if predicted else [],
                "llm_called": False,
                "decision_source": "",
                "source_code_supplied": False,
                "semgrep_gate_triggered": False,
                "raw_response_path": None,
                "semgrep_raw_path": "/artifacts/evaluation/frozen/raw_responses/semgrep/Case000.semgrep.json",
                "error": None,
            }
        )
    mode_rows = {}
    for mode in ("semgrep", "llm", "semgrep_gated", "hybrid"):
        copied = [dict(row) for row in rows]
        if mode in {"llm", "hybrid"}:
            for row in copied:
                row["llm_called"] = True
                row["raw_response_path"] = "/artifacts/evaluation/frozen/raw_responses/llm/Case000.txt"
        if mode == "llm":
            for row in copied:
                row["semgrep_raw_path"] = None
                row["semgrep_rule_ids"] = []
        if duplicate:
            copied[1]["test_id"] = copied[0]["test_id"]
        mode_rows[mode] = copied
        _write_jsonl(artifact / "predictions" / f"{mode}.jsonl", copied)
    _write_jsonl(artifact / "predictions" / "all.jsonl", mode_rows["hybrid"])
    (artifact / "metrics").mkdir(parents=True)
    (artifact / "metrics" / "summary.csv").write_text("mode,tp,fp,tn,fn\nsemgrep,0,0,0,0\n", encoding="utf-8")
    (artifact / "manifest.json").write_text("{}", encoding="utf-8")
    (artifact / "week4_report.md").write_text("# report\n", encoding="utf-8")
    return artifact


def test_load_week4_artifact_and_hashes(tmp_path: Path):
    artifact = _make_artifact(tmp_path)
    loaded = load_week4_artifact(artifact, tmp_path)
    assert len(loaded.predictions["semgrep"]) == 60
    assert loaded.hashes["manifest.json"] == sha256_file(artifact / "manifest.json")


def test_duplicate_detection(tmp_path: Path):
    artifact = _make_artifact(tmp_path, duplicate=True)
    predictions = {mode: [json.loads(line) for line in (artifact / "predictions" / f"{mode}.jsonl").read_text().splitlines()] for mode in ("semgrep", "llm", "semgrep_gated", "hybrid")}
    with pytest.raises(ValueError, match="Duplicate"):
        validate_frozen_predictions(predictions, tmp_path)


def test_case_rows_and_fp_fn_extraction(tmp_path: Path):
    artifact = load_week4_artifact(_make_artifact(tmp_path), tmp_path)
    rows = build_case_rows(artifact, tmp_path)
    assert len(rows) == 240
    assert {row["mode"] for row in rows} == {"semgrep", "llm", "semgrep_gated", "hybrid"}
    confusion = build_confusion_cases(rows)
    assert any(row["confusion"] == "FP" for row in confusion)
    assert any(row["confusion"] == "FN" for row in confusion)


def test_taxonomy_output_schema(tmp_path: Path):
    artifact = load_week4_artifact(_make_artifact(tmp_path), tmp_path)
    failures, queue, summary = build_failure_rows(build_case_rows(artifact, tmp_path))
    assert failures
    assert {"case_id", "mode", "primary_category", "review_status"}.issubset(failures[0])
    assert summary
    assert all(row["review_status"] != "human-reviewed" for row in failures + queue)


def test_hallucination_evidence_checks(tmp_path: Path):
    artifact = load_week4_artifact(_make_artifact(tmp_path), tmp_path)
    hallucinations, evidence = build_hallucination_rows(build_case_rows(artifact, tmp_path), tmp_path)
    assert hallucinations
    assert any("missing_identifier" in row["detail"] or "line 99" in row["detail"] for row in evidence)


def test_missing_or_constant_confidence_is_not_measurable():
    rows = [
        {"mode": "llm", "confidence": "", "correct": True},
        {"mode": "llm", "confidence": "", "correct": False},
        {"mode": "semgrep", "confidence": 1.0, "correct": True},
        {"mode": "semgrep", "confidence": 1.0, "correct": False},
    ]
    rows.extend({"mode": mode, "confidence": "", "correct": True} for mode in ["semgrep_gated", "hybrid"])
    result = calibration_rows(rows)
    assert all("confidence_measurable" in row for row in result)


def test_run_derivation_writes_expected_outputs(tmp_path: Path):
    artifact = _make_artifact(tmp_path)
    output = run_derivation(artifact, tmp_path / "artifacts" / "trustworthiness", tmp_path, timestamp="20260101T000000Z")
    assert (output / "manifest.json").exists()
    assert (output / "case_results.csv").exists()
    assert (output / "case_results.jsonl").exists()
    assert (output / "false_positives.csv").exists()
    assert (output / "false_negatives.csv").exists()
    assert (output / "failure_taxonomy.csv").exists()
    assert (output / "hallucination_cases.csv").exists()
    assert (output / "human_review_queue.csv").exists()
