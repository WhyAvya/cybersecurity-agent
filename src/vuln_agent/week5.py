"""Artifact-driven Week 5 trustworthiness derivations.

This module reads a frozen Week 4 evaluation artifact and writes Week 5
derivation-only outputs. It does not call Semgrep, Ollama, or rerun evaluation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import statistics
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .utils import normalize_cwe


MODES = ("semgrep", "llm", "semgrep_gated", "hybrid")
HASHED_WEEK4_FILES = (
    "manifest.json",
    "predictions/all.jsonl",
    "predictions/semgrep.jsonl",
    "predictions/llm.jsonl",
    "predictions/semgrep_gated.jsonl",
    "predictions/hybrid.jsonl",
    "metrics/summary.csv",
    "week4_report.md",
)
IDENTIFIER_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`|\\b(function|variable)\\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)
LINE_RE = re.compile(r"\\bline\\s+(\\d+)\\b", re.I)


@dataclass(frozen=True)
class Week4Artifact:
    path: Path
    predictions: dict[str, list[dict[str, Any]]]
    hashes: dict[str, str]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = fieldnames or (list(rows[0].keys()) if rows else [])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def resolve_artifact_path(path_text: str | None, project_root: Path) -> Path | None:
    if not path_text:
        return None
    if path_text.startswith("/artifacts/"):
        return project_root / "artifacts" / path_text[len("/artifacts/") :]
    if path_text.startswith("/app/"):
        return project_root / path_text[len("/app/") :]
    path = Path(path_text)
    if path.is_absolute():
        return path
    return project_root / path


def resolve_source_path(path_text: str | None, project_root: Path) -> Path | None:
    return resolve_artifact_path(path_text, project_root)


def load_week4_artifact(path: Path, project_root: Path) -> Week4Artifact:
    path = path.resolve()
    missing = [rel for rel in HASHED_WEEK4_FILES if not (path / rel).exists()]
    if missing:
        raise ValueError(f"Frozen Week 4 artifact is missing required files: {missing}")

    predictions = {mode: read_jsonl(path / "predictions" / f"{mode}.jsonl") for mode in MODES}
    validate_frozen_predictions(predictions, project_root)
    hashes = {rel: sha256_file(path / rel) for rel in HASHED_WEEK4_FILES}
    return Week4Artifact(path=path, predictions=predictions, hashes=hashes)


def validate_frozen_predictions(predictions: dict[str, list[dict[str, Any]]], project_root: Path) -> None:
    if set(predictions) != set(MODES):
        raise ValueError("Predictions must contain exactly the four comparison modes")
    ids_by_mode: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    for mode, rows in predictions.items():
        if len(rows) != 60:
            raise ValueError(f"Expected 60 predictions for {mode}, got {len(rows)}")
        ids_by_mode[mode] = {str(row["test_id"]) for row in rows}
        for row in rows:
            key = (mode, str(row["test_id"]))
            if key in seen:
                raise ValueError(f"Duplicate case-mode row: {key}")
            seen.add(key)
            if row.get("error"):
                raise ValueError(f"Frozen prediction contains execution error: {key}: {row['error']}")
            expected_paths: list[str | None] = []
            if mode in {"semgrep", "semgrep_gated", "hybrid"}:
                expected_paths.append(row.get("semgrep_raw_path"))
            if row.get("llm_called"):
                expected_paths.append(row.get("raw_response_path"))
            for raw_path in expected_paths:
                resolved = resolve_artifact_path(raw_path, project_root)
                if resolved is None or not resolved.exists():
                    raise ValueError(f"Missing raw output for {key}: {raw_path}")
    if len({tuple(sorted(ids)) for ids in ids_by_mode.values()}) != 1:
        raise ValueError("The same 60 case IDs must appear in every mode")
    sample = predictions["semgrep"]
    labels = Counter(bool(row["expected_vulnerable"]) for row in sample)
    if labels[True] != 30 or labels[False] != 30:
        raise ValueError(f"Expected 30 vulnerable and 30 safe cases, got {labels}")
    if len(seen) != 240:
        raise ValueError(f"Expected 240 mode-case rows, got {len(seen)}")


def row_correct(row: dict[str, Any]) -> bool:
    return bool(row["expected_vulnerable"]) == bool(row["predicted_vulnerable"])


def confusion_label(row: dict[str, Any]) -> str:
    expected = bool(row["expected_vulnerable"])
    predicted = bool(row["predicted_vulnerable"])
    if expected and predicted:
        return "TP"
    if not expected and predicted:
        return "FP"
    if not expected and not predicted:
        return "TN"
    return "FN"


def normalize_prediction(mode: str, row: dict[str, Any], project_root: Path) -> dict[str, Any]:
    source_file = row.get("source_file") or ""
    semgrep_raw = row.get("semgrep_raw_path") or ""
    llm_raw = row.get("raw_response_path") or ""
    return {
        "case_id": row["test_id"],
        "source_file": source_file,
        "source_path_exists": bool(resolve_source_path(source_file, project_root) and resolve_source_path(source_file, project_root).exists()),
        "ground_truth": "vulnerable" if row["expected_vulnerable"] else "safe",
        "predicted_label": "vulnerable" if row["predicted_vulnerable"] else "safe",
        "mode": mode,
        "cwe_ground_truth": row.get("expected_cwe", "NONE"),
        "cwe_predicted": row.get("predicted_cwe", "NONE"),
        "confidence": row.get("confidence", ""),
        "correct": row_correct(row),
        "confusion": confusion_label(row),
        "error": row.get("error") or "",
        "schema_valid": row.get("schema_valid", ""),
        "llm_called": row.get("llm_called", False),
        "gate_status": "blocked" if row.get("semgrep_gate_triggered") else ("open" if mode == "semgrep_gated" and row.get("llm_called") else ""),
        "semgrep_rule_ids": json.dumps(row.get("semgrep_rule_ids") or []),
        "semgrep_raw_path": semgrep_raw,
        "semgrep_raw_exists": bool(resolve_artifact_path(semgrep_raw, project_root) and resolve_artifact_path(semgrep_raw, project_root).exists()),
        "llm_raw_path": llm_raw,
        "llm_raw_exists": bool(resolve_artifact_path(llm_raw, project_root) and resolve_artifact_path(llm_raw, project_root).exists()),
        "latency_ms": row.get("latency_ms", ""),
        "decision_source": row.get("decision_source", ""),
        "source_code_supplied": row.get("source_code_supplied", ""),
        "semgrep_finding_count": row.get("semgrep_finding_count", ""),
    }


def build_case_rows(artifact: Week4Artifact, project_root: Path) -> list[dict[str, Any]]:
    return [normalize_prediction(mode, row, project_root) for mode in MODES for row in artifact.predictions[mode]]


def build_confusion_cases(case_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {**row, "failure_group": "false_positive" if row["confusion"] == "FP" else ("false_negative" if row["confusion"] == "FN" else "")}
        for row in case_rows
    ]


def build_mode_error_summary(case_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    by_mode: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        by_mode[row["mode"]].append(row)
    for mode in MODES:
        items = by_mode[mode]
        rows.append(
            {
                "mode": mode,
                "total_predictions": len(items),
                "tool_error_count": sum(1 for row in items if row["error"]),
                "schema_invalid_count": sum(1 for row in items if row["schema_valid"] is False),
                "false_positive_count": sum(1 for row in items if row["confusion"] == "FP"),
                "false_negative_count": sum(1 for row in items if row["confusion"] == "FN"),
            }
        )
    return rows


def parse_llm_output(path_text: str, project_root: Path) -> dict[str, Any]:
    path = resolve_artifact_path(path_text, project_root)
    if path is None or not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return {}
    return {}


def raw_semgrep_rule_ids(path_text: str, project_root: Path) -> set[str]:
    path = resolve_artifact_path(path_text, project_root)
    if path is None or not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return set()
    return {str(item.get("check_id", "")) for item in data.get("results", []) if item.get("check_id")}


def classify_failure(row: dict[str, Any], by_case: dict[str, dict[str, dict[str, Any]]]) -> tuple[str, str, str]:
    mode = row["mode"]
    confusion = row["confusion"]
    case_modes = by_case[row["case_id"]]
    if row["error"]:
        return "tool failure", "", "Recorded tool or pipeline error."
    if confusion == "FN" and mode == "semgrep":
        return "Semgrep rule coverage gap", "", "Semgrep produced no vulnerable prediction for a vulnerable benchmark case."
    if confusion == "FN" and mode == "semgrep_gated" and row["gate_status"] == "blocked":
        return "gate-blocked vulnerable case", "Semgrep rule coverage gap", "Semgrep gate blocked LLM review for a vulnerable case."
    if confusion == "FN" and mode == "hybrid":
        return "LLM underprediction", "", "Hybrid LLM decision predicted safe for a vulnerable case."
    if confusion == "FN" and mode == "llm":
        return "LLM underprediction", "", "LLM-only decision predicted safe for a vulnerable case."
    if confusion == "FP" and mode in {"llm", "hybrid"}:
        cwe_mismatch = normalize_cwe(row["cwe_ground_truth"]) != normalize_cwe(row["cwe_predicted"])
        if cwe_mismatch:
            return "CWE mapping error", "LLM overprediction", "Prediction was vulnerable on a safe case and CWE differed from the benchmark label."
        return "LLM overprediction", "", "LLM predicted vulnerable for a benchmark-safe case."
    if confusion == "FP" and mode in {"semgrep", "semgrep_gated"}:
        return "source not recognized", "", "Semgrep-derived mode predicted vulnerable for a benchmark-safe case."
    if mode == "hybrid" and case_modes["semgrep"]["confusion"] == "FN" and row["confusion"] == "TP":
        return "recovered Semgrep miss", "", "Hybrid recovered a case missed by Semgrep."
    return "classification error", "", "Prediction disagrees with ground truth."


def build_failure_rows(case_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    by_case: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in case_rows:
        by_case[row["case_id"]][row["mode"]] = row
    failures = []
    queue = []
    for row in case_rows:
        if row["confusion"] not in {"FP", "FN"}:
            continue
        primary, secondary, evidence = classify_failure(row, by_case)
        review_status = "human-review-pending" if primary in {"classification error", "source not recognized"} else "auto-classified"
        record = {
            "case_id": row["case_id"],
            "mode": row["mode"],
            "ground_truth": row["ground_truth"],
            "prediction": row["predicted_label"],
            "failure_group": "false_positive" if row["confusion"] == "FP" else "false_negative",
            "cwe": row["cwe_ground_truth"],
            "predicted_cwe": row["cwe_predicted"],
            "primary_category": primary,
            "secondary_category": secondary,
            "evidence": evidence,
            "raw_output_path": row["llm_raw_path"] or row["semgrep_raw_path"],
            "source_path": row["source_file"],
            "likely_root_cause": primary,
            "evaluation_impact": row["confusion"],
            "classification_method": "automatic heuristic from frozen predictions",
            "review_status": review_status,
        }
        failures.append(record)
        if review_status == "human-review-pending":
            queue.append(record)
    return failures, queue, summarize_failures(failures)


def summarize_failures(failures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counter = Counter((row["mode"], row["failure_group"], row["primary_category"], row["cwe"]) for row in failures)
    total = len(failures)
    return [
        {
            "mode": mode,
            "failure_group": group,
            "primary_category": category,
            "cwe": cwe,
            "count": count,
            "percentage_of_failures": count / total if total else 0.0,
        }
        for (mode, group, category, cwe), count in sorted(counter.items())
    ]


def source_text(row: dict[str, Any], project_root: Path) -> tuple[str, int]:
    path = resolve_source_path(row.get("source_file"), project_root)
    if path is None or not path.exists():
        return "", 0
    text = path.read_text(encoding="utf-8", errors="replace")
    return text, len(text.splitlines())


def evidence_checks(row: dict[str, Any], project_root: Path) -> tuple[list[dict[str, str]], dict[str, str]]:
    if not row["llm_raw_path"]:
        return [], {}
    parsed = parse_llm_output(row["llm_raw_path"], project_root)
    text, line_count = source_text(row, project_root)
    checks: list[dict[str, str]] = []
    fields = ["reasoning_summary", "source_evidence", "sink_evidence", "data_flow_evidence", "sanitization_evidence"]
    combined = " ".join(str(parsed.get(field, "")) for field in fields)
    for match in LINE_RE.finditer(combined):
        line_no = int(match.group(1))
        if line_count and line_no > line_count:
            checks.append({"type": "factual hallucination", "detail": f"line {line_no} is outside source line count {line_count}"})
    identifiers = {m.group(1) or m.group(3) for m in IDENTIFIER_RE.finditer(combined)}
    for identifier in sorted(filter(None, identifiers)):
        if text and identifier not in text:
            checks.append({"type": "factual hallucination", "detail": f"identifier `{identifier}` not found in source"})
    if re.search(r"sanitiz|validat|escap", combined, re.I) and not re.search(r"sanitiz|validat|escap", text, re.I):
        checks.append({"type": "unsupported reasoning", "detail": "sanitization/validation claim not supported by source keywords"})
    expected_rules = set(json.loads(row["semgrep_rule_ids"] or "[]"))
    if expected_rules and row["semgrep_raw_path"]:
        raw_rules = raw_semgrep_rule_ids(row["semgrep_raw_path"], project_root)
        missing = expected_rules - raw_rules
        if missing:
            checks.append({"type": "factual hallucination", "detail": f"Semgrep rule IDs absent from raw Semgrep output: {sorted(missing)}"})
    if normalize_cwe(row["cwe_predicted"]) != "NONE" and normalize_cwe(row["cwe_predicted"]) != normalize_cwe(row["cwe_ground_truth"]):
        checks.append({"type": "CWE mapping error", "detail": "predicted CWE differs from benchmark CWE"})
    if row["confusion"] in {"FP", "FN"} and not checks:
        checks.append({"type": "classification error", "detail": "incorrect label without directly verifiable hallucination evidence"})
    return checks, parsed


def build_hallucination_rows(case_rows: list[dict[str, Any]], project_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_rows = []
    hallucination_rows = []
    for row in case_rows:
        if row["mode"] not in {"llm", "semgrep_gated", "hybrid"} or not row["llm_raw_path"]:
            continue
        checks, parsed = evidence_checks(row, project_root)
        if not checks:
            checks = [{"type": "ambiguous evidence", "detail": "no unsupported evidence detected by automatic checks"}]
        for check in checks:
            output = {
                "case_id": row["case_id"],
                "mode": row["mode"],
                "ground_truth": row["ground_truth"],
                "prediction": row["predicted_label"],
                "confusion": row["confusion"],
                "check_type": check["type"],
                "detail": check["detail"],
                "raw_output_path": row["llm_raw_path"],
                "source_path": row["source_file"],
                "review_status": "human-review-pending" if check["type"] in {"ambiguous evidence", "unsupported reasoning"} else "auto-classified",
                "reasoning_summary": parsed.get("reasoning_summary", ""),
            }
            evidence_rows.append(output)
            if check["type"] in {"factual hallucination", "unsupported reasoning", "CWE mapping error", "ambiguous evidence"}:
                hallucination_rows.append(output)
    return hallucination_rows, evidence_rows


def calibration_rows(case_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for mode in MODES:
        items = [row for row in case_rows if row["mode"] == mode]
        numeric = [float(row["confidence"]) for row in items if row["confidence"] != ""]
        if not numeric or len(set(numeric)) <= 1:
            rows.append({"mode": mode, "confidence_measurable": False, "reason": "missing or constant confidence values"})
            continue
        correct_conf = [float(row["confidence"]) for row in items if row["confidence"] != "" and row["correct"]]
        incorrect_conf = [float(row["confidence"]) for row in items if row["confidence"] != "" and not row["correct"]]
        rows.append(
            {
                "mode": mode,
                "confidence_measurable": True,
                "mean_confidence_correct": statistics.fmean(correct_conf) if correct_conf else "",
                "mean_confidence_incorrect": statistics.fmean(incorrect_conf) if incorrect_conf else "",
                "overconfident_error_count": sum(1 for row in items if row["confidence"] != "" and not row["correct"] and float(row["confidence"]) >= 0.8),
                "reason": "",
            }
        )
    return rows


def create_manifest(output_dir: Path, week4: Week4Artifact, project_root: Path) -> dict[str, Any]:
    def capture(command: list[str], timeout: int) -> str:
        try:
            result = subprocess.run(command, cwd=project_root, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return "not-recorded"
        return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else "not-recorded"

    commit = capture(["git", "rev-parse", "HEAD"], 10)
    branch = capture(["git", "branch", "--show-current"], 10)
    image_id = capture(["docker", "image", "inspect", "cybersecurity-agent-app:latest", "--format", "{{.Id}}"], 20)
    return {
        "week5_experiment_id": output_dir.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": commit,
        "git_branch": branch,
        "source_week4_artifact_path": str(week4.path),
        "source_week4_hashes": week4.hashes,
        "docker_image_name": "cybersecurity-agent-app:latest",
        "docker_image_id": image_id,
        "python_version": "recorded by test/runtime environment",
        "ollama_url": "http://host.docker.internal:11434",
        "model_name": "qwen2.5-coder:7b",
        "model_parameters": {"temperature": 0, "seed": 42, "num_ctx": 2048},
        "prompt_hashes": {},
        "consistency_subset_seed": 42,
        "prompt_sensitivity_subset_seed": 42,
        "repetition_count": 3,
        "timeout_settings": {"ollama_timeout_seconds": 120, "semgrep_timeout_seconds": 120},
        "analysis_methods": ["frozen prediction derivation", "heuristic failure taxonomy", "automatic evidence checks"],
        "limitations": [
            "No new LLM or Semgrep calls were made in derivation-only phases.",
            "Failure and hallucination labels are automatic unless marked Codex-inspected later.",
            "Human review is pending for uncertain or ambiguous cases.",
        ],
        "human_review_status_definitions": {
            "auto-classified": "Assigned by deterministic heuristics.",
            "Codex-inspected": "Inspected by Codex from saved artifacts.",
            "human-review-pending": "Requires a human reviewer.",
            "human-reviewed": "Reserved for actual human review; not used by this generator.",
        },
    }


def write_report(output_dir: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Week 5 Derivation-Only Trustworthiness Artifact",
        "",
        "This artifact reads the frozen Week 4 run and derives failure, evidence, and reliability tables.",
        "No Semgrep, Ollama, or evaluation reruns were performed for these phases.",
        "",
        f"- Case-mode rows: {summary['case_rows']}",
        f"- False positives: {summary['false_positives']}",
        f"- False negatives: {summary['false_negatives']}",
        f"- Human-review queue size: {summary['human_review_queue']}",
        "",
        "## Generated Files",
        "",
    ]
    for path in summary["created_files"]:
        lines.append(f"- `{path}`")
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def artifact_index(output_dir: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file():
            row_count = ""
            if path.suffix == ".csv":
                row_count = max(0, sum(1 for _ in path.open(encoding="utf-8")) - 1)
            elif path.suffix == ".jsonl":
                row_count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
            rows.append(
                {
                    "file_path": str(path.relative_to(output_dir)),
                    "description": "Week 5 derived artifact",
                    "source": "frozen Week 4 artifact" if "raw_responses" not in str(path) else "new Week 5 experiment",
                    "generated_time": datetime.now(timezone.utc).isoformat(),
                    "row_count": row_count,
                    "sha256": sha256_file(path),
                }
            )
    return rows


def run_derivation(week4_path: Path, output_root: Path, project_root: Path, timestamp: str | None = None) -> Path:
    week4 = load_week4_artifact(week4_path, project_root)
    experiment_id = (timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")) + "-week5-final"
    output_dir = output_root / experiment_id
    output_dir.mkdir(parents=True, exist_ok=False)
    manifest = create_manifest(output_dir, week4, project_root)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    case_rows = build_case_rows(week4, project_root)
    if len(case_rows) != 240:
        raise ValueError(f"Expected 240 normalized case rows, got {len(case_rows)}")
    write_csv(output_dir / "case_results.csv", case_rows)
    write_jsonl(output_dir / "case_results.jsonl", case_rows)

    confusion_rows = build_confusion_cases(case_rows)
    fp_rows = [row for row in confusion_rows if row["confusion"] == "FP"]
    fn_rows = [row for row in confusion_rows if row["confusion"] == "FN"]
    write_csv(output_dir / "false_positives.csv", fp_rows)
    write_csv(output_dir / "false_negatives.csv", fn_rows)
    write_csv(output_dir / "confusion_cases.csv", confusion_rows)
    write_csv(output_dir / "mode_error_summary.csv", build_mode_error_summary(case_rows))

    failure_rows, human_queue, failure_summary = build_failure_rows(case_rows)
    write_csv(output_dir / "failure_cases.csv", failure_rows)
    write_csv(output_dir / "human_review_queue.csv", human_queue)
    write_csv(output_dir / "failure_category_summary.csv", failure_summary)
    write_csv(output_dir / "failure_taxonomy.csv", failure_summary)
    (output_dir / "failure_taxonomy.json").write_text(json.dumps(failure_summary, indent=2), encoding="utf-8")
    (output_dir / "failure_examples.md").write_text("\n".join(f"- {row['case_id']} / {row['mode']}: {row['primary_category']}" for row in failure_rows[:20]), encoding="utf-8")

    hallucination_rows, evidence_rows = build_hallucination_rows(case_rows, project_root)
    write_csv(output_dir / "hallucination_cases.csv", hallucination_rows)
    write_csv(output_dir / "evidence_validation.csv", evidence_rows)
    summary_counter = Counter(row["check_type"] for row in hallucination_rows)
    hallucination_summary = [{"check_type": key, "count": value} for key, value in sorted(summary_counter.items())]
    write_csv(output_dir / "hallucination_summary.csv", hallucination_summary)
    (output_dir / "hallucination_examples.md").write_text("\n".join(f"- {row['case_id']} / {row['mode']}: {row['check_type']} - {row['detail']}" for row in hallucination_rows[:20]), encoding="utf-8")

    write_csv(output_dir / "calibration_summary.csv", calibration_rows(case_rows))

    summary = {
        "case_rows": len(case_rows),
        "false_positives": len(fp_rows),
        "false_negatives": len(fn_rows),
        "human_review_queue": len(human_queue),
        "created_files": [],
    }
    write_report(output_dir, summary)
    index_rows = artifact_index(output_dir)
    write_csv(output_dir / "artifact_index.csv", index_rows)
    summary["created_files"] = [row["file_path"] for row in index_rows]
    write_report(output_dir, summary)
    write_csv(output_dir / "artifact_index.csv", artifact_index(output_dir))
    return output_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate derivation-only Week 5 artifacts from frozen Week 4 outputs.")
    parser.add_argument("--week4-artifact", default="artifacts/evaluation/20260720T083753Z-df296df1")
    parser.add_argument("--output-root", default="artifacts/trustworthiness")
    args = parser.parse_args(argv)
    project_root = Path.cwd()
    output_dir = run_derivation(Path(args.week4_artifact), Path(args.output_root), project_root)
    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
