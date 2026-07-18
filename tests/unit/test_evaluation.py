import json
from pathlib import Path

from vuln_agent.config import Settings
from vuln_agent.evaluation import (
    bootstrap_confidence_intervals,
    calculate_metrics,
    failure_records,
    per_cwe_metrics,
    run_evaluation,
    stratified_sample_ids,
)
from vuln_agent.schemas import EvaluationPrediction


def test_stratified_sample_is_deterministic():
    ground_truth = {
        "a": {"vulnerable": True, "cwe": "CWE-089"},
        "b": {"vulnerable": True, "cwe": "CWE-022"},
        "c": {"vulnerable": False, "cwe": "NONE"},
        "d": {"vulnerable": False, "cwe": "NONE"},
    }
    assert stratified_sample_ids(ground_truth, 3, 7) == stratified_sample_ids(ground_truth, 3, 7)


def test_metrics_handle_binary_counts():
    metrics = calculate_metrics(
        [
            EvaluationPrediction(test_id="tp", expected_vulnerable=True, predicted_vulnerable=True),
            EvaluationPrediction(test_id="fp", expected_vulnerable=False, predicted_vulnerable=True),
            EvaluationPrediction(test_id="tn", expected_vulnerable=False, predicted_vulnerable=False),
            EvaluationPrediction(test_id="fn", expected_vulnerable=True, predicted_vulnerable=False),
        ]
    )
    assert metrics.tp == 1
    assert metrics.fp == 1
    assert metrics.tn == 1
    assert metrics.fn == 1
    assert metrics.precision == 0.5


def test_per_cwe_metrics_groups_predictions():
    rows = per_cwe_metrics(
        [
            EvaluationPrediction(
                test_id="a",
                expected_vulnerable=True,
                predicted_vulnerable=True,
                expected_cwe="CWE-89",
            ),
            EvaluationPrediction(
                test_id="b",
                expected_vulnerable=False,
                predicted_vulnerable=False,
                expected_cwe="NONE",
            ),
        ]
    )
    assert {row["cwe"] for row in rows} == {"CWE-089", "NONE"}


def test_confidence_intervals_are_deterministic():
    predictions = [
        EvaluationPrediction(test_id="a", expected_vulnerable=True, predicted_vulnerable=True),
        EvaluationPrediction(test_id="b", expected_vulnerable=False, predicted_vulnerable=False),
    ]
    assert bootstrap_confidence_intervals(predictions, seed=1) == bootstrap_confidence_intervals(predictions, seed=1)


def test_failure_records_include_prediction_errors():
    records = failure_records(
        [EvaluationPrediction(test_id="x", expected_vulnerable=True, predicted_vulnerable=False)]
    )
    assert records
    assert records[0].test_id == "x"


def test_run_evaluation_writes_artifacts_without_placeholders(tmp_path: Path):
    truth_path = tmp_path / "ground_truth.json"
    truth_path.write_text(
        json.dumps(
            {
                "BenchmarkTest00001": {"vulnerable": True, "cwe": "CWE-022"},
                "BenchmarkTest00002": {"vulnerable": False, "cwe": "NONE"},
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(
        artifact_root=tmp_path / "artifacts",
        evaluation_dir=tmp_path / "artifacts" / "evaluation",
        ground_truth_path=truth_path,
    )
    output_dir = run_evaluation(settings, "all", sample_size=2, offline=True, project_root=tmp_path)
    assert (output_dir / "manifest.json").exists()
    assert (output_dir / "predictions" / "all.jsonl").exists()
    assert (output_dir / "predictions" / "semgrep.jsonl").exists()
    assert (output_dir / "predictions" / "llm.jsonl").exists()
    assert (output_dir / "predictions" / "hybrid.jsonl").exists()
    assert (output_dir / "metrics" / "summary.csv").exists()
    assert (output_dir / "metrics" / "confidence_intervals.csv").exists()
    assert (output_dir / "metrics" / "per_cwe.csv").exists()
    assert (output_dir / "metrics" / "failures.csv").exists()
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["fair_comparison"] is True
    week5 = (output_dir / "week5_report.md").read_text(encoding="utf-8")
    assert "{" not in week5
    assert "}" not in week5
