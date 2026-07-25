# Plan B Final Report

## 1. Project Objective

This project evaluates a local Python vulnerability scanner that combines deterministic Semgrep findings with Qwen2.5-Coder 7B analysis through Ollama. The objective is to produce reproducible, case-level vulnerability predictions with preserved detector provenance, uncertainty handling, and structured artifacts suitable for review.

The validated scope for Plan B is intentionally narrow: Python benchmark cases for CWE-078 OS command injection and CWE-089 SQL injection. The scanner must not claim complete code security.

## 2. Plan A Baseline

Accepted Plan A run: `20260724T144625Z-fdcefdf2`.

Plan A remains preserved as the baseline comparison artifact. Plan B work does not modify Plan A artifacts.

## 3. Why Plan B Was Introduced

Plan B was introduced after the broader 20-case evaluation exposed a mismatch between benchmark scope and deterministic Semgrep coverage. The local Semgrep ruleset is strongest where explicit deterministic rules exist, while broader CWE categories vary in coverage. Plan B narrows the final evaluation to case classes that were validated during development and are aligned with the implemented local rules and evaluation parser.

## 4. Scope: CWE-078 and CWE-089

Plan B covers:

- `CWE-078`: OS command injection.
- `CWE-089`: SQL injection.

The final holdout contains only these two CWEs, with vulnerable and safe cases represented for each.

## 5. Dataset and Case-Selection Protocol

Source dataset: `data/BenchmarkPython/testcode`.

Labels and CWE metadata are loaded from `evaluation/ground_truth.json`. The final Plan B case list is frozen in `evaluation/plan_b_manifest.json`.

Selection protocol:

- Use the same final eight case IDs for every mode.
- Include only CWE-078 and CWE-089.
- Include vulnerable and safe cases for both CWEs.
- Do not manually edit predictions.
- Do not silently exclude attempted cases.
- Do not use final holdout cases for tuning, pilot scans, or development validation.

## 6. Development Cases

Successful development pilot run: `20260725T070438Z-1ffabe43`.

Pilot cases:

- `BenchmarkTest00268`: vulnerable CWE-078, expected sink line 55.
- `BenchmarkTest00350`: safe CWE-078.
- `BenchmarkTest00099`: vulnerable CWE-089, expected sink line 49.
- `BenchmarkTest00755`: safe CWE-089.

Pilot result summary:

- `semgrep`: TP 2, FP 0, TN 2, FN 0.
- `llm`: TP 2, FP 0, TN 2, FN 0.
- `semgrep_gated`: TP 2, FP 0, TN 2, FN 0.
- `hybrid`: TP 2, FP 0, TN 2, FN 0.

All pilot modes completed four records with zero errors and zero timeouts.

## 7. Final Eight-Case Holdout Design

Final holdout IDs:

- `BenchmarkTest00431`
- `BenchmarkTest00432`
- `BenchmarkTest00900`
- `BenchmarkTest01097`
- `BenchmarkTest00454`
- `BenchmarkTest00455`
- `BenchmarkTest00285`
- `BenchmarkTest00286`

These cases must be run once, after freeze, across all four modes:

- `semgrep`
- `llm`
- `semgrep_gated`
- `hybrid`

Placeholder: final eight-case metrics are not available yet.

## 8. Semgrep Implementation

Semgrep uses the version-controlled local ruleset path:

`semgrep-rules/python`

The frozen metadata records hashes for:

- `semgrep-rules/python/command-injection.yaml`
- `semgrep-rules/python/sql-injection.yaml`
- Deterministic combined hash of `semgrep-rules/python`

The run must not switch to registry config such as `p/python`.

## 9. LLM Validation Design

The LLM mode uses Qwen2.5-Coder 7B via Ollama. Raw full-file LLM responses are parsed through an evaluation-specific parser that preserves raw artifacts while applying deterministic scanner validation for supported Plan B findings.

The evaluation parser repairs schema compatibility for full-file output without weakening normal `AgentAnalysis` validation.

## 10. Hybrid Behavior

Hybrid mode combines independent Semgrep and LLM execution at case level. Hybrid predictions are not inflated by multiple findings. Detector contribution fields record whether Semgrep, LLM, both, or neither contributed.

For Plan B pilot cases, vulnerable findings in Hybrid were contributed by both detectors, and safe cases remained safe.

## 11. Evaluation-Path Defect and Repair

During pre-freeze validation, an evaluation-only defect was found in full-file SQL validation. The frozen detector regex was restored, but the evaluation parser had been passing broad evidence and full-file code into deterministic SQL parameterization validation. In SQL cases, unrelated commas outside the reported sink could make `cur.execute(sql)` look parameterized.

The repair is limited to the full-file evaluation parsing path:

- CWE-089 validation uses the reported sink line or matched sink evidence context.
- The original LLM evidence remains preserved in prediction artifacts.
- Scanner detector logic, prompts, Semgrep rules, mode semantics, and thresholds are unchanged.

## 12. Reproducibility Controls

Freeze metadata path:

`evaluation/plan_b_freeze_metadata.json`

Recorded controls include:

- Branch and pre-freeze HEAD.
- Detector implementation commit.
- Python, Semgrep, Ollama, model, and operating system.
- Accepted Plan A run.
- Successful Plan B pilot run and metrics.
- Full unit-test result.
- SHA-256 hashes for ground truth, manifest, rules, prompts, config, evaluation code, schemas, and reader/API files.

## 13. Test Results

Pre-freeze validation:

- `tests/unit/test_evaluation.py`: 20 passed.
- `tests/unit/test_orchestrator.py`: 44 passed.
- `tests/unit/test_web_api.py`: 19 passed.
- `tests/unit/test_semgrep.py`: 1 passed.
- Full `tests/unit`: 155 passed, 1 skipped.

The full unit suite was run outside the sandbox because local Semgrep tests hang inside the sandbox.

## 14. Pilot Results

Accepted pilot: `20260725T070438Z-1ffabe43`.

Pilot metrics:

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | 2 | 0 | 2 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| llm | 2 | 0 | 2 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| semgrep_gated | 2 | 0 | 2 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| hybrid | 2 | 0 | 2 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |

## 15. Integrity and Leakage Safeguards

Pre-freeze checks confirmed:

- `src/vuln_agent/orchestrator.py` has no diff from the frozen detector implementation.
- Semgrep rules have no diff.
- Prompts have no diff.
- Model settings and evaluation YAML have no diff.
- Plan A artifacts have no diff.
- Final eight IDs have zero hits in `.scan_runtime`.
- Final eight IDs have zero hits in `artifacts/evaluation`.
- Final eight IDs do not appear in source prediction logic.
- Expected labels and expected CWEs are not used to determine live predictions.

## 16. Limitations

Plan B is not a broad security benchmark. It is a scoped, reproducible evaluation of CWE-078 and CWE-089 behavior under the current local rules and LLM validation design.

Known limitations:

- Semgrep coverage is local and deterministic, not comprehensive.
- LLM output remains model-runtime dependent.
- The final holdout has eight cases, so confidence intervals and generalization claims must be cautious.
- Results must not be interpreted as proof that scanned code is secure.

## 17. Final Evaluation Protocol

The final eight-case evaluation must:

- Use `semgrep-rules/python`.
- Use the frozen eight IDs from `evaluation/plan_b_manifest.json`.
- Run all four modes once.
- Retain every attempted case as a prediction or explicit failure record.
- Exclude failed/time-out cases from TP/FP/FN/TN while preserving attempted, completion, error, and timeout counts.
- Avoid manual prediction edits or selective reruns.
- Derive compatibility exports from structured artifacts only.

Placeholder: final eight-case metrics will be filled after the one-time run.

## 18. Extended Confirmatory Evaluation Plan

After the final eight-case holdout is frozen and reported, a separate confirmatory evaluation may be run on a larger predeclared set. That extended run must be clearly labeled as confirmatory and must not be used to alter the frozen eight-case results.

Placeholders for final report completion:

- Final eight-case metrics: pending.
- Per-mode confusion matrices: pending.
- Per-CWE results: pending.
- Strict CWE-aware results: pending.
- Failure analysis: pending.
- Plan A versus Plan B comparison: pending.
- Final conclusion: pending.
