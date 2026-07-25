# Plan B Final Report

## 1. Project Objective

This project evaluates a local Python vulnerability scanner that combines deterministic Semgrep findings with Qwen2.5-Coder 7B analysis through Ollama. The objective is to produce reproducible, case-level vulnerability predictions with preserved detector provenance, uncertainty handling, and structured artifacts suitable for review.

The validated Plan B scope is Python benchmark behavior for CWE-078 OS command injection and CWE-089 SQL injection. The scanner must not claim that code is completely secure.

## 2. Plan A Baseline

Accepted Plan A run: `20260724T144625Z-fdcefdf2`.

Plan A used a broader 20-case run across ten CWE categories. Persisted Plan A summary metrics were:

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | 0 | 0 | 10 | 10 | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 |
| llm | 9 | 9 | 1 | 1 | 0.500 | 0.900 | 0.643 | 0.500 | 0.900 |
| semgrep_gated | 0 | 0 | 10 | 10 | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 |
| hybrid | 9 | 9 | 1 | 1 | 0.500 | 0.900 | 0.643 | 0.500 | 0.900 |

Plan A artifacts remain preserved and unchanged.

## 3. Why Plan B Was Introduced

Plan B was introduced after the broader 20-case evaluation exposed a mismatch between benchmark scope and deterministic Semgrep coverage. The local Semgrep ruleset is strongest where explicit deterministic rules exist, while broader CWE categories vary in coverage. Plan B narrows the final evaluation to case classes aligned with implemented local rules and the evaluation parser.

## 4. Scope: CWE-078 and CWE-089

Plan B covers:

- `CWE-078`: OS command injection.
- `CWE-089`: SQL injection.

The final holdout contains vulnerable and safe cases for both CWEs. The result is scoped evidence, not universal scanner performance.

## 5. Dataset and Case-Selection Protocol

Source dataset: `data/BenchmarkPython/testcode`.

Labels and CWE metadata are loaded from `evaluation/ground_truth.json`. The frozen Plan B case list is stored in `evaluation/plan_b_manifest.json`.

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

- `BenchmarkTest00268`: vulnerable CWE-078, sink line 55.
- `BenchmarkTest00350`: safe CWE-078.
- `BenchmarkTest00099`: vulnerable CWE-089, sink line 49.
- `BenchmarkTest00755`: safe CWE-089.

Pilot metrics:

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| llm | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| semgrep_gated | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| hybrid | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |

Pilot results are development validation only and are distinct from the final holdout.

## 7. Final Eight-Case Holdout Design

Official final run: `20260725T073500Z-b7fc6d9f`.

Run path: `artifacts/evaluation/plan-b-final/20260725T073500Z-b7fc6d9f`.

Final holdout IDs:

- `BenchmarkTest00431`
- `BenchmarkTest00432`
- `BenchmarkTest00900`
- `BenchmarkTest01097`
- `BenchmarkTest00454`
- `BenchmarkTest00455`
- `BenchmarkTest00285`
- `BenchmarkTest00286`

The run completed all four modes with 32 total case executions.

## 8. Semgrep Implementation

Semgrep uses the version-controlled local ruleset path:

`semgrep-rules/python`

The run did not switch to a registry config such as `p/python`. Result metadata records the ruleset hash.

## 9. LLM Validation Design

The LLM mode uses Qwen2.5-Coder 7B via Ollama. Raw full-file LLM responses are parsed through an evaluation-specific parser that preserves raw artifacts while applying deterministic scanner validation for supported Plan B findings.

The parser repairs schema compatibility for full-file output without weakening normal `AgentAnalysis` validation.

## 10. Hybrid Behavior

Hybrid mode combines independent Semgrep and LLM execution at case level. Hybrid predictions are not inflated by multiple findings. Detector contribution fields record whether Semgrep, LLM, both, or neither contributed.

Final Hybrid detector contribution counts:

| Contribution | Count |
| --- | ---: |
| agree_vulnerable | 2 |
| agree_safe | 2 |
| llm_only | 4 |
| semgrep_only | 0 |

Hybrid recovered both CWE-078 vulnerable cases through LLM-only positives and both CWE-089 vulnerable cases through detector-positive paths. It also inherited two LLM-only CWE-078 false positives.

## 11. Evaluation-Path Defect and Repair

During pre-freeze validation, an evaluation-only defect was found in full-file SQL validation. The frozen detector regex was restored, but the evaluation parser had been passing broad evidence and full-file code into deterministic SQL parameterization validation. In SQL cases, unrelated commas outside the reported sink could make `cur.execute(sql)` look parameterized.

The repair is limited to the full-file evaluation parsing path:

- CWE-089 validation uses the reported sink line or matched sink evidence context.
- The original LLM evidence remains preserved in prediction artifacts.
- Scanner detector logic, prompts, Semgrep rules, mode semantics, and thresholds are unchanged.

## 12. Reproducibility Controls

Pre-run freeze metadata: `evaluation/plan_b_freeze_metadata.json`.

Final result metadata: `artifacts/evaluation/plan-b-final/20260725T073500Z-b7fc6d9f/result_metadata.json`.

Recorded controls include hashes for the manifest, predictions, metrics, final reports, local ruleset, and prompt file, along with model and Semgrep version information.

## 13. Test Results

Pre-freeze validation:

- `tests/unit/test_evaluation.py`: 20 passed.
- `tests/unit/test_orchestrator.py`: 44 passed.
- `tests/unit/test_web_api.py`: 19 passed.
- `tests/unit/test_semgrep.py`: 1 passed.
- Full `tests/unit`: 155 passed, 1 skipped.

Post-result documentation validation:

- `git diff --check`: passed.
- Full `tests/unit`: passed after result documentation work.

## 14. Pilot Results

Accepted pilot: `20260725T070438Z-1ffabe43`.

The pilot demonstrated that the four approved development cases produced the expected case-level labels and sink locations across the supported modes. These pilot results were not used as final holdout results.

## 15. Integrity and Leakage Safeguards

Pre-freeze and post-run checks confirmed:

- `src/vuln_agent/orchestrator.py` remained unchanged from the frozen detector implementation.
- Semgrep rules remained unchanged.
- Prompts remained unchanged.
- Model settings and thresholds remained unchanged.
- Plan A artifacts remained unchanged.
- Final prediction files were not rewritten during analysis.
- The nested evaluation reader loaded the final run.

## 16. Limitations

Plan B is not a broad security benchmark. It is a scoped, reproducible evaluation of CWE-078 and CWE-089 behavior under the current local rules and LLM validation design.

Known limitations:

- The final holdout has only eight cases.
- Semgrep coverage is local and deterministic, not comprehensive.
- LLM output remains model-runtime dependent.
- Hybrid recall improved in this scoped run, but false positives remained.
- Results must not be interpreted as proof that scanned code is secure.

## 17. Final Evaluation Results

Final metrics from persisted artifacts:

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | 2 | 0 | 4 | 2 | 1.000 | 0.500 | 0.667 | 0.750 | 0.000 | 0.500 |
| llm | 3 | 2 | 2 | 1 | 0.600 | 0.750 | 0.667 | 0.625 | 0.500 | 0.250 |
| semgrep_gated | 2 | 0 | 4 | 2 | 1.000 | 0.500 | 0.667 | 0.750 | 0.000 | 0.500 |
| hybrid | 4 | 2 | 2 | 0 | 0.667 | 1.000 | 0.800 | 0.750 | 0.500 | 0.000 |

Completion/error/timeout results:

| Mode | Attempted | Completed | Errors | Timeouts |
| --- | ---: | ---: | ---: | ---: |
| semgrep | 8 | 8 | 0 | 0 |
| llm | 8 | 8 | 0 | 0 |
| semgrep_gated | 8 | 8 | 0 | 0 |
| hybrid | 8 | 8 | 0 | 0 |

Per-CWE results:

| Mode | CWE | n | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | CWE-078 | 4 | 0 | 0 | 2 | 2 | 0.000 | 0.000 | 0.000 | 0.500 |
| semgrep | CWE-089 | 4 | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| llm | CWE-078 | 4 | 2 | 2 | 0 | 0 | 0.500 | 1.000 | 0.667 | 0.500 |
| llm | CWE-089 | 4 | 1 | 0 | 2 | 1 | 1.000 | 0.500 | 0.667 | 0.750 |
| semgrep_gated | CWE-078 | 4 | 0 | 0 | 2 | 2 | 0.000 | 0.000 | 0.000 | 0.500 |
| semgrep_gated | CWE-089 | 4 | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| hybrid | CWE-078 | 4 | 2 | 2 | 0 | 0 | 0.500 | 1.000 | 0.667 | 0.500 |
| hybrid | CWE-089 | 4 | 2 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |

Strict CWE-aware results match the binary results for this run because every positive prediction used the expected CWE family for its case. No predicted-vulnerable row had an unexpected CWE.

## 18. Failure Analysis

Failure artifacts:

- `artifacts/evaluation/plan-b-final/20260725T073500Z-b7fc6d9f/failures/false_positives.jsonl`
- `artifacts/evaluation/plan-b-final/20260725T073500Z-b7fc6d9f/failures/false_negatives.jsonl`
- `artifacts/evaluation/plan-b-final/20260725T073500Z-b7fc6d9f/failures/taxonomy.csv`

Summary:

| Mode | False positives | False negatives | Main cause |
| --- | ---: | ---: | --- |
| semgrep | 0 | 2 | CWE-078 deterministic rule coverage gap |
| llm | 2 | 1 | CWE-078 overclassification and one CWE-089 miss |
| semgrep_gated | 0 | 2 | CWE-078 deterministic rule coverage gap |
| hybrid | 2 | 0 | LLM-only CWE-078 false positives inherited by fusion |

## 19. Plan A Versus Plan B Comparison

Plan A and Plan B are not directly interchangeable: Plan A is a 20-case broader CWE run; Plan B is an eight-case scoped CWE-078/CWE-089 holdout. The comparison is useful for project direction, not universal ranking.

| Mode | Plan A F1 | Plan A Accuracy | Plan A FPR | Plan B F1 | Plan B Accuracy | Plan B FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | 0.000 | 0.500 | 0.000 | 0.667 | 0.750 | 0.000 |
| llm | 0.643 | 0.500 | 0.900 | 0.667 | 0.625 | 0.500 |
| semgrep_gated | 0.000 | 0.500 | 0.000 | 0.667 | 0.750 | 0.000 |
| hybrid | 0.643 | 0.500 | 0.900 | 0.800 | 0.750 | 0.500 |

Within the scoped Plan B holdout, Hybrid reached the highest F1 and recall, while Semgrep/Semgrep-gated had perfect precision but missed CWE-078 positives.

## 20. Scoped Final Conclusion

The official final Plan B run completed successfully with no errors or timeouts. Hybrid achieved the strongest scoped F1 at 0.800 and recall at 1.000, but retained a 0.500 false-positive rate due to LLM-only CWE-078 detections. Semgrep and Semgrep-gated were precise but incomplete, especially for CWE-078. The result supports Plan B as a reproducible scoped evaluation repair and reporting framework, not as a claim of complete scanner correctness.

## 21. Extended Confirmatory Evaluation Plan

A future extended confirmatory evaluation should be predeclared before execution, use unseen cases, and remain separate from the frozen eight-case result. Recommended protocol:

- Use at least 40 unseen cases, balanced across CWE-078 and CWE-089 where possible.
- Keep vulnerable/safe balance within each CWE.
- Run all four modes once on the same case IDs.
- Preserve all failures/timeouts as attempted records.
- Report binary and strict CWE-aware metrics.
- Do not alter prompts, rules, thresholds, detector code, or fusion behavior after reviewing the final eight-case result.
