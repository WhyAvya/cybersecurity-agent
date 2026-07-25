# Final Plan B Evaluation Report

Run ID: `20260725T073500Z-b7fc6d9f`
Run path: `artifacts/evaluation/plan-b-final/20260725T073500Z-b7fc6d9f`
Frozen Plan B commit: `3d04c911b12a91cd5a5033ee13711b5669a5d7a0`

## Verification

The persisted manifest status is `complete`. The run contains four modes, eight selected cases per mode, and 32 completed case executions. No prediction rows contain errors or timeouts. Raw response and Semgrep artifact references from prediction rows resolve on disk.

## Final Metrics

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | 2 | 0 | 4 | 2 | 1.000 | 0.500 | 0.667 | 0.750 | 0.000 | 0.500 |
| llm | 3 | 2 | 2 | 1 | 0.600 | 0.750 | 0.667 | 0.625 | 0.500 | 0.250 |
| semgrep_gated | 2 | 0 | 4 | 2 | 1.000 | 0.500 | 0.667 | 0.750 | 0.000 | 0.500 |
| hybrid | 4 | 2 | 2 | 0 | 0.667 | 1.000 | 0.800 | 0.750 | 0.500 | 0.000 |

## Per-CWE Metrics

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

## Hybrid Detector Contributions

- `agree_vulnerable`: 1
- `agree_safe`: 2
- `llm_only`: 4
- `semgrep_only`: 1

Hybrid achieved recall 1.000 on the eight-case holdout by accepting LLM-only CWE-078 positives and Semgrep/LLM-supported CWE-089 positives. It also inherited two LLM-only false positives on safe CWE-078 cases.

## Failure Summary

- False positives: 4
- False negatives: 5
- Failure taxonomy rows: `artifacts/evaluation/plan-b-final/20260725T073500Z-b7fc6d9f/failures/taxonomy.csv`

By mode:

- Semgrep: 0 FP, 2 FN.
- LLM: 2 FP, 1 FN.
- Semgrep-gated: 0 FP, 2 FN.
- Hybrid: 2 FP, 0 FN.

## Plan A Versus Plan B

| Mode | Plan A F1 | Plan A Accuracy | Plan A FPR | Plan B F1 | Plan B Accuracy | Plan B FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| semgrep | 0.000 | 0.500 | 0.000 | 0.667 | 0.750 | 0.000 |
| llm | 0.643 | 0.500 | 0.900 | 0.667 | 0.625 | 0.500 |
| semgrep_gated | 0.000 | 0.500 | 0.000 | 0.667 | 0.750 | 0.000 |
| hybrid | 0.643 | 0.500 | 0.900 | 0.800 | 0.750 | 0.500 |

Plan B is not directly comparable as a universal improvement because it uses a scoped eight-case CWE-078/CWE-089 holdout, while Plan A used the accepted 20-case broader run. Within this scoped holdout, Plan B improves Semgrep SQL coverage and Hybrid recall, but Hybrid precision remains limited by LLM false positives.

## Conclusion

The frozen Plan B run completed successfully and produced deterministic artifacts for all 32 mode/case executions. The strongest scoped result is Hybrid recall of 1.000 with F1 0.800, balanced by a false-positive rate of 0.500. These results support Plan B as a scoped reproducibility and evaluation repair, not as evidence of universal scanner performance.
