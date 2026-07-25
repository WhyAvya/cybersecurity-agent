# Executive Summary

Final Plan B run `20260725T073500Z-b7fc6d9f` completed 32/32 executions across Semgrep, LLM, Semgrep-gated, and Hybrid modes with zero errors and zero timeouts.

Key results:

- Semgrep: precision 1.000, recall 0.500, F1 0.667, accuracy 0.750.
- LLM: precision 0.600, recall 0.750, F1 0.667, accuracy 0.625.
- Semgrep-gated: precision 1.000, recall 0.500, F1 0.667, accuracy 0.750.
- Hybrid: precision 0.667, recall 1.000, F1 0.800, accuracy 0.750.

Hybrid found all four vulnerable holdout cases but produced two false positives, both inherited from LLM-only CWE-078 detections. Semgrep and Semgrep-gated produced no false positives but missed both vulnerable CWE-078 holdout cases. The result is promising for scoped Plan B behavior, but the eight-case sample is too small for broad claims.
