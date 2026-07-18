# Evaluation Protocol

The new CLI contains evaluation command scaffolds, but the full benchmark runner still needs migration from the legacy `evaluation/` scripts. Main comparisons must use the same immutable test ID sample for Semgrep-only, LLM-only, and hybrid runs.

Future runs should write a manifest, predictions, summary metrics, calibration data, and generated Week 4/Week 5 reports under `artifacts/evaluation/<run_id>/`.
