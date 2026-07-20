# Pilot Baseline And Validation Notes

## Frozen 10-Case Baseline

Frozen run: `artifacts/evaluation/20260718T165643Z-3dcf912a`

Derived case-level CSV: `artifacts/evaluation/20260718T165643Z-3dcf912a/case_level_baseline.csv`

Conclusions:

- Semgrep missed all five vulnerable cases in the frozen pilot.
- LLM-only predicted all ten cases as vulnerable, giving recall 1.0, specificity 0.0, and false-positive rate 1.0.
- The original hybrid behavior was a Semgrep-gated verifier, not a fully independent hybrid detector.
- Because the LLM was not invoked when Semgrep produced zero findings, the Semgrep-gated hybrid could not recover Semgrep false negatives.

For `BenchmarkTest00180`, ground truth is vulnerable `CWE-022`. Semgrep returned zero findings. LLM-only saw the complete file and predicted vulnerable, but emitted `CWE-078`. The Semgrep-gated hybrid did not call the LLM and therefore returned vulnerable=false, CWE=NONE.

## Semgrep Ruleset Inspection

Configured Semgrep ruleset: `p/python`

Validation result: Semgrep 1.170.0 reported 151 valid Python rules for `p/python`.

Relevant pilot CWEs:

- `CWE-022`: path traversal
- `CWE-078`: OS command injection
- `CWE-079`: cross-site scripting
- `CWE-089`: SQL injection
- `CWE-090`: LDAP injection

Observed emitted rule IDs in the frozen and validation samples:

- `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`

The configured ruleset did not emit findings for the selected vulnerable cases across CWE-022, CWE-078, CWE-079, CWE-089, or CWE-090 in the frozen pilot. In the fresh validation sample, it emitted one command-injection-related rule, but only on a safe case. This points to a ruleset-coverage limitation for these OWASP Benchmark Python patterns rather than an evaluation mapping defect: files were scanned successfully, Semgrep returned no errors, and the one emitted rule was mapped into a normalized CWE.

## Mode Definitions

- `semgrep`: Semgrep-only detector.
- `llm`: Full-file LLM-only detector.
- `semgrep_gated`: Preserved ablation for the old Semgrep-first verifier behavior. The LLM is called only when Semgrep emits findings.
- `hybrid`: True hybrid detector. The LLM is always called with the complete source file plus normalized Semgrep findings. If Semgrep emits no findings, the prompt receives an explicit empty findings list.

## Fresh 20-Case Validation

Run: `artifacts/evaluation/20260718T172142Z-15cd7543`

Manifest: `artifacts/evaluation/20260718T172142Z-15cd7543/validation_manifest.json`

Case-level CSV: `artifacts/evaluation/20260718T172142Z-15cd7543/case_level_validation.csv`

Disagreement CSV: `artifacts/evaluation/20260718T172142Z-15cd7543/disagreements.csv`

The fresh validation excluded every frozen 10-case pilot ID and used the same 20 selected IDs for all four modes.
