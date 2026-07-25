# Plan B v2 Evaluation Notes

Evaluation claims are separated between the frozen Plan B v1 quantitative baseline and the Plan B v2 architectural MVP validation.

## Plan B v1

Plan B v1 remains the quantitative benchmark baseline for this repository. Its frozen detector, Semgrep rules, prompts, validators, Hybrid logic, model configuration, thresholds, and evaluation artifacts are preserved.

Do not reinterpret Plan B v2 behavioral tests as a replacement for the frozen Plan B v1 benchmark metrics.

## Plan B v2

Plan B v2 currently has architectural and behavioral MVP validation. Verified evidence includes:

- Phase 1 focused tests: 17 passed
- Phase 2 focused tests: 8 passed, 1 skipped
- Phase 3 focused tests: 8 passed
- Phase 4 focused tests: 13 passed
- Phase 5 focused tests: 19 passed
- Latest full suite: 199 passed, 2 skipped
- Six local fixtures covering vulnerable, rejected, human-review, and no-route cases
- Clean Git checkpoints
- Frozen Plan B v1 unchanged

This is not a claim of statistical accuracy superiority. Plan B v2 has not completed a large external benchmark in this repository state.

## Useful Measures For V2 Runs

Useful run-level measures include:

- Active and skipped routes
- Candidate count
- LLM calls used
- Investigation passes
- Confirmed, rejected, human-review, tool-error, and out-of-scope counts
- Runtime
- Artifact completeness

These measures should be computed from `scan_plan.json`, `events.jsonl`, `state.json`, and `final_report.json`.

## Fixture Evidence

The six fixture repositories exercise expected behavior for:

- Command injection: `CONFIRMED`
- Constant overwrite: `REJECTED`
- Missing helper: second pass, then `HUMAN_REVIEW_REQUIRED`
- String SQL: `CONFIRMED`
- Parameterized SQL: `REJECTED`
- No relevant APIs: skipped during routing

The fixture tests mock the LLM and reuse existing Semgrep interfaces, keeping the validation deterministic and independent of a live model.

## Reporting Boundaries

Reports may describe Plan B v2 as presentable, reproducible, bounded, and behaviorally tested. They should not claim that v2 is equivalent to Claude Code, fully autonomous, more accurate than v1, or validated on a completed external benchmark unless separate evidence is produced.
