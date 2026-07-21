# Recommendations

## Immediate Operational Recommendations

- Use the original hybrid workflow for demonstrations that need a balance between recall and specificity.
- Keep the original LLM mode available when maximum recall is the operational goal.
- Require human review for high-impact findings and any ambiguous evidence.
- Do not use `evidence_first_llm_repair` or `improved_hybrid` as operational replacements; the held-out experiment showed severe recall loss.

## Near-Term Research

- Add a real uncertain/review state instead of converting uncertainty to safe.
- Preserve original-hybrid recall before optimizing false positives.
- Improve schema reliability separately from semantic decision quality.
- Use bounded format-only repair and verify semantic label stability.
- Calibrate decision thresholds on development data only.
- Evaluate any new configuration on a new held-out set.

## Long-Term Work

- Broaden datasets beyond the current benchmark sample.
- Add additional languages and framework-aware rules.
- Investigate interprocedural analysis and additional analyzers such as CodeQL.
- Evaluate larger or specialized local models.
- Add human-expert evaluation for evidence quality.
- Build confidence calibration and safe deployment controls.

All future-work items are recommendations, not implemented Week 6 functionality.
