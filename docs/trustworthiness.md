# Trustworthiness

Trustworthiness analysis should separate tool failures, model failures, schema failures, uncertain results, false positives, false negatives, and CWE mismatches.

The current remediation removes the most dangerous behavior from the old baseline: invalid LLM output is not converted into a safe verdict.

Automated failure labels are defined in `src/vuln_agent/failure_taxonomy.py`. Manual review should use `docs/human_review_template.md` so explanation quality and reasoning correctness are recorded separately from automated heuristic labels.
