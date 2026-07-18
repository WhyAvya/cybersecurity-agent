# Human Review Template

Use this template when manually verifying explanation quality, reasoning correctness, and failure taxonomy labels.

```text
review_id:
reviewer:
date:
run_id:
finding_id:
test_id:

expected_vulnerable:
predicted_vulnerable:
expected_cwe:
predicted_cwe:

final_label:
  [ ] true_positive
  [ ] false_positive
  [ ] true_negative
  [ ] false_negative
  [ ] uncertain
  [ ] infrastructure_failure

failure_category:
  [ ] TOOL_COVERAGE_GAP
  [ ] MODEL_HALLUCINATION
  [ ] PROMPT_INJECTION_SUSPECTED
  [ ] CWE_MISMATCH
  [ ] SANITIZATION_MISUNDERSTANDING
  [ ] DATA_FLOW_MISUNDERSTANDING
  [ ] SOURCE_MISIDENTIFICATION
  [ ] SINK_MISIDENTIFICATION
  [ ] SCHEMA_FAILURE
  [ ] MODEL_FAILURE
  [ ] TOOL_FAILURE
  [ ] UNCERTAINTY_ERROR
  [ ] POLICY_ERROR
  [ ] DUPLICATE_FINDING

evidence_quality:
  [ ] sufficient
  [ ] partial
  [ ] insufficient

reasoning_correctness:
  [ ] correct
  [ ] partially_correct
  [ ] incorrect

notes:

inter_rater_agreement_group:
```
