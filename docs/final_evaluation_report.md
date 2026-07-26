# Final Evaluation Report

## Abstract

This report summarizes the finished vulnerability-discovery project across three distinct evaluation stages: the frozen Week 4 benchmark comparison, the Week 5 trustworthiness analysis with post-Week-5 held-out improvement experiment, and the final Plan B and Agentic v2 verification.

The final conclusion is scoped and mixed. LLM-only analysis improved recall but produced excessive false positives. Semgrep was more precise but incomplete. Conservative post-Week-5 variants reduced false positives but collapsed recall and were rejected. The final Plan B Hybrid achieved the strongest scoped result in the focused eight-case comparison. Agentic v2 added bounded orchestration, adaptive routing, manual approval, isolated reasoner and reviewer roles, deterministic validation, human escalation, and structured audit artifacts. The final result is a scoped research prototype, not a universal production scanner.

## Research Question

Can a bounded local agentic workflow improve the usefulness, auditability, and trustworthiness of Python vulnerability discovery by combining static analysis, isolated local-LLM reasoning and review, deterministic validation, human checkpoints, and reproducible artifacts?

The original research question focused more narrowly on whether a local open-source LLM could improve static-analysis vulnerability discovery while preserving reproducibility, evidence, and structured output reliability.

## System Evolution

### Earlier Evaluation Workflow

The earlier workflow was implemented as a Python scanner and evaluation package. It used Semgrep for deterministic static analysis, Ollama for local model execution, and `qwen2.5-coder:7b` as the local open-source model. Docker supported the benchmark workflow and broader repository packaging.

The evaluated modes were:

- `semgrep`
- `llm`
- `semgrep_gated`
- `hybrid`

### Final Plan B Hybrid

Plan B introduced a reproducible scoped quantitative repair focused on `CWE-078` and `CWE-089`. It used a final focused eight-case evaluation, preserved frozen artifacts, and avoided any claim of universal scanner performance. The final Plan B comparison is useful as scoped project evidence, not as broad benchmark proof.

### Final Agentic v2 MVP

Agentic v2 was verified locally on Windows using a Python virtual environment, Semgrep `1.171.0`, Ollama, and `qwen2.5-coder:7b`. It added bounded read-only execution, adaptive routing for `CWE-078` and `CWE-089`, manual scan-plan approval, isolated reasoner and reviewer roles, deterministic validation, one bounded evidence pass, structured terminal decisions, and six audit artifacts.

Docker remained part of the broader repository and earlier workflow, but Docker was not used for the final verified Agentic v2 demonstration.

## Dataset and Sampling Methodology

The project used separate evidence sets that must not be merged because they answer different questions:

- Frozen Week 4 60-case benchmark: the earlier benchmark comparison across `semgrep`, `llm`, `semgrep_gated`, and `hybrid`.
- Separate post-Week-5 40-case held-out set: a controlled test of conservative improvement variants.
- Focused final Plan B eight-case comparison: scoped `CWE-078` and `CWE-089` evidence for Plan A versus Plan B.
- Controlled Agentic v2 fixtures: safe and vulnerable local repositories used to verify bounded orchestration behavior.

The Week 4 and post-Week-5 results are earlier/frozen evaluation evidence. The Plan B comparison and Agentic v2 fixtures are final scoped verification evidence.

## Experimental Conditions

Earlier modes:

- `semgrep`
- `llm`
- `semgrep_gated`
- `hybrid`

Rejected post-Week-5 configurations:

- `evidence_first_llm_repair`
- `improved_hybrid`

Final additions:

- Plan A Hybrid baseline.
- Plan B Hybrid final scoped comparison.
- Agentic v2 safe parameterized SQL case.
- Agentic v2 vulnerable SQL injection case.

## Frozen Week 4 Detection Results

| Mode | Precision | Recall | F1 | Accuracy |
| --- | ---: | ---: | ---: | ---: |
| Semgrep | 0.600 | 0.200 | 0.300 | 0.533 |
| LLM | 0.519 | 0.900 | 0.659 | 0.533 |
| Semgrep-gated | 0.600 | 0.200 | 0.300 | 0.533 |
| Hybrid | 0.600 | 0.400 | 0.480 | 0.567 |

## Week 5 Trustworthiness and Failure Analysis

Week 5 derived trustworthiness evidence from frozen Week 4 artifacts and controlled follow-up experiments. The analysis examined false positives, false negatives, case-level failure taxonomy rows, hallucination and evidence support, consistency behavior, prompt sensitivity, schema reliability, latency, timeouts, and human-review burden.

The main failure patterns were:

- LLM overprediction, which increased recall but produced excessive false positives.
- LLM underprediction, including missed vulnerable cases.
- Semgrep coverage gaps, especially where deterministic rules did not cover the relevant code pattern.
- Gate-blocked vulnerable cases, where `semgrep_gated` did not reach LLM analysis because no Semgrep finding was produced.
- CWE mapping errors.
- Unsupported or ambiguous evidence.
- Prompt sensitivity and schema fragility.
- Consistency not implying correctness, because stable wrong answers remained possible.
- Latency and timeout risks in LLM-backed variants.
- A large human-review burden when outputs were uncertain or evidence was weak.

This analysis supported the need for deterministic validation, explicit evidence handling, and human review rather than unchecked model-only decisions.

## Post-Week-5 Improvement Experiment

Held-out results:

| Configuration | Precision | Recall | F1 | FPR | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| LLM | 0.559 | 0.950 | 0.704 | 0.750 | 0.600 |
| Evidence-first LLM repair | 1.000 | 0.050 | 0.095 | 0.000 | 0.486 |
| Original hybrid | 0.588 | 0.500 | 0.541 | 0.350 | 0.575 |
| Improved hybrid | 0.000 | 0.000 | 0.000 | 0.000 | 0.591 |

The evidence-first LLM repair configuration removed false positives but introduced 18 new false negatives compared with the LLM baseline. Improved hybrid removed seven false positives, introduced schema failures, had four explicit timeouts, had substantially higher latency, and achieved zero measured recall on the held-out set. Both conservative replacements were rejected.

## Final Plan A versus Plan B Hybrid Comparison

| Workflow | Precision | Recall | F1 | Accuracy | FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Plan A Hybrid | 0.500 | 0.900 | 0.643 | 0.500 | 0.900 |
| Plan B Hybrid | 0.667 | 1.000 | 0.800 | 0.750 | 0.500 |

Observed changes:

| Metric | Change |
| --- | ---: |
| Precision | +0.167 |
| Recall | +0.100 |
| F1 | +0.157 |
| Accuracy | +0.250 |
| FPR | -0.400 |

This was a focused eight-case comparison. Plan B Hybrid produced the strongest scoped result, with `TP=4`, `FP=2`, `TN=2`, and `FN=0`. Recall was `1.000`, F1 was `0.800`, and FPR remained `0.500`. This supports scoped improvement and reproducibility, not universal scanner correctness.

## Final Agentic v2 End-to-End Verification

| Test case | Active route | Candidates | LLM calls | Final outcome |
| --- | --- | ---: | ---: | --- |
| Safe parameterized SQL | CWE-089 | 0 | 0 | No vulnerability reported |
| Vulnerable SQL injection | CWE-089 | 1 | 2 | CONFIRMED, confidence 1.0 |

Safe parameterized SQL case:

- One Python file.
- Flask indicator detected.
- `CWE-089` activated.
- `CWE-078` skipped because no shell indicators were found.
- Manual approval recorded.
- `read_only=true`.
- `execute_target_code=false`.
- `modify_target_files=false`.
- `allow_cloud_models=false`.
- No Semgrep candidate.
- No LLM call.
- `decisions=[]`.
- `human_review_decisions=[]`.

Vulnerable SQL injection case:

- One Python file.
- Flask indicator detected.
- `CWE-089` activated.
- Manual approval recorded.
- One Semgrep candidate.
- Candidate mapped to `CWE-089`.
- Candidate at line 7.
- Reasoner invoked.
- Deterministic validator invoked.
- Reviewer invoked.
- 2 LLM calls used.
- 2 steps used.
- `terminal_state=CONFIRMED`.
- `confidence=1.0`.
- No human-review escalation.

## Generated Audit Artifacts

| Artifact | Purpose |
| --- | --- |
| `run_manifest.json` | Records run ID, repository path, requested CWEs, review policy, and run metadata. |
| `scan_plan.json` | Records inventory, active routes, skipped routes, candidate budget, and safety policy. |
| `events.jsonl` | Provides an append-only event trace for approval, Semgrep, model calls, validation, review, terminal decisions, and human review. |
| `findings.json` | Stores normalized Semgrep candidates. |
| `state.json` | Stores run state, approval status, candidate count, budget use, and human-review counters. |
| `final_report.json` | Stores final terminal decisions and human-review decisions. |

## Reproducibility and Safety Controls

Agentic v2 includes the following verified controls:

- Local repository paths only.
- Read-only target handling.
- No target imports.
- No target execution.
- No target dependency installation.
- No target test execution.
- No GitHub cloning.
- No cloud models.
- Bounded candidate count.
- Bounded LLM calls.
- Bounded reasoning steps.
- One bounded repair attempt.
- One bounded additional evidence pass.
- Manual approval before scanning.
- Human escalation for unresolved findings.

## Threats to Validity

The Week 4 sample was small. The post-Week-5 40-case held-out sample was separate and should not be merged with Week 4 metrics. The final Plan B comparison used only eight focused cases. Agentic v2 was verified with controlled fixtures rather than a large external benchmark.

Other threats include Python-only scope, `CWE-078` and `CWE-089` routing scope, bounded same-file evidence, no full interprocedural call graph, local-model hardware and runtime dependence, uncalibrated confidence, and no completed large external Agentic v2 benchmark.

## Limitations

- Python only.
- Two supported CWEs for Agentic v2.
- CLI-focused final demonstration.
- Mainly verified for `CWE-089`.
- Bounded same-file context.
- No full interprocedural analysis.
- No automatic remediation.
- No robust resume engine.
- No deployed final Agentic v2 web interface.
- No universal production guarantees.
- Human review required for high-impact or unresolved findings.

## Recommendations

- Retain frozen Week 4 and Week 5 results as historical evidence.
- Do not adopt the rejected conservative post-Week-5 variants.
- Use final Plan B Hybrid as the scoped quantitative baseline.
- Use Agentic v2 as the final bounded architectural MVP.
- Preserve manual approval, deterministic validation, and independent review.
- Expand evaluation only with new held-out data.
- Add broader CWE coverage carefully.
- Add interprocedural evidence.
- Improve calibration and schema robustness.
- Preserve reproducible artifact generation.

## Final Conclusion

Local LLMs improved recall but introduced false positives and reliability risks. Semgrep remained precise but incomplete. Conservative post-Week-5 changes failed because recall and reliability collapsed.

Final Plan B Hybrid achieved precision `0.667`, recall `1.000`, F1 `0.800`, accuracy `0.750`, and FPR `0.500` on the focused eight-case comparison. Agentic v2 successfully demonstrated bounded end-to-end behavior on safe and vulnerable SQL fixtures. The safe case produced zero candidates, zero LLM calls, and no decision. The vulnerable case produced one candidate, two LLM calls, and terminal `CONFIRMED` with confidence `1.0`.

The final project contribution is a reproducible, local, auditable, bounded vulnerability-analysis research prototype. It is not evidence of universal scanner performance or production readiness.
