# Final Evaluation Report

## Abstract

This report summarizes the final vulnerability-discovery agent evaluation across the frozen Week 4 benchmark, Week 5 trustworthiness analysis, and the post-Week-5 improvement experiment. The main finding is mixed: the local LLM achieved high recall but excessive false positives, Semgrep achieved higher specificity but low recall, and the original hybrid provided a more balanced operational trade-off. The post-Week-5 conservative improvements reduced false positives but collapsed recall and were rejected.

## Research Question

Can a local open-source LLM improve static-analysis vulnerability discovery while preserving reproducibility, evidence, and structured output reliability?

## System Description

The system runs as a Python package in Docker. Semgrep runs inside the application container. Ollama runs on the Windows host at `http://host.docker.internal:11434` with `qwen2.5-coder:7b`.

## Dataset And Sampling Methodology

Week 4 used a frozen 60-case benchmark sample. Post-Week-5 held-out evaluation used a separate 40-case sample. These sets are not combined because they answer different questions under different experimental conditions.

## Experimental Conditions

Modes evaluated include `semgrep`, `llm`, `semgrep_gated`, and `hybrid`. Post-Week-5 tested rejected research configurations `evidence_first_llm_repair` and `improved_hybrid` on a held-out set.

## Week 4 Detection Results

| Mode | Precision | Recall | F1 | Accuracy |
| --- | ---: | ---: | ---: | ---: |
| Semgrep | 0.600 | 0.200 | 0.300 | 0.533 |
| LLM | 0.519 | 0.900 | 0.659 | 0.533 |
| Semgrep-gated | 0.600 | 0.200 | 0.300 | 0.533 |
| Hybrid | 0.600 | 0.400 | 0.480 | 0.567 |

## Confusion Matrices

The frozen Week 4 and post-Week-5 CSV artifacts provide authoritative TP, FP, TN, and FN values. The final artifact also includes `final_metrics_summary.csv` with explicit evaluation-set labels.

## Per-CWE Observations

Week 5 found repeated Semgrep rule coverage gaps and CWE mapping errors across multiple CWE families. These are evidence that tool coverage and model CWE normalization should be improved separately.

## Latency And Reliability Observations

Semgrep was faster than LLM-backed modes. Post-Week-5 `improved_hybrid` had four explicit timeouts and substantially higher average latency than the original hybrid.

## Week 5 Trustworthiness Methodology

Week 5 derived case-level false positives, false negatives, failure taxonomy rows, hallucination/evidence checks, consistency runs, and prompt-sensitivity runs from frozen Week 4 artifacts and controlled follow-up experiments.

## False-Positive Analysis

The original LLM overpredicted vulnerable labels. Evidence-first prompting removed false positives in the post-Week-5 held-out set, but did so by becoming too conservative.

## False-Negative Analysis

Semgrep and Semgrep-gated missed many vulnerable cases because Semgrep rule coverage was limited. Evidence-first and improved-hybrid configurations introduced many false negatives.

## Failure Taxonomy

Major categories included Semgrep rule coverage gaps, gate-blocked vulnerable cases, LLM overprediction, LLM underprediction, CWE mapping errors, unsupported evidence, and ambiguous evidence.

## Consistency Findings

Canonical Week 5 consistency was strong on the selected subset, but this did not imply correctness. Stable wrong answers remained possible.

## Prompt-Sensitivity Findings

Prompt variants were schema fragile. Week 5 prompt-sensitivity produced schema-invalid outputs and showed that stricter wording can harm structured-output reliability.

## Schema-Reliability Findings

Canonical LLM and original hybrid outputs were more schema reliable than the post-Week-5 conservative hybrid configuration. Schema repair did not produce a usable operational replacement.

## Hallucination And Evidence Findings

Evidence checks found CWE mapping errors and ambiguous evidence. Unsupported evidence decreased in conservative variants, but recall also collapsed.

## Post-Week-5 Improvement Experiment

Held-out results:

| Configuration | Precision | Recall | F1 | FPR | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| LLM | 0.559 | 0.950 | 0.704 | 0.750 | 0.600 |
| Evidence-first LLM repair | 1.000 | 0.050 | 0.095 | 0.000 | 0.486 |
| Original hybrid | 0.588 | 0.500 | 0.541 | 0.350 | 0.575 |
| Improved hybrid | 0.000 | 0.000 | 0.000 | 0.000 | 0.591 |

## Why The Proposed Improvements Were Rejected

The evidence-first LLM repair configuration removed false positives but introduced 18 new false negatives compared with the LLM baseline. Improved hybrid removed seven false positives but introduced schema failures, four timeouts, a large latency increase, and zero measured recall on the held-out set. These results do not support adopting either configuration.

## Threats To Validity

The samples are small, the model is local and hardware-dependent, and benchmark cases may not represent real application distributions. Automatic evidence checks are not a replacement for expert human review.

## Limitations

The system does not fine-tune models, does not guarantee complete vulnerability coverage, and should not be used as a final authority for high-impact security decisions.

## Recommendations

Use original hybrid for balanced demonstrations, use original LLM when recall is the highest priority, and require human review. Future work should add a real uncertain state, improve schema reliability independently, and evaluate on new held-out data.

## Conclusion

Local LLMs can add useful recall and explanations, but they also introduce false positives and reliability risks. The final operational recommendation is to retain the original hybrid as the balanced demonstration mode and treat the negative post-Week-5 experiment as evidence for more careful recall-preserving improvement work.
