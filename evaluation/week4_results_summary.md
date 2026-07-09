# Week 4 Experimental Evaluation Results

## Objective

The goal of Week 4 was to evaluate the vulnerability discovery workflow against the OWASP BenchmarkPython dataset and compare three conditions:

1. Raw Semgrep output
2. LLM-only reasoning
3. Hybrid Semgrep + LLM agent workflow

## Dataset

The evaluation used the OWASP BenchmarkPython dataset with 1230 benchmark entries. The ground truth file was generated and stored as:

- evaluation/ground_truth.json

The LLM-only baseline was evaluated on a 100-file sample because full LLM-only evaluation over all 1230 files is slow on local hardware.

## Main Binary Detection Results

| System | Sample | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| Semgrep only | 1230 | 58.2% | 19.7% | 29.4% | 8.2% |
| LLM only | 100 | 34.7% | 100.0% | 51.5% | 97.0% |
| Hybrid-Strict | 1230 | 70.0% | 12.4% | 21.1% | 3.1% |
| Hybrid-Review | 1230 | 64.9% | 13.5% | 22.3% | 4.2% |
| Hybrid-Conf75 | 1230 | 59.6% | 19.2% | 29.1% | 7.6% |

## Strict CWE-Match Results

| System | Sample | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| LLM only | 100 | 38.1% | 23.5% | 29.1% | 19.7% |
| Hybrid-Strict | 1230 | 33.3% | 2.7% | 4.9% | 3.1% |
| Hybrid-Review | 1230 | 28.9% | 2.9% | 5.2% | 4.1% |
| Hybrid-Conf75 | 1230 | 21.6% | 3.5% | 6.1% | 7.5% |

## Interpretation

The Semgrep-only baseline was stable but had low recall. It achieved 58.2% precision and 19.7% recall in binary detection.

The LLM-only baseline showed the opposite behavior. It achieved 100.0% recall on the 100-file sample, but its false positive rate was 97.0%. This means the LLM detected nearly every vulnerable file, but also incorrectly marked most safe files as vulnerable.

The hybrid workflow behaved as a false-positive filtering layer over Semgrep. The strict hybrid policy achieved the best precision at 70.0% and the lowest false positive rate at 3.1%, but recall dropped to 12.4%. The confidence-threshold policy, Hybrid-Conf75, achieved the best balance: 59.6% precision, 19.2% recall, 29.1% F1, and 7.6% FPR.

## Key Finding

The main Week 4 finding is that LLM-only reasoning has high recall but poor false-positive control, while the hybrid workflow improves precision and reduces false positives when used with decision policies such as confidence thresholding.

Hybrid-Conf75 is the best balanced policy so far because it preserves most of Semgrep's recall while slightly improving precision and reducing the false positive rate.

## Current Limitations

1. The hybrid pipeline is Semgrep-first, so it cannot recover vulnerabilities that Semgrep completely misses.
2. The strict hybrid policy rejects some true positives, which lowers recall.
3. The LLM-only baseline over-detects vulnerabilities and has very high false positives.
4. Strict CWE matching remains difficult because tools and the benchmark may use different CWE labels for related vulnerability types.

## Files Produced

- evaluation/ground_truth.json
- results/hybrid_findings.jsonl
- results/hybrid_policy_analysis.csv
- results/week4_semgrep_vs_hybrid_fair.csv
- results/llm_baseline_100.jsonl
- results/week4_final_results.csv

## Week 4 Status

Week 4 experimental evaluation is complete. The next stage is Week 5: trustworthiness and failure analysis, focusing on false positives, false negatives, uncertainty handling, prompt sensitivity, and reasoning failures.
