# evaluation/week5_generate_report.py

import csv
from pathlib import Path


FAILURE_TAXONOMY = Path("results/week5_failure_taxonomy.csv")
CONSISTENCY_RESULTS = Path("results/week5_consistency_results.csv")
PROMPT_SUMMARY = Path("results/week5_prompt_sensitivity_summary.csv")
WEEK4_RESULTS = Path("results/week4_final_results.csv")

REPORT_PATH = Path("evaluation/week5_trustworthiness_report.md")


def read_csv(path):
    if not path.exists():
        return []

    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def count_jsonl(path):
    if not path.exists():
        return 0

    with open(path, "r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def make_markdown_table(rows, columns):
    if not rows:
        return "No data available.\n"

    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join(["---"] * len(columns)) + " |"

    body = []

    for row in rows:
        body.append(
            "| " + " | ".join(str(row.get(col, "")) for col in columns) + " |"
        )

    return "\n".join([header, separator] + body)


def main():
    taxonomy_rows = read_csv(FAILURE_TAXONOMY)
    consistency_rows = read_csv(CONSISTENCY_RESULTS)
    prompt_rows = read_csv(PROMPT_SUMMARY)
    week4_rows = read_csv(WEEK4_RESULTS)

    hybrid_fp_count = count_jsonl(
        Path("results/week5_hybrid_conf75_false_positives.jsonl")
    )

    hybrid_fn_count = count_jsonl(
        Path("results/week5_hybrid_conf75_false_negatives.jsonl")
    )

    llm_fp_count = count_jsonl(
        Path("results/week5_llm_false_positives.jsonl")
    )

    llm_fn_count = count_jsonl(
        Path("results/week5_llm_false_negatives.jsonl")
    )

    total_consistency = len(consistency_rows)
    matching_consistency = sum(
        1 for row in consistency_rows
        if str(row.get("verdict_match", "")).lower() == "true"
    )

    consistency_rate = (
        matching_consistency / total_consistency
        if total_consistency
        else 0
    )

    avg_conf_diff = 0

    if consistency_rows:
        diffs = [
            float(row.get("confidence_difference", 0))
            for row in consistency_rows
        ]

        avg_conf_diff = sum(diffs) / len(diffs)

    report = f"""# Week 5 Trustworthiness and Failure Analysis Report

## 1. Objective

The goal of Week 5 was to analyze the trustworthiness of the agentic vulnerability discovery workflow.

The analysis focused on:

1. False positives
2. False negatives
3. Consistency
4. Prompt sensitivity
5. Hallucinated findings
6. Reasoning failures
7. Failure taxonomy

This week did not focus on improving performance directly. Instead, it focused on understanding why the current system fails.

---

## 2. Systems Analyzed

The following systems were analyzed:

1. Semgrep-only baseline
2. LLM-only baseline using Qwen2.5-Coder through Ollama
3. Hybrid Semgrep + LLM workflow

The hybrid system uses Semgrep as the first-stage scanner and then uses the LLM analyzer to classify findings as TP, FP, or UNCERTAIN.

---

## 3. Week 4 Result Context

The Week 4 results showed that:

- Semgrep-only was stable but had low recall.
- LLM-only had very high recall but also very high false positives.
- Hybrid-Strict improved precision but reduced recall.
- Hybrid-Conf75 gave the best balanced hybrid behavior.

Week 5 explains why these results occurred.

"""

    if week4_rows:
        report += "\n### Week 4 Final Result Table\n\n"
        report += make_markdown_table(
            week4_rows,
            [
                "System",
                "Sample",
                "Metric Type",
                "Precision (%)",
                "Recall (%)",
                "F1 (%)",
                "FPR (%)"
            ]
        )

    report += f"""

---

## 4. Failure Counts

The Week 5 failure-analysis script produced the following failure counts:

| System / Category | Count |
|---|---:|
| Hybrid-Conf75 false positives | {hybrid_fp_count} |
| Hybrid-Conf75 false negatives | {hybrid_fn_count} |
| LLM-only false positives | {llm_fp_count} |
| LLM-only false negatives | {llm_fn_count} |

Important note:

Week 4 metrics are file-level metrics, while some Week 5 outputs are finding-level failure records. Therefore, the false-positive counts in Week 5 may not exactly match the Week 4 metric table.

---

## 5. Failure Taxonomy

The following failure taxonomy was generated from the Week 5 analysis:

"""

    report += make_markdown_table(
        taxonomy_rows,
        [
            "system",
            "failure_type",
            "count"
        ]
    )

    report += """

### Interpretation

The largest failure category was TOOL_COVERAGE_GAP. This means that many false negatives occurred because Semgrep did not produce an initial finding. Since the hybrid system is Semgrep-first, the LLM analyzer cannot recover vulnerabilities that Semgrep never sends to it.

The LLM-only baseline showed many high-confidence hallucinations. This means the LLM often predicted a vulnerability even when the benchmark labeled the file as safe.

CWE mismatch was also a major issue. This means the model sometimes detected a security pattern but assigned the wrong CWE.

---

## 6. False Positive Analysis

False positives were mainly caused by:

1. High-confidence hallucination
2. Speculative reasoning
3. Sanitization misunderstanding
4. Incorrect CWE interpretation
5. Hybrid policy accepting high-confidence findings even when the analyzer verdict was FP

The LLM-only system produced many false positives because it tended to treat suspicious-looking code as vulnerable even when exploitability was not clearly proven.

The hybrid system reduced false positives compared to LLM-only, but some false positives remained due to CWE mismatch and reasoning errors.

---

## 7. False Negative Analysis

The main hybrid false-negative cause was TOOL_COVERAGE_GAP.

This means that the hybrid pipeline missed many vulnerable files because Semgrep did not flag them first.

This is an important architectural limitation:

> The current hybrid system can filter and explain Semgrep findings, but it cannot discover vulnerabilities that Semgrep completely misses.

This limitation should be addressed in Week 6 by adding either better Semgrep rule coverage, additional tools, or an optional LLM scan mode.

---

## 8. Consistency Analysis

The consistency test reran the LLM analyzer on the same 30 hybrid findings.

| Metric | Value |
|---|---:|
| Total repeated cases | {total_consistency} |
| Matching verdicts | {matching_consistency} |
| Consistency rate | {consistency_rate:.3f} |
| Consistency rate percentage | {consistency_rate * 100:.1f}% |
| Average confidence difference | {avg_conf_diff:.3f} |

### Interpretation

The consistency rate was {consistency_rate * 100:.1f}%. This means the model changed its verdict in a noticeable number of repeated cases.

This shows that the LLM reasoning layer is not fully stable. For a real vulnerability analysis workflow, repeated or unstable results should be handled carefully.

A practical solution is to route unstable cases to human review instead of automatically accepting or rejecting them.

---

## 9. Prompt Sensitivity Analysis

The prompt sensitivity test used three prompt styles:

1. Strict
2. Balanced
3. Recall-focused

"""

    report += make_markdown_table(
        prompt_rows,
        [
            "prompt_style",
            "total",
            "tp_count",
            "fp_count",
            "uncertain_count",
            "match_rate",
            "avg_confidence",
            "parse_success_rate"
        ]
    )

    report += """

### Interpretation

The strict prompt produced fewer TP verdicts and more FP verdicts. This means it was conservative and less likely to accept findings.

The balanced prompt produced more UNCERTAIN verdicts. This means it avoided over-committing when evidence was incomplete.

The recall-focused prompt produced more TP verdicts. This means it was more likely to accept potential vulnerabilities, but this can increase false positives.

This proves that prompt wording significantly affects the behavior of the LLM analyzer.

---

## 10. Hallucinated Findings

Hallucinated findings were mainly observed in the LLM-only baseline.

The LLM-only system sometimes predicted vulnerabilities with high confidence even when the benchmark labeled the file as safe.

This supports the Week 4 result where LLM-only had high recall but very poor false-positive control.

This means LLM-only reasoning should not be trusted as a standalone vulnerability detector.

---

## 11. Reasoning Failures

The main reasoning failures were:

| Reasoning Failure | Meaning |
|---|---|
| High-confidence hallucination | The LLM confidently predicted a vulnerability where none existed |
| Speculative reasoning | The LLM used words like may, could, or potential without strong evidence |
| Sanitization misunderstanding | The LLM misunderstood whether validation or protection existed |
| CWE mismatch | The LLM assigned the wrong vulnerability category |
| Tool coverage gap | Semgrep missed the file, so the hybrid pipeline never analyzed it |
| Uncertainty misclassification | UNCERTAIN cases were not handled as human-review cases |

---

## 12. Trustworthiness Conclusion

The current system is working, but it should not be treated as a fully autonomous vulnerability detector.

The most trustworthy use case is:

> Semgrep finds possible vulnerabilities, the LLM explains and prioritizes them, and uncertain or unstable cases are sent to human review.

The system is useful as a vulnerability triage and explanation assistant, but it still requires careful handling of false positives, false negatives, and prompt sensitivity.

---

## 13. Recommended Week 6 Improvements

The Week 5 analysis suggests the following Week 6 improvements:

1. Add a real scan mode so any Python source-code folder can be scanned.
2. Treat UNCERTAIN as human review instead of safe or vulnerable.
3. Improve the Hybrid-Conf75 policy so FP verdicts are not accepted only because confidence is high.
4. Improve Semgrep coverage or add another static analysis tool.
5. Improve CWE mapping and CWE alias handling.
6. Add Markdown and JSON reports for final demo.
7. Dockerize the project for reproducible execution.
8. Add a sample vulnerable app for demonstration.

---

## 14. Week 5 Status

Week 5 is complete after this report.

Generated Week 5 files:

- results/week5_failure_taxonomy.csv
- results/week5_hybrid_conf75_false_positives.jsonl
- results/week5_hybrid_conf75_false_negatives.jsonl
- results/week5_llm_false_positives.jsonl
- results/week5_llm_false_negatives.jsonl
- results/week5_consistency_results.csv
- results/week5_prompt_sensitivity.csv
- results/week5_prompt_sensitivity_summary.csv
- evaluation/week5_trustworthiness_report.md

"""

    REPORT_PATH.write_text(report, encoding="utf-8")

    print(f"Saved Week 5 trustworthiness report to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
