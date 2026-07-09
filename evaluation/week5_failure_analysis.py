# evaluation/week5_failure_analysis.py

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


GROUND_TRUTH_PATH = Path("evaluation/ground_truth.json")
HYBRID_RESULTS_PATH = Path("results/hybrid_findings.jsonl")
LLM_RESULTS_PATH = Path("results/llm_baseline_100.jsonl")

HYBRID_FP_PATH = Path("results/week5_hybrid_conf75_false_positives.jsonl")
HYBRID_FN_PATH = Path("results/week5_hybrid_conf75_false_negatives.jsonl")
LLM_FP_PATH = Path("results/week5_llm_false_positives.jsonl")
LLM_FN_PATH = Path("results/week5_llm_false_negatives.jsonl")
TAXONOMY_PATH = Path("results/week5_failure_taxonomy.csv")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path):
    records = []

    if not path.exists():
        return records

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    return records


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def accept_hybrid_conf75(record):
    """
    Hybrid-Conf75 policy:
    Accept finding if analyzer says TP
    OR confidence >= 0.75.
    """

    verdict = str(record.get("analyzer_verdict", "")).upper()
    confidence = float(record.get("confidence", 0.0))

    return verdict == "TP" or confidence >= 0.75


def classify_hybrid_false_positive(record):
    verdict = str(record.get("analyzer_verdict", "")).upper()
    reasoning = str(record.get("reasoning", "")).lower()
    cwe = str(record.get("semgrep_cwe", "NONE"))

    if "sanitize" in reasoning or "validation" in reasoning or "escape" in reasoning:
        return "SANITIZATION_MISUNDERSTANDING"

    if cwe in ["CWE-327", "CWE-093", "CWE-704"]:
        return "CWE_MISMATCH_OR_TOOL_LABEL_GAP"

    if verdict == "TP" and float(record.get("confidence", 0.0)) >= 0.85:
        return "HIGH_CONFIDENCE_FALSE_POSITIVE"

    return "FALSE_POSITIVE_FILTER_FAILURE"


def classify_hybrid_false_negative(test_id, records_for_test):
    if not records_for_test:
        return "TOOL_COVERAGE_GAP"

    verdicts = {
        str(record.get("analyzer_verdict", "")).upper()
        for record in records_for_test
    }

    if "UNCERTAIN" in verdicts:
        return "UNCERTAINTY_MISCLASSIFICATION"

    if "FP" in verdicts:
        return "CONSERVATIVE_REJECTION"

    return "HYBRID_POLICY_REJECTION"


def classify_llm_false_positive(record):
    reasoning = str(record.get("reasoning", "")).lower()
    predicted_cwe = record.get("predicted_cwe", "NONE")

    if predicted_cwe == "NONE":
        return "VULNERABLE_WITHOUT_VALID_CWE"

    if "could" in reasoning or "may" in reasoning or "potential" in reasoning:
        return "SPECULATIVE_REASONING"

    if record.get("confidence", 0.0) >= 0.90:
        return "HIGH_CONFIDENCE_HALLUCINATION"

    return "LLM_OVER_DETECTION"


def classify_llm_false_negative(record):
    if not record.get("schema_valid", False):
        return "SCHEMA_OR_PARSE_FAILURE"

    if record.get("predicted_vulnerable") is False:
        return "MISSED_VULNERABILITY"

    return "UNKNOWN_LLM_FALSE_NEGATIVE"


def main():
    ground_truth = load_json(GROUND_TRUTH_PATH)
    hybrid_records = load_jsonl(HYBRID_RESULTS_PATH)
    llm_records = load_jsonl(LLM_RESULTS_PATH)

    print(f"Loaded ground truth entries: {len(ground_truth)}")
    print(f"Loaded hybrid records: {len(hybrid_records)}")
    print(f"Loaded LLM records: {len(llm_records)}")

    taxonomy_counter = Counter()

    # -----------------------------
    # Hybrid Conf75 analysis
    # -----------------------------

    hybrid_by_test = defaultdict(list)

    for record in hybrid_records:
        hybrid_by_test[record["test_id"]].append(record)

    hybrid_accepted_by_test = defaultdict(list)

    for record in hybrid_records:
        if accept_hybrid_conf75(record):
            hybrid_accepted_by_test[record["test_id"]].append(record)

    hybrid_false_positives = []
    hybrid_false_negatives = []

    for test_id, truth in ground_truth.items():
        actual_vulnerable = bool(truth["vulnerable"])
        accepted_records = hybrid_accepted_by_test.get(test_id, [])
        all_records_for_test = hybrid_by_test.get(test_id, [])

        predicted_vulnerable = len(accepted_records) > 0

        if not actual_vulnerable and predicted_vulnerable:
            for record in accepted_records:
                failure_type = classify_hybrid_false_positive(record)
                taxonomy_counter[("Hybrid-Conf75", failure_type)] += 1

                enriched = {
                    **record,
                    "failure_type": failure_type,
                    "failure_group": "false_positive",
                    "actual_vulnerable": actual_vulnerable,
                    "actual_cwe": truth["cwe"]
                }

                hybrid_false_positives.append(enriched)

        if actual_vulnerable and not predicted_vulnerable:
            failure_type = classify_hybrid_false_negative(
                test_id,
                all_records_for_test
            )

            taxonomy_counter[("Hybrid-Conf75", failure_type)] += 1

            hybrid_false_negatives.append({
                "test_id": test_id,
                "failure_type": failure_type,
                "failure_group": "false_negative",
                "actual_vulnerable": actual_vulnerable,
                "actual_cwe": truth["cwe"],
                "num_semgrep_records": len(all_records_for_test),
                "hybrid_verdicts": [
                    record.get("analyzer_verdict")
                    for record in all_records_for_test
                ],
                "hybrid_confidences": [
                    record.get("confidence")
                    for record in all_records_for_test
                ],
                "reasoning_samples": [
                    record.get("reasoning", "")
                    for record in all_records_for_test[:3]
                ]
            })

    # -----------------------------
    # LLM-only analysis
    # -----------------------------

    llm_false_positives = []
    llm_false_negatives = []

    for record in llm_records:
        actual_vulnerable = bool(record["actual_vulnerable"])
        predicted_vulnerable = bool(record["predicted_vulnerable"])

        if not actual_vulnerable and predicted_vulnerable:
            failure_type = classify_llm_false_positive(record)
            taxonomy_counter[("LLM-only", failure_type)] += 1

            llm_false_positives.append({
                **record,
                "failure_type": failure_type,
                "failure_group": "false_positive"
            })

        if actual_vulnerable and not predicted_vulnerable:
            failure_type = classify_llm_false_negative(record)
            taxonomy_counter[("LLM-only", failure_type)] += 1

            llm_false_negatives.append({
                **record,
                "failure_type": failure_type,
                "failure_group": "false_negative"
            })

        # Additional CWE mismatch analysis
        if (
            actual_vulnerable
            and predicted_vulnerable
            and record.get("predicted_cwe") != record.get("actual_cwe")
        ):
            taxonomy_counter[("LLM-only", "CWE_MISMATCH")] += 1

    # -----------------------------
    # Write outputs
    # -----------------------------

    write_jsonl(HYBRID_FP_PATH, hybrid_false_positives)
    write_jsonl(HYBRID_FN_PATH, hybrid_false_negatives)
    write_jsonl(LLM_FP_PATH, llm_false_positives)
    write_jsonl(LLM_FN_PATH, llm_false_negatives)

    TAXONOMY_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(TAXONOMY_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "system",
                "failure_type",
                "count"
            ]
        )

        writer.writeheader()

        for (system, failure_type), count in sorted(
            taxonomy_counter.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            writer.writerow({
                "system": system,
                "failure_type": failure_type,
                "count": count
            })

    print("\n===== WEEK 5 FAILURE ANALYSIS COMPLETE =====")
    print(f"Hybrid false positives : {len(hybrid_false_positives)}")
    print(f"Hybrid false negatives : {len(hybrid_false_negatives)}")
    print(f"LLM false positives    : {len(llm_false_positives)}")
    print(f"LLM false negatives    : {len(llm_false_negatives)}")

    print("\n===== TOP FAILURE TYPES =====")

    for (system, failure_type), count in taxonomy_counter.most_common(20):
        print(f"{system} | {failure_type}: {count}")

    print("\nSaved files:")
    print(HYBRID_FP_PATH)
    print(HYBRID_FN_PATH)
    print(LLM_FP_PATH)
    print(LLM_FN_PATH)
    print(TAXONOMY_PATH)


if __name__ == "__main__":
    main()