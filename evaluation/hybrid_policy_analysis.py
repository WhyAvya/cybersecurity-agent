# evaluation/hybrid_policy_analysis.py

import csv
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from evaluation.metrics import evaluate, normalize_cwe


GROUND_TRUTH_PATH = Path("evaluation/ground_truth.json")
HYBRID_RESULTS_PATH = Path("results/hybrid_findings.jsonl")
OUTPUT_CSV = Path("results/hybrid_policy_analysis.csv")


def load_ground_truth():
    with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path):
    records = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    return records


def calculate_metrics(results):
    tp = results["tp"]
    fp = results["fp"]
    fn = results["fn"]
    tn = results["tn"]

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0

    return precision, recall, f1, fpr


def binary_evaluate(grouped_findings, ground_truth):
    tp = fp = fn = tn = 0

    for test_id, truth in ground_truth.items():
        actual = bool(truth["vulnerable"])
        predicted = test_id in grouped_findings and len(grouped_findings[test_id]) > 0

        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        else:
            tn += 1

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn
    }


def should_accept(record, policy):
    verdict = str(record.get("analyzer_verdict", "")).upper()
    confidence = float(record.get("confidence", 0.0))

    if policy == "Hybrid-Strict":
        return verdict == "TP"

    if policy == "Hybrid-Review":
        return verdict in ["TP", "UNCERTAIN"]

    if policy == "Hybrid-Conf75":
        return verdict == "TP" or confidence >= 0.75

    return False


def build_grouped(records, policy):
    grouped = {}

    for record in records:
        if not should_accept(record, policy):
            continue

        test_id = record["test_id"]

        grouped.setdefault(test_id, []).append({
            "cwe_tag": normalize_cwe(record.get("semgrep_cwe", "NONE"))
        })

    return grouped


def make_row(policy, metric_type, results, accepted_files):
    precision, recall, f1, fpr = calculate_metrics(results)

    return {
        "Policy": policy,
        "Metric Type": metric_type,
        "Accepted Files": accepted_files,
        "TP": results["tp"],
        "FP": results["fp"],
        "FN": results["fn"],
        "TN": results["tn"],
        "Precision": round(precision, 3),
        "Recall": round(recall, 3),
        "F1": round(f1, 3),
        "FPR": round(fpr, 3)
    }


def print_row(row):
    print(
        f"{row['Policy']} | {row['Metric Type']} | "
        f"Accepted={row['Accepted Files']} | "
        f"TP={row['TP']} FP={row['FP']} FN={row['FN']} TN={row['TN']} | "
        f"P={row['Precision']} R={row['Recall']} F1={row['F1']} FPR={row['FPR']}"
    )


def main():
    ground_truth = load_ground_truth()
    records = load_jsonl(HYBRID_RESULTS_PATH)

    benchmark_cwes = {
        normalize_cwe(item["cwe"])
        for item in ground_truth.values()
    }

    policies = [
        "Hybrid-Strict",
        "Hybrid-Review",
        "Hybrid-Conf75"
    ]

    rows = []

    print("\n===== HYBRID POLICY ANALYSIS =====")
    print(f"Loaded hybrid records: {len(records)}")
    print()

    for policy in policies:
        grouped = build_grouped(records, policy)
        accepted_files = len(grouped)

        binary_results = binary_evaluate(grouped, ground_truth)
        strict_results = evaluate(grouped, ground_truth, benchmark_cwes)

        rows.append(make_row(
            policy,
            "Binary detection",
            binary_results,
            accepted_files
        ))

        rows.append(make_row(
            policy,
            "Strict CWE match",
            strict_results,
            accepted_files
        ))

    for row in rows:
        print_row(row)

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved policy analysis to: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()