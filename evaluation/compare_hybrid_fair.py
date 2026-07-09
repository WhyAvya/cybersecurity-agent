# evaluation/compare_hybrid_fair.py

import csv
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from evaluation.metrics import evaluate, normalize_cwe


GROUND_TRUTH_PATH = Path("evaluation/ground_truth.json")
HYBRID_RESULTS_PATH = Path("results/hybrid_findings.jsonl")
OUTPUT_CSV = Path("results/week4_semgrep_vs_hybrid_fair.csv")


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
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def binary_evaluate(grouped_findings, ground_truth):
    """
    Binary vulnerability detection:
    If a system flags a file as vulnerable, that is prediction=True.
    CWE does not need to match here.
    """

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
        "tn": tn,
    }


def build_grouped_findings(records, mode):
    """
    mode='semgrep':
        Treat every Semgrep finding as accepted.

    mode='hybrid':
        Only keep findings where analyzer_verdict == TP.
        FP and UNCERTAIN are treated as rejected by the hybrid system.
    """

    grouped = {}

    for record in records:
        test_id = record["test_id"]
        semgrep_cwe = normalize_cwe(record.get("semgrep_cwe", "NONE"))

        if mode == "semgrep":
            grouped.setdefault(test_id, []).append({
                "cwe_tag": semgrep_cwe
            })

        elif mode == "hybrid":
            verdict = str(record.get("analyzer_verdict", "")).upper()

            if verdict == "TP":
                grouped.setdefault(test_id, []).append({
                    "cwe_tag": semgrep_cwe
                })

    return grouped


def make_row(system, metric_type, results):
    m = calculate_metrics(results)

    return {
        "System": system,
        "Metric Type": metric_type,
        "TP": results["tp"],
        "FP": results["fp"],
        "FN": results["fn"],
        "TN": results["tn"],
        "Precision": round(m["precision"], 3),
        "Recall": round(m["recall"], 3),
        "F1": round(m["f1"], 3),
        "FPR": round(m["fpr"], 3),
    }


def print_row(row):
    print(
        f"{row['System']} | {row['Metric Type']} | "
        f"TP={row['TP']} FP={row['FP']} FN={row['FN']} TN={row['TN']} | "
        f"P={row['Precision']} R={row['Recall']} "
        f"F1={row['F1']} FPR={row['FPR']}"
    )


def main():
    ground_truth = load_ground_truth()
    records = load_jsonl(HYBRID_RESULTS_PATH)

    benchmark_cwes = {
        normalize_cwe(item["cwe"])
        for item in ground_truth.values()
    }

    semgrep_grouped = build_grouped_findings(records, mode="semgrep")
    hybrid_grouped = build_grouped_findings(records, mode="hybrid")

    rows = []

    # Binary detection metrics
    rows.append(make_row(
        "Semgrep only",
        "Binary detection",
        binary_evaluate(semgrep_grouped, ground_truth)
    ))

    rows.append(make_row(
        "Hybrid pipeline",
        "Binary detection",
        binary_evaluate(hybrid_grouped, ground_truth)
    ))

    # Strict CWE-matched metrics
    rows.append(make_row(
        "Semgrep only",
        "Strict CWE match",
        evaluate(semgrep_grouped, ground_truth, benchmark_cwes)
    ))

    rows.append(make_row(
        "Hybrid pipeline",
        "Strict CWE match",
        evaluate(hybrid_grouped, ground_truth, benchmark_cwes)
    ))

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print("\n===== FAIR SEMGREP VS HYBRID COMPARISON =====")
    print(f"Loaded hybrid records: {len(records)}")
    print(f"Semgrep flagged test files: {len(semgrep_grouped)}")
    print(f"Hybrid accepted test files: {len(hybrid_grouped)}")
    print()

    for row in rows:
        print_row(row)

    print(f"\nSaved comparison CSV to: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()