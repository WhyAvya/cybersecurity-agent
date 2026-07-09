# evaluation/llm_baseline.py

import json
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from agents.llm_baseline_agent import run_llm_baseline
from evaluation.metrics import normalize_cwe


GROUND_TRUTH_PATH = Path("evaluation/ground_truth.json")
DATASET_DIR = Path("data/BenchmarkPython")


def load_ground_truth():
    with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def find_file(test_id):
    matches = list(DATASET_DIR.rglob(f"{test_id}.py"))

    if not matches:
        return None

    return matches[0]


def compute_metrics(records, strict_cwe=False):
    tp = fp = fn = tn = 0

    for record in records:
        actual_vulnerable = bool(record["actual_vulnerable"])
        predicted_vulnerable = bool(record["predicted_vulnerable"])

        if strict_cwe and predicted_vulnerable:
            predicted_vulnerable = (
                normalize_cwe(record["predicted_cwe"])
                == normalize_cwe(record["actual_cwe"])
            )

        if actual_vulnerable and predicted_vulnerable:
            tp += 1
        elif not actual_vulnerable and predicted_vulnerable:
            fp += 1
        elif actual_vulnerable and not predicted_vulnerable:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def print_metrics(title, metrics):
    print(f"\n===== {title} =====")
    print(f"True Positives : {metrics['tp']}")
    print(f"False Positives: {metrics['fp']}")
    print(f"False Negatives: {metrics['fn']}")
    print(f"True Negatives : {metrics['tn']}")

    print("\n===== METRICS =====")
    print(f"Precision : {metrics['precision']:.3f} ({metrics['precision'] * 100:.1f}%)")
    print(f"Recall    : {metrics['recall']:.3f} ({metrics['recall'] * 100:.1f}%)")
    print(f"F1 Score  : {metrics['f1']:.3f} ({metrics['f1'] * 100:.1f}%)")
    print(f"FPR       : {metrics['fpr']:.3f} ({metrics['fpr'] * 100:.1f}%)")


def main():
    ground_truth = load_ground_truth()

    max_files = int(os.environ.get("MAX_FILES", "20"))

    items = list(ground_truth.items())

    if max_files > 0:
        items = items[:max_files]

    output_name = f"llm_baseline_{max_files if max_files > 0 else 'full'}.jsonl"
    output_path = Path("results") / output_name
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Loaded {len(ground_truth)} benchmark entries")
    print(f"MAX_FILES = {max_files}")
    print(f"Ready to evaluate {len(items)} files.")
    print(f"Saving output to {output_path}")

    records = []

    with open(output_path, "w", encoding="utf-8") as out:
        for index, (test_id, truth) in enumerate(items, start=1):
            file_path = find_file(test_id)

            if file_path is None:
                prediction = {
                    "verdict": "SAFE",
                    "cwe": "NONE",
                    "confidence": 0.0,
                    "reasoning": "File not found.",
                    "schema_valid": False,
                }
            else:
                code = file_path.read_text(encoding="utf-8", errors="ignore")
                prediction = run_llm_baseline(code)

            predicted_vulnerable = prediction["verdict"] == "VULNERABLE"

            record = {
                "test_id": test_id,
                "condition": "llm_only",
                "actual_vulnerable": bool(truth["vulnerable"]),
                "actual_cwe": normalize_cwe(truth["cwe"]),
                "predicted_vulnerable": predicted_vulnerable,
                "predicted_cwe": normalize_cwe(prediction.get("cwe", "NONE")),
                "confidence": float(prediction.get("confidence", 0.0)),
                "reasoning": prediction.get("reasoning", ""),
                "schema_valid": bool(prediction.get("schema_valid", False)),
            }

            records.append(record)
            out.write(json.dumps(record) + "\n")

            print(
                f"[{index}/{len(items)}] {test_id} | "
                f"pred={record['predicted_vulnerable']} | "
                f"cwe={record['predicted_cwe']} | "
                f"conf={record['confidence']}"
            )

    binary_metrics = compute_metrics(records, strict_cwe=False)
    strict_metrics = compute_metrics(records, strict_cwe=True)

    print_metrics("LLM ONLY - BINARY DETECTION", binary_metrics)
    print_metrics("LLM ONLY - STRICT CWE MATCH", strict_metrics)

    total = len(records)
    schema_valid = sum(1 for r in records if r["schema_valid"])

    print("\n===== LLM RELIABILITY =====")
    print(f"Total records       : {total}")
    print(f"Schema valid records: {schema_valid}")
    print(f"Schema validity rate: {schema_valid / total if total else 0:.3f}")
    print(f"Saved raw output    : {output_path}")


if __name__ == "__main__":
    main()