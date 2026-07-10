# evaluation/evaluate_multi_file_demo.py

import json
import re
from pathlib import Path


REPORTS_DIR = Path("reports")

EXPECTED_CWE_CATEGORIES = {
    "CWE-078",  # OS command injection / subprocess command injection
    "CWE-089",  # SQL injection
    "CWE-022",  # Path traversal
}


def normalize_cwe(text):
    text = str(text)

    match = re.search(r"CWE[-_]?0*(\d+)", text, re.IGNORECASE)

    if not match:
        return "UNKNOWN"

    return f"CWE-{int(match.group(1)):03d}"


def calculate_metrics(tp, fp, fn, tn=0):
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )

    fpr = fp / (fp + tn) if (fp + tn) else None

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
    print(f"TP: {metrics['tp']}")
    print(f"FP: {metrics['fp']}")
    print(f"FN: {metrics['fn']}")
    print(f"TN: {metrics['tn']}")
    print(f"Precision: {metrics['precision']:.3f} ({metrics['precision'] * 100:.1f}%)")
    print(f"Recall   : {metrics['recall']:.3f} ({metrics['recall'] * 100:.1f}%)")
    print(f"F1 Score : {metrics['f1']:.3f} ({metrics['f1'] * 100:.1f}%)")

    if metrics["fpr"] is None:
        print("FPR      : Not meaningful for this vulnerable-only demo folder")
    else:
        print(f"FPR      : {metrics['fpr']:.3f} ({metrics['fpr'] * 100:.1f}%)")


def load_latest_jsonl_report():
    reports = sorted(
        REPORTS_DIR.glob("scan_report_*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not reports:
        raise FileNotFoundError("No JSONL reports found in reports/")

    latest_report = reports[0]

    records = []

    with open(latest_report, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    return latest_report, records


def main():
    latest_report, records = load_latest_jsonl_report()

    print(f"Loaded latest report: {latest_report}")
    print(f"Total findings in report: {len(records)}")

    print("\nFiles in latest report:")
    for file_name in sorted({record.get("file") for record in records}):
        print(f"- {file_name}")

    accepted = [
        record for record in records
        if record.get("status") == "ACCEPTED"
    ]

    review = [
        record for record in records
        if record.get("status") == "NEEDS_REVIEW"
    ]

    rejected = [
        record for record in records
        if record.get("status") == "REJECTED"
    ]

    print("\n===== STATUS COUNTS =====")
    print(f"Accepted    : {len(accepted)}")
    print(f"Needs review: {len(review)}")
    print(f"Rejected    : {len(rejected)}")

    # Raw finding-level demo evaluation:
    # In this intentionally vulnerable demo folder, all Semgrep findings are
    # around vulnerable code locations or duplicate rules for those locations.
    strict_tp = len(accepted)
    strict_fp = 0
    strict_fn = len(review) + len(rejected)

    print_metrics(
        "RAW FINDING LEVEL - STRICT ACCEPTED ONLY",
        calculate_metrics(
            tp=strict_tp,
            fp=strict_fp,
            fn=strict_fn,
        ),
    )

    review_tp = len(accepted) + len(review)
    review_fp = 0
    review_fn = len(rejected)

    print_metrics(
        "RAW FINDING LEVEL - ACCEPTED + NEEDS_REVIEW",
        calculate_metrics(
            tp=review_tp,
            fp=review_fp,
            fn=review_fn,
        ),
    )

    accepted_cwes = {
        normalize_cwe(record.get("cwe"))
        for record in accepted
    }

    review_cwes = {
        normalize_cwe(record.get("cwe"))
        for record in accepted + review
    }

    strict_category_tp = len(accepted_cwes & EXPECTED_CWE_CATEGORIES)
    strict_category_fp = len(accepted_cwes - EXPECTED_CWE_CATEGORIES)
    strict_category_fn = len(EXPECTED_CWE_CATEGORIES - accepted_cwes)

    print_metrics(
        "CWE CATEGORY LEVEL - STRICT ACCEPTED ONLY",
        calculate_metrics(
            tp=strict_category_tp,
            fp=strict_category_fp,
            fn=strict_category_fn,
        ),
    )

    review_category_tp = len(review_cwes & EXPECTED_CWE_CATEGORIES)
    review_category_fp = len(review_cwes - EXPECTED_CWE_CATEGORIES)
    review_category_fn = len(EXPECTED_CWE_CATEGORIES - review_cwes)

    print_metrics(
        "CWE CATEGORY LEVEL - ACCEPTED + NEEDS_REVIEW",
        calculate_metrics(
            tp=review_category_tp,
            fp=review_category_fp,
            fn=review_category_fn,
        ),
    )

    print("\nExpected CWE categories:")
    for cwe in sorted(EXPECTED_CWE_CATEGORIES):
        print(f"- {cwe}")

    print("\nAccepted CWE categories:")
    for cwe in sorted(accepted_cwes):
        print(f"- {cwe}")


if __name__ == "__main__":
    main()