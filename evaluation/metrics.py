# evaluation/metrics.py

import re


def normalize_cwe(cwe_text):
    """
    Normalize CWE formats:
    CWE-79  -> CWE-079
    CWE-22  -> CWE-022
    CWE-611 -> CWE-611
    CWE-611: description -> CWE-611
    """

    if not cwe_text:
        return "NONE"

    match = re.search(r"CWE[-_]?(\d+)", str(cwe_text), re.IGNORECASE)

    if not match:
        return "NONE"

    return f"CWE-{int(match.group(1)):03d}"


def evaluate(grouped_findings, ground_truth, benchmark_cwes):
    """
    Evaluate Semgrep or agent predictions against benchmark ground truth.

    This evaluates:
    - vulnerable file detected or missed
    - false positives on non-vulnerable files
    - CWE match for vulnerable files
    """

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    normalized_benchmark_cwes = {
        normalize_cwe(cwe) for cwe in benchmark_cwes
    }

    for test_id, truth in ground_truth.items():

        findings = grouped_findings.get(test_id, [])

        expected_cwe = normalize_cwe(truth["cwe"])

        valid_findings = []

        for finding in findings:
            predicted_cwe = normalize_cwe(finding.get("cwe_tag", ""))

            if predicted_cwe in normalized_benchmark_cwes:
                valid_findings.append(predicted_cwe)

        has_valid_finding = len(valid_findings) > 0
        has_correct_cwe = expected_cwe in valid_findings

        if truth["vulnerable"]:

            if has_correct_cwe:
                tp += 1
            else:
                fn += 1

        else:

            if has_valid_finding:
                fp += 1
            else:
                tn += 1

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn
    }


def calculate_metrics(results):
    """
    Calculate precision, recall, F1, and false positive rate.
    """

    tp = results["tp"]
    fp = results["fp"]
    fn = results["fn"]
    tn = results["tn"]

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    if precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0

    fpr = fp / (fp + tn) if (fp + tn) else 0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr
    }


def print_metrics(results, title="RESULTS"):
    """
    Print evaluation metrics.
    """

    metrics = calculate_metrics(results)

    print(f"\n===== {title} =====")

    print(f"True Positives : {results['tp']}")
    print(f"False Positives: {results['fp']}")
    print(f"False Negatives: {results['fn']}")
    print(f"True Negatives : {results['tn']}")

    print("\n===== METRICS =====")

    print(f"Precision : {metrics['precision']:.3f}")
    print(f"Recall    : {metrics['recall']:.3f}")
    print(f"F1 Score  : {metrics['f1']:.3f}")
    print(f"FPR       : {metrics['fpr']:.3f}")


if __name__ == "__main__":
    print("metrics.py contains reusable evaluation functions.")
    print("Run this instead:")
    print("python -m evaluation.semgrep_baseline")