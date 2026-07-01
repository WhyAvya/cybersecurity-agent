# evaluation/metrics.py

def evaluate(grouped_findings, ground_truth, benchmark_cwes):
    """
    Evaluate predictions against the benchmark.
    """

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for test_id, truth in ground_truth.items():

        findings = grouped_findings.get(test_id, [])

        expected_cwe = truth["cwe"]

        found_match = False

        for finding in findings:

            semgrep_cwe = (
                finding["cwe_tag"]
                .split(":")[0]
                .strip()
            )

            if semgrep_cwe not in benchmark_cwes:
                continue

            if semgrep_cwe == expected_cwe:
                found_match = True
                break

        if truth["vulnerable"]:

            if found_match:
                tp += 1
            else:
                fn += 1

        else:

            if len(findings) == 0:
                tn += 1
            else:
                fp += 1

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn
    }


def print_metrics(results):
    """
    Print evaluation metrics.
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

    print("\n===== SEMGREP BASELINE =====")
    print(f"True Positives : {tp}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Negatives : {tn}")

    print("\n===== METRICS =====")
    print(f"Precision : {precision:.3f}")
    print(f"Recall    : {recall:.3f}")
    print(f"F1 Score  : {f1:.3f}")
    print(f"FPR       : {fpr:.3f}")