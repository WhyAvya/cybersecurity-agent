# evaluation/filters.py

from evaluation.extract_test_id import extract_test_id


def group_findings(raw_findings):
    """
    Group Semgrep findings by benchmark test.
    """

    grouped = {}

    for finding in raw_findings:

        test_id = extract_test_id(
            finding["file"]
        )

        if test_id not in grouped:
            grouped[test_id] = []

        grouped[test_id].append(
            finding
        )

    print(
        f"Grouped findings into {len(grouped)} benchmark tests."
    )

    return grouped


def build_benchmark_cwes(ground_truth):
    """
    Extract all benchmark CWEs from the benchmark dataset.
    """

    return {
        truth["cwe"]
        for truth in ground_truth.values()
    }