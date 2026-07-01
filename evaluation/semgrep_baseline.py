# evaluation/semgrep_baseline.py

import json

from tools.semgrep_tool import run_semgrep

from evaluation.filters import (
    group_findings,
    build_benchmark_cwes,
)

from evaluation.metrics import (
    evaluate,
    print_metrics,
)


def load_ground_truth():
    """
    Load the OWASP Benchmark ground truth.
    """

    with open("evaluation/ground_truth.json", "r") as f:
        ground_truth = json.load(f)

    print(
        f"Loaded {len(ground_truth)} benchmark entries"
    )

    return ground_truth


def load_semgrep_findings():
    """
    Run Semgrep on the benchmark dataset.
    """

    findings = run_semgrep(
        "data/BenchmarkPython/testcode",
        "auto"
    )

    print(
        f"Semgrep found {len(findings)} findings"
    )

    return findings


def main():

    ground_truth = load_ground_truth()

    benchmark_cwes = build_benchmark_cwes(
        ground_truth
    )

    raw_findings = load_semgrep_findings()

    grouped_findings = group_findings(
        raw_findings
    )

    results = evaluate(
        grouped_findings,
        ground_truth,
        benchmark_cwes
    )

    print_metrics(results)


if __name__ == "__main__":
    main()