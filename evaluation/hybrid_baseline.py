# evaluation/hybrid_baseline.py

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from tools.semgrep_tool import run_semgrep
from agents.scanner_agent import run_scanner
from agents.analyzer_agent import run_analyzer
from evaluation.metrics import evaluate, print_metrics, normalize_cwe


GROUND_TRUTH_PATH = Path("evaluation/ground_truth.json")
DATASET_DIR = "data/BenchmarkPython"
OUTPUT_PATH = Path("results/hybrid_findings.jsonl")


def extract_test_id(path):
    """
    Converts any path containing BenchmarkTest00001.py
    into BenchmarkTest00001.
    """

    match = re.search(r"BenchmarkTest\d+", str(path))

    if not match:
        return None

    return match.group(0)


def get_value(obj, *keys, default=None):
    """
    Safely read from dict or object.
    """

    for key in keys:
        if isinstance(obj, dict) and key in obj:
            return obj[key]

        if hasattr(obj, key):
            return getattr(obj, key)

    return default


def convert_to_finding_object(raw_finding, index):
    """
    Converts Semgrep dict output into the object format expected by agents.
    """

    file_path = get_value(
        raw_finding,
        "file",
        "path",
        "filename",
        default=""
    )

    line = get_value(
        raw_finding,
        "line",
        "start_line",
        default=1
    )

    rule_id = get_value(
        raw_finding,
        "rule_id",
        "check_id",
        "rule",
        default="unknown_rule"
    )

    cwe_tag = get_value(
        raw_finding,
        "cwe_tag",
        "cwe",
        default="NONE"
    )

    severity = get_value(
        raw_finding,
        "severity",
        default="MEDIUM"
    )

    return SimpleNamespace(
        finding_id=f"hybrid_{index}",
        file=file_path,
        line=line,
        rule_id=rule_id,
        cwe_tag=normalize_cwe(cwe_tag),
        severity=str(severity).upper()
    )


def load_ground_truth():
    with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    ground_truth = load_ground_truth()

    benchmark_cwes = {
        normalize_cwe(item["cwe"])
        for item in ground_truth.values()
    }

    print(f"Loaded {len(ground_truth)} benchmark entries")
    print("Running Semgrep...")

    raw_findings = run_semgrep(DATASET_DIR)

    print(f"Semgrep found {len(raw_findings)} raw findings")
    print("Running hybrid analyzer on Semgrep findings...")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    accepted_grouped_findings = {}
    total_analyzed = 0
    tp_verdicts = 0
    fp_verdicts = 0
    uncertain_verdicts = 0
    parse_failures = 0

    with open(OUTPUT_PATH, "w", encoding="utf-8") as out:

        for index, raw_finding in enumerate(raw_findings, start=1):

            finding = convert_to_finding_object(raw_finding, index)

            test_id = extract_test_id(finding.file)

            if test_id is None:
                continue

            try:
                context = run_scanner(finding)
                analysis = run_analyzer(finding, context)

                verdict = analysis.get("verdict", "UNCERTAIN").upper()
                confidence = float(analysis.get("confidence", 0.0))

            except Exception as e:
                verdict = "UNCERTAIN"
                confidence = 0.0
                analysis = {
                    "reasoning": f"Hybrid pipeline failed: {str(e)}",
                    "iterations": 1,
                    "tool_call_evaded": True
                }
                parse_failures += 1

            total_analyzed += 1

            if verdict == "TP":
                tp_verdicts += 1

                accepted_grouped_findings.setdefault(test_id, []).append({
                    "cwe_tag": finding.cwe_tag,
                    "confidence": confidence,
                    "reasoning": analysis.get("reasoning", "")
                })

            elif verdict == "FP":
                fp_verdicts += 1

            else:
                uncertain_verdicts += 1

            record = {
                "test_id": test_id,
                "condition": "hybrid",
                "file": finding.file,
                "line": finding.line,
                "rule_id": finding.rule_id,
                "semgrep_cwe": finding.cwe_tag,
                "analyzer_verdict": verdict,
                "confidence": confidence,
                "reasoning": analysis.get("reasoning", ""),
                "iterations": analysis.get("iterations", 1),
                "tool_call_evaded": analysis.get("tool_call_evaded", False),
                "actual_vulnerable": ground_truth.get(test_id, {}).get("vulnerable"),
                "actual_cwe": ground_truth.get(test_id, {}).get("cwe")
            }

            out.write(json.dumps(record) + "\n")

            print(
                f"[{index}/{len(raw_findings)}] "
                f"{test_id} | {finding.cwe_tag} | {verdict} | {confidence}"
            )

    results = evaluate(
        accepted_grouped_findings,
        ground_truth,
        benchmark_cwes
    )

    print_metrics(results, title="HYBRID PIPELINE")

    print("\n===== HYBRID RELIABILITY =====")
    print(f"Total analyzed findings : {total_analyzed}")
    print(f"Analyzer TP verdicts   : {tp_verdicts}")
    print(f"Analyzer FP verdicts   : {fp_verdicts}")
    print(f"UNCERTAIN verdicts     : {uncertain_verdicts}")
    print(f"Parse/pipeline failures: {parse_failures}")
    print(f"Saved raw hybrid output: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()