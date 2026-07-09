# evaluation/week5_consistency_test.py

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from agents.scanner_agent import run_scanner
from agents.analyzer_agent import run_analyzer


HYBRID_RESULTS_PATH = Path("results/hybrid_findings.jsonl")
OUTPUT_CSV = Path("results/week5_consistency_results.csv")


def load_jsonl(path):
    records = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    return records


def make_finding_object(record, index):
    return SimpleNamespace(
        finding_id=f"consistency_{index}",
        file=record["file"],
        line=int(record["line"]),
        rule_id=record["rule_id"],
        cwe_tag=record["semgrep_cwe"],
        severity="MEDIUM"
    )


def select_balanced_sample(records, per_verdict=10):
    grouped = defaultdict(list)

    for record in records:
        verdict = str(record.get("analyzer_verdict", "UNCERTAIN")).upper()
        grouped[verdict].append(record)

    sample = []

    for verdict in ["TP", "FP", "UNCERTAIN"]:
        sample.extend(grouped[verdict][:per_verdict])

    return sample


def main():
    records = load_jsonl(HYBRID_RESULTS_PATH)

    sample = select_balanced_sample(records, per_verdict=10)

    print(f"Loaded hybrid records: {len(records)}")
    print(f"Selected consistency sample: {len(sample)}")
    print("Rerunning analyzer on selected findings...")

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    for index, record in enumerate(sample, start=1):
        finding = make_finding_object(record, index)

        try:
            context = run_scanner(finding)
            repeat_analysis = run_analyzer(finding, context)

            repeat_verdict = str(
                repeat_analysis.get("verdict", "UNCERTAIN")
            ).upper()

            repeat_confidence = float(
                repeat_analysis.get("confidence", 0.0)
            )

            repeat_reasoning = repeat_analysis.get("reasoning", "")

        except Exception as e:
            repeat_verdict = "UNCERTAIN"
            repeat_confidence = 0.0
            repeat_reasoning = f"Consistency rerun failed: {str(e)}"

        original_verdict = str(
            record.get("analyzer_verdict", "UNCERTAIN")
        ).upper()

        original_confidence = float(
            record.get("confidence", 0.0)
        )

        verdict_match = original_verdict == repeat_verdict
        confidence_difference = abs(original_confidence - repeat_confidence)

        row = {
            "test_id": record.get("test_id"),
            "file": record.get("file"),
            "line": record.get("line"),
            "semgrep_cwe": record.get("semgrep_cwe"),
            "actual_vulnerable": record.get("actual_vulnerable"),
            "actual_cwe": record.get("actual_cwe"),
            "original_verdict": original_verdict,
            "repeat_verdict": repeat_verdict,
            "verdict_match": verdict_match,
            "original_confidence": original_confidence,
            "repeat_confidence": repeat_confidence,
            "confidence_difference": round(confidence_difference, 3),
            "original_reasoning": record.get("reasoning", ""),
            "repeat_reasoning": repeat_reasoning
        }

        rows.append(row)

        print(
            f"[{index}/{len(sample)}] "
            f"{record.get('test_id')} | "
            f"{original_verdict} -> {repeat_verdict} | "
            f"match={verdict_match}"
        )

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(rows[0].keys())
        )

        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    matches = sum(1 for row in rows if row["verdict_match"])
    consistency_rate = matches / total if total else 0

    avg_confidence_diff = (
        sum(row["confidence_difference"] for row in rows) / total
        if total
        else 0
    )

    print("\n===== WEEK 5 CONSISTENCY TEST COMPLETE =====")
    print(f"Total repeated cases : {total}")
    print(f"Matching verdicts    : {matches}")
    print(f"Consistency rate     : {consistency_rate:.3f} ({consistency_rate * 100:.1f}%)")
    print(f"Avg confidence diff  : {avg_confidence_diff:.3f}")
    print(f"Saved results to     : {OUTPUT_CSV}")


if __name__ == "__main__":
    main()