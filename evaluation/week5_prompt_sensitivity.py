# evaluation/week5_prompt_sensitivity.py

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from agents.scanner_agent import run_scanner
from llm.ollama_client import call_qwen


HYBRID_RESULTS_PATH = Path("results/hybrid_findings.jsonl")
OUTPUT_CSV = Path("results/week5_prompt_sensitivity.csv")
OUTPUT_SUMMARY_CSV = Path("results/week5_prompt_sensitivity_summary.csv")


PROMPT_STYLES = {
    "strict": """
You are a strict cybersecurity verifier.

Classify the Semgrep finding as TP, FP, or UNCERTAIN.

Use TP only if there is clear evidence of:
1. user-controlled input,
2. data flow to a dangerous sink,
3. no effective sanitization,
4. correct CWE match.

If any evidence is missing, prefer FP or UNCERTAIN.
Do not over-report.
""",

    "balanced": """
You are a balanced cybersecurity analyst.

Classify the Semgrep finding as TP, FP, or UNCERTAIN.

Consider source, data flow, sink, sanitization, and CWE match.
Use TP when the finding is likely exploitable.
Use FP when the code does not support the finding.
Use UNCERTAIN when evidence is incomplete.
""",

    "recall_focused": """
You are a recall-focused cybersecurity analyst.

Classify the Semgrep finding as TP, FP, or UNCERTAIN.

Your goal is to avoid missing real vulnerabilities.
Use TP if there is reasonable evidence that user input may reach a dangerous operation.
Use FP only when the finding is clearly not exploitable.
Use UNCERTAIN when the evidence is mixed.
"""
}


def load_jsonl(path):
    records = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    return records


def make_finding_object(record, index):
    return SimpleNamespace(
        finding_id=f"prompt_sensitivity_{index}",
        file=record["file"],
        line=int(record["line"]),
        rule_id=record["rule_id"],
        cwe_tag=record["semgrep_cwe"],
        severity="MEDIUM"
    )


def select_balanced_sample(records, per_verdict=5):
    grouped = defaultdict(list)

    for record in records:
        verdict = str(record.get("analyzer_verdict", "UNCERTAIN")).upper()
        grouped[verdict].append(record)

    sample = []

    for verdict in ["TP", "FP", "UNCERTAIN"]:
        sample.extend(grouped[verdict][:per_verdict])

    return sample


def extract_json(response):
    response = response.replace("```json", "")
    response = response.replace("```", "")
    response = response.strip()

    match = re.search(r"\{.*\}", response, re.DOTALL)

    if not match:
        raise ValueError("No JSON object found")

    return json.loads(match.group(0))


def run_prompt_style(style_name, finding, context):
    style_prompt = PROMPT_STYLES[style_name]

    prompt = f"""
{style_prompt}

Allowed verdict values:
TP
FP
UNCERTAIN

Do NOT output FN.
Do NOT output TN.
Do NOT output any other label.

Finding details:

File:
{finding.file}

Rule:
{finding.rule_id}

CWE:
{finding.cwe_tag}

Code Context:
{context["context_lines"]}

Return ONLY valid JSON in this exact format:

{{
    "verdict": "TP",
    "confidence": 0.90,
    "reasoning": "short explanation"
}}
"""

    response = call_qwen(prompt)

    result = extract_json(response)

    verdict = str(result.get("verdict", "UNCERTAIN")).upper()

    if verdict not in ["TP", "FP", "UNCERTAIN"]:
        verdict = "UNCERTAIN"

    return {
        "verdict": verdict,
        "confidence": float(result.get("confidence", 0.0)),
        "reasoning": result.get("reasoning", ""),
        "parse_success": True
    }


def main():
    records = load_jsonl(HYBRID_RESULTS_PATH)

    sample = select_balanced_sample(records, per_verdict=5)

    print(f"Loaded hybrid records: {len(records)}")
    print(f"Selected prompt sensitivity sample: {len(sample)}")
    print("Testing strict, balanced, and recall-focused prompts...")

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    for index, record in enumerate(sample, start=1):
        finding = make_finding_object(record, index)
        context = run_scanner(finding)

        original_verdict = str(
            record.get("analyzer_verdict", "UNCERTAIN")
        ).upper()

        for style_name in ["strict", "balanced", "recall_focused"]:
            try:
                result = run_prompt_style(style_name, finding, context)

            except Exception as e:
                result = {
                    "verdict": "UNCERTAIN",
                    "confidence": 0.0,
                    "reasoning": f"Prompt sensitivity run failed: {str(e)}",
                    "parse_success": False
                }

            row = {
                "test_id": record.get("test_id"),
                "file": record.get("file"),
                "line": record.get("line"),
                "semgrep_cwe": record.get("semgrep_cwe"),
                "actual_vulnerable": record.get("actual_vulnerable"),
                "actual_cwe": record.get("actual_cwe"),
                "original_verdict": original_verdict,
                "prompt_style": style_name,
                "new_verdict": result["verdict"],
                "confidence": result["confidence"],
                "parse_success": result["parse_success"],
                "matches_original": original_verdict == result["verdict"],
                "reasoning": result["reasoning"]
            }

            rows.append(row)

            print(
                f"[{index}/{len(sample)}] "
                f"{record.get('test_id')} | "
                f"{style_name} | "
                f"{original_verdict} -> {result['verdict']}"
            )

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(rows[0].keys())
        )

        writer.writeheader()
        writer.writerows(rows)

    summary_rows = []

    for style_name in ["strict", "balanced", "recall_focused"]:
        style_rows = [
            row for row in rows
            if row["prompt_style"] == style_name
        ]

        verdict_counts = Counter(
            row["new_verdict"]
            for row in style_rows
        )

        total = len(style_rows)

        matches = sum(
            1 for row in style_rows
            if row["matches_original"]
        )

        avg_confidence = (
            sum(row["confidence"] for row in style_rows) / total
            if total
            else 0
        )

        parse_success_count = sum(
            1 for row in style_rows
            if row["parse_success"]
        )

        summary_rows.append({
            "prompt_style": style_name,
            "total": total,
            "tp_count": verdict_counts.get("TP", 0),
            "fp_count": verdict_counts.get("FP", 0),
            "uncertain_count": verdict_counts.get("UNCERTAIN", 0),
            "matches_original": matches,
            "match_rate": round(matches / total, 3) if total else 0,
            "avg_confidence": round(avg_confidence, 3),
            "parse_success_count": parse_success_count,
            "parse_success_rate": round(parse_success_count / total, 3) if total else 0
        })

    with open(OUTPUT_SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(summary_rows[0].keys())
        )

        writer.writeheader()
        writer.writerows(summary_rows)

    print("\n===== WEEK 5 PROMPT SENSITIVITY COMPLETE =====")

    for row in summary_rows:
        print(
            f"{row['prompt_style']} | "
            f"TP={row['tp_count']} "
            f"FP={row['fp_count']} "
            f"UNCERTAIN={row['uncertain_count']} | "
            f"match_rate={row['match_rate']} | "
            f"avg_conf={row['avg_confidence']} | "
            f"parse_success={row['parse_success_rate']}"
        )

    print(f"\nSaved detailed results to: {OUTPUT_CSV}")
    print(f"Saved summary results to : {OUTPUT_SUMMARY_CSV}")


if __name__ == "__main__":
    main()
