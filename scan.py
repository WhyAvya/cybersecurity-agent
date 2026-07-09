# scan.py

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from agents.scanner_agent import run_scanner
from agents.analyzer_agent import run_analyzer
from agents.reporter_agent import run_reporter
from tools.semgrep_tool import run_semgrep


REPORTS_DIR = Path("reports")


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def infer_cwe_from_rule(rule_id, original_cwe):
    """
    Semgrep sometimes returns broad or unexpected CWE metadata.
    For demo reporting, infer the most relevant CWE from the rule name.
    """

    rule_text = str(rule_id).lower()

    if (
        "command" in rule_text
        or "os-system" in rule_text
        or "dangerous-system-call" in rule_text
    ):
        return "CWE-078: OS Command Injection"

    if (
        "sql" in rule_text
        or "tainted-sql" in rule_text
        or "raw-query" in rule_text
        or "cursor-execute" in rule_text
    ):
        return "CWE-089: SQL Injection"

    if "path-traversal" in rule_text:
        return "CWE-022: Path Traversal"

    return original_cwe


def normalize_severity(severity):
    severity = str(severity).upper()

    if severity == "ERROR":
        return "HIGH"

    if severity == "WARNING":
        return "MEDIUM"

    if severity in ["HIGH", "MEDIUM", "LOW"]:
        return severity

    return "MEDIUM"


def looks_contradictory_fp(finding, reasoning):
    """
    If the LLM says FP but the reasoning still contains strong vulnerability evidence,
    route the finding to NEEDS_REVIEW instead of confidently rejecting it.
    """

    text = f"{finding.rule_id} {reasoning}".lower()

    risky_terms = [
        "user-controlled",
        "without sanitization",
        "without validation",
        "directly concatenated",
        "directly passed",
        "os.system",
        "sql injection",
        "path traversal",
        "open function",
        "dangerous",
        "could potentially",
        "vulnerable"
    ]

    matches = sum(1 for term in risky_terms if term in text)

    return matches >= 2


def classify_report_status(verdict, finding=None, reasoning=""):
    verdict = str(verdict).upper()

    if verdict == "TP":
        return "ACCEPTED"

    if verdict == "FP":
        if finding is not None and looks_contradictory_fp(finding, reasoning):
            return "NEEDS_REVIEW"

        return "REJECTED"

    return "NEEDS_REVIEW"


def calculate_priority(status, severity, confidence):
    severity = normalize_severity(severity)

    if status == "ACCEPTED":
        if severity == "HIGH" and confidence >= 0.85:
            return "HIGH"

        if confidence >= 0.60:
            return "MEDIUM"

        return "LOW"

    if status == "NEEDS_REVIEW":
        return "MEDIUM"

    return "LOW"


def make_finding_object(raw_finding, index):
    rule_id = raw_finding.get("rule_id", "UNKNOWN_RULE")
    original_cwe = raw_finding.get("cwe_tag", "UNKNOWN_CWE")

    return SimpleNamespace(
        finding_id=raw_finding.get("finding_id", f"finding_{index}"),
        file=raw_finding.get("file", ""),
        line=int(raw_finding.get("line", 0)),
        rule_id=rule_id,
        cwe_tag=infer_cwe_from_rule(rule_id, original_cwe),
        severity=normalize_severity(raw_finding.get("severity", "MEDIUM")),
        snippet=raw_finding.get("snippet", "")
    )


def write_jsonl(records, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def write_markdown(records, summary, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = []

    lines.append("# Vulnerability Scan Report")
    lines.append("")
    lines.append(f"Generated at: {summary['generated_at']}")
    lines.append(f"Target path: `{summary['target_path']}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Raw Semgrep findings: {summary['raw_findings']}")
    lines.append(f"- Accepted vulnerabilities: {summary['accepted']}")
    lines.append(f"- Rejected findings: {summary['rejected']}")
    lines.append(f"- Needs human review: {summary['needs_review']}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not records:
        lines.append("No findings were produced.")
    else:
        for index, record in enumerate(records, start=1):
            lines.append(f"### Finding {index}: {record['status']}")
            lines.append("")
            lines.append(f"- File: `{record['file']}`")
            lines.append(f"- Line: {record['line']}")
            lines.append(f"- Rule: `{record['rule_id']}`")
            lines.append(f"- CWE: `{record['cwe']}`")
            lines.append(f"- Severity: `{record['severity']}`")
            lines.append(f"- Analyzer verdict: `{record['analyzer_verdict']}`")
            lines.append(f"- Confidence: {record['confidence']}")
            lines.append(f"- Priority: `{record['priority']}`")
            lines.append("")
            lines.append("Reasoning:")
            lines.append("")
            lines.append(record["reasoning"])
            lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def run_scan(target_path, semgrep_config):
    target_path = Path(target_path)

    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    REPORTS_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    jsonl_output = REPORTS_DIR / f"scan_report_{timestamp}.jsonl"
    markdown_output = REPORTS_DIR / f"scan_report_{timestamp}.md"

    print("===== REAL SCAN MODE =====")
    print(f"Target path: {target_path}")
    print(f"Semgrep config: {semgrep_config}")
    print()

    raw_findings = run_semgrep(str(target_path), config=semgrep_config)

    print(f"Raw Semgrep findings found: {len(raw_findings)}")

    records = []

    accepted = 0
    rejected = 0
    needs_review = 0

    for index, raw_finding in enumerate(raw_findings, start=1):
        finding = make_finding_object(raw_finding, index)

        print(
            f"[{index}/{len(raw_findings)}] "
            f"{finding.file}:{finding.line} | {finding.rule_id}"
        )

        try:
            context = run_scanner(finding)
            analysis = run_analyzer(finding, context)
            reporter_output = run_reporter(finding, analysis)

            verdict = str(analysis.get("verdict", "UNCERTAIN")).upper()
            confidence = safe_float(analysis.get("confidence", 0.0))
            reasoning = analysis.get("reasoning", "")

            cwe = infer_cwe_from_rule(
                finding.rule_id,
                reporter_output.get("cwe_id", finding.cwe_tag)
            )

        except Exception as e:
            verdict = "UNCERTAIN"
            confidence = 0.0
            reasoning = f"Pipeline failed during real scan: {str(e)}"
            cwe = finding.cwe_tag

        status = classify_report_status(verdict, finding, reasoning)
        priority = calculate_priority(status, finding.severity, confidence)

        if status == "ACCEPTED":
            accepted += 1
        elif status == "REJECTED":
            rejected += 1
        else:
            needs_review += 1

        record = {
            "scan_mode": "real_project_scan",
            "status": status,
            "file": finding.file,
            "line": finding.line,
            "rule_id": finding.rule_id,
            "cwe": cwe,
            "severity": finding.severity,
            "analyzer_verdict": verdict,
            "confidence": confidence,
            "priority": priority,
            "reasoning": reasoning
        }

        records.append(record)

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target_path": str(target_path),
        "raw_findings": len(raw_findings),
        "accepted": accepted,
        "rejected": rejected,
        "needs_review": needs_review
    }

    write_jsonl(records, jsonl_output)
    write_markdown(records, summary, markdown_output)

    print()
    print("===== SCAN COMPLETE =====")
    print(f"Raw Semgrep findings : {len(raw_findings)}")
    print(f"Accepted             : {accepted}")
    print(f"Rejected             : {rejected}")
    print(f"Needs review         : {needs_review}")
    print(f"JSONL report saved   : {jsonl_output}")
    print(f"Markdown report saved: {markdown_output}")


def main():
    parser = argparse.ArgumentParser(
        description="Run the hybrid Semgrep + LLM vulnerability scan on a Python project."
    )

    parser.add_argument(
        "target_path",
        help="Path to the Python file or folder to scan."
    )

    parser.add_argument(
        "--config",
        default="auto",
        help="Semgrep config to use. Default: auto"
    )

    args = parser.parse_args()

    run_scan(args.target_path, args.config)


if __name__ == "__main__":
    main()