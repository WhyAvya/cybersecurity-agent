from schemas.verdict import SemgrepFinding, AgentVerdict

from agents.scanner_agent import run_scanner
from agents.analyzer_agent import run_analyzer
from agents.reporter_agent import run_reporter

from logger.jsonl_logger import log_verdict


def run_pipeline():

    finding = SemgrepFinding(
        finding_id="F001",
        file="data/BenchmarkPython/testcode/BenchmarkTest00001.py",
        line=47,
        rule_id="test-rule",
        cwe_tag="CWE-022",
        severity="HIGH",
        snippet="codecs.open(...)"
    )

    context = run_scanner(finding)

    analysis = run_analyzer(
        finding,
        context
    )

    report = run_reporter(
        finding,
        analysis
    )

    verdict = AgentVerdict(
        finding_id=finding.finding_id,
        verdict=analysis["verdict"],
        confidence=analysis["confidence"],
        cwe_id=report["cwe_id"],
        cwe_mismatch=report["cwe_mismatch"],
        priority=report["priority"],
        reasoning=analysis["reasoning"],
        iterations=analysis["iterations"],
        agent_role="reporter",
        schema_valid=True,
        tool_call_evaded=analysis["tool_call_evaded"]
    )

    log_verdict(finding, verdict)

    print("Pipeline completed successfully")


if __name__ == "__main__":
    run_pipeline()