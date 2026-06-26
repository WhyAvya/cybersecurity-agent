from pydantic import ValidationError

from schemas.verdict import SemgrepFinding, AgentVerdict

from agents.scanner_agent import run_scanner
from agents.analyzer_agent import run_analyzer
from agents.reporter_agent import run_reporter

from logger.jsonl_logger import log_verdict, log_failure

from tools.semgrep_tool import run_semgrep


def run_pipeline():

    raw_findings = run_semgrep(
        "data/BenchmarkPython/testcode",
        "auto"
    )

    print(
        f"Semgrep found {len(raw_findings)} findings"
    )

    findings = [
        SemgrepFinding(**f)
        for f in raw_findings[:1]
    ]

    print(
        f"Processing {len(findings)} findings"
    )

    for finding in findings:

        try:
            print("Running Scanner...")
            context = run_scanner(
                finding
            )
            
            print("Running Analyzer...")
            analysis = run_analyzer(
                finding,
                context
            )
            
            print("Running Reporter...")
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

            log_verdict(
                finding,
                verdict
            )

            print(
                f"Processed {finding.finding_id}"
            )

        except ValidationError as e:

            log_failure(
                finding.finding_id,
                str(e),
                "pipeline"
            )

            print(
                f"Schema error: {finding.finding_id}"
            )

        except Exception as e:

            log_failure(
                finding.finding_id,
                str(e),
                "pipeline"
            )

            print(
                f"Pipeline error: {finding.finding_id}"
            )


if __name__ == "__main__":
    run_pipeline()