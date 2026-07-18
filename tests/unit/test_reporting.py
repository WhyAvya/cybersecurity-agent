from pathlib import Path

from vuln_agent.reporting import calculate_priority, classify_status, write_jsonl, write_markdown
from vuln_agent.schemas import CweSource, FinalFinding, FindingStatus, ModelMetadata, Priority, Severity, ToolMetadata, Verdict


def test_status_policy_routes_low_confidence_tp_to_review():
    assert classify_status(Verdict.tp, 0.4, 0.6) == FindingStatus.needs_review
    assert classify_status(Verdict.tp, 0.7, 0.6) == FindingStatus.accepted
    assert classify_status(Verdict.fp, 0.9, 0.6) == FindingStatus.rejected


def test_priority_policy():
    assert calculate_priority(FindingStatus.accepted, Severity.high, 0.9, 0.85) == Priority.high
    assert calculate_priority(FindingStatus.rejected, Severity.high, 0.9, 0.85) == Priority.low


def test_report_writers_emit_jsonl_and_markdown(tmp_path: Path):
    finding = FinalFinding(
        run_id="run",
        finding_id="finding",
        relative_file="app.py",
        line_start=1,
        line_end=1,
        rule_id="rule",
        normalized_cwe="CWE-078",
        cwe_source=CweSource.semgrep,
        cwe_mismatch=False,
        severity=Severity.high,
        priority=Priority.high,
        status=FindingStatus.accepted,
        analyzer_verdict=Verdict.tp,
        confidence=0.9,
        reasoning_summary="Command reaches shell.",
        tool_metadata=ToolMetadata(name="semgrep"),
        model_metadata=ModelMetadata(model="test"),
        duration_ms=1,
    )

    jsonl_path = tmp_path / "scan.jsonl"
    markdown_path = tmp_path / "scan.md"
    write_jsonl([finding], jsonl_path)
    write_markdown([finding], markdown_path, "app")

    assert jsonl_path.read_text(encoding="utf-8").count("\n") == 1
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "Vulnerability Scan Report" in markdown
    assert "Command reaches shell." in markdown
