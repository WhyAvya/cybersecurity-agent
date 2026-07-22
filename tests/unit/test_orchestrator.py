from pathlib import Path

from vuln_agent.config import Settings
from vuln_agent.llm import LLMResult
from vuln_agent.orchestrator import VulnerabilityOrchestrator
from vuln_agent.schemas import FileAnalysis, FileFinding, FindingStatus, ModelMetadata, SemgrepFinding, Severity, ToolMetadata, Verdict


def test_offline_scan_writes_reports(tmp_path: Path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "app.py").write_text(
        "import os\n\n\ndef run(name):\n    os.system('echo ' + name)\n",
        encoding="utf-8",
    )
    settings = Settings(
        report_dir=tmp_path / "reports",
        artifact_root=tmp_path / "artifacts",
        allowed_scan_root=tmp_path,
    )

    records, output_dir = VulnerabilityOrchestrator(settings).scan(app_dir, offline=True)

    assert len(records) == 1
    assert records[0].status == FindingStatus.accepted
    assert records[0].analyzer_verdict == Verdict.tp
    assert (output_dir / "manifest.json").exists()
    assert (output_dir / "scan_report.jsonl").exists()
    assert (output_dir / "scan_report.md").exists()


class FakeSemgrep:
    def __init__(self, findings):
        self.findings = findings
        self.calls = []

    def scan(self, path):
        self.calls.append(path)
        return self.findings, ToolMetadata(name="semgrep", config="test")


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def healthcheck(self):
        raise AssertionError("not used")

    def generate_structured(self, prompt, schema):
        self.calls.append((prompt, schema))
        parsed = schema.model_validate(self.response.model_dump())
        return LLMResult(parsed=parsed, raw_text=parsed.model_dump_json(), metadata=ModelMetadata(model="fake"), latency_ms=1)


def test_hybrid_full_file_runs_without_semgrep_findings(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm = FakeLLM(FileAnalysis(findings=[]))
    records, output_dir = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([]), llm=llm).scan(
        source, output_dir=tmp_path / "out", mode="hybrid", save_raw=True
    )
    assert records == []
    assert len(llm.calls) == 1
    assert (output_dir / "raw" / "llm" / "app-py-full-file.txt").exists()
    assert '"scan_mode": "hybrid"' in (output_dir / "manifest.json").read_text(encoding="utf-8")


def test_semgrep_gated_skips_llm_when_no_findings(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm = FakeLLM(FileAnalysis(findings=[]))
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([]), llm=llm).scan(source, mode="semgrep_gated")
    assert records == []
    assert llm.calls == []


def test_llm_mode_does_not_call_semgrep(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("danger()\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm = FakeLLM(FileAnalysis(findings=[FileFinding(line_start=1, line_end=1, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-089", reasoning_summary="sink")]))
    semgrep = FakeSemgrep([])
    records, _ = VulnerabilityOrchestrator(settings, semgrep=semgrep, llm=llm).scan(source, mode="llm")
    assert len(records) == 1
    assert semgrep.calls == []
    assert records[0].user_classification == "VULNERABLE"


def test_grouping_deduplicates_adjacent_rules(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system('x')\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    findings = [
        SemgrepFinding(finding_id=f"id-{i}", relative_file="app.py", line_start=2, line_end=2, rule_id=f"python.command.{i}", raw_semgrep_cwes=["CWE-704"], normalized_cwe="CWE-078", severity=Severity.high, snippet="os.system('x')")
        for i in range(3)
    ]
    records, output_dir = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep(findings)).scan(source, mode="semgrep")
    assert len(records) == 1
    assert records[0].duplicate_count == 2
    assert len(records[0].underlying_rule_ids) == 3
    assert (output_dir / "raw_findings.jsonl").exists()
