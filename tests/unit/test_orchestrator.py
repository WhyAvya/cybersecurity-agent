from pathlib import Path

from vuln_agent.config import Settings
import json

import pytest

from vuln_agent.exceptions import ToolError
from vuln_agent.llm import LLMResult, RawModel
from vuln_agent.orchestrator import VulnerabilityOrchestrator
from vuln_agent.schemas import AgentAnalysis, FileAnalysis, FileFinding, FindingStatus, ModelMetadata, SemgrepFinding, Severity, ToolMetadata, Verdict


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


class FailingSemgrep:
    def scan(self, path):
        raise ToolError("semgrep exploded")


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def healthcheck(self):
        raise AssertionError("not used")

    def generate_structured(self, prompt, schema):
        self.calls.append((prompt, schema))
        if schema is AgentAnalysis and isinstance(self.response, FileAnalysis):
            item = self.response.findings[0] if self.response.findings else FileFinding(line_start=1, line_end=1, verdict=Verdict.uncertain, confidence=0.0, reasoning_summary="no finding")
            parsed = AgentAnalysis.model_validate(item.model_dump())
            return LLMResult(parsed=parsed, raw_text=parsed.model_dump_json(), metadata=ModelMetadata(model="fake"), latency_ms=1)
        parsed = schema.model_validate(self.response.model_dump())
        return LLMResult(parsed=parsed, raw_text=parsed.model_dump_json(), metadata=ModelMetadata(model="fake"), latency_ms=1)


class RawLLM:
    def __init__(self, raw_text):
        self.raw_text = raw_text
        self.calls = []

    def generate_raw(self, prompt):
        self.calls.append(prompt)
        return LLMResult(parsed=RawModel(), raw_text=self.raw_text, metadata=ModelMetadata(model="fake"), latency_ms=1)


def semgrep_finding(rule_id="python.lang.security.audit.dangerous-system-call", line=2, snippet="os.system(cmd)", cwe="CWE-078", relative_file="app.py"):
    return SemgrepFinding(
        finding_id=f"sg-{rule_id}-{line}",
        relative_file=relative_file,
        line_start=line,
        line_end=line,
        rule_id=rule_id,
        raw_semgrep_cwes=[cwe],
        normalized_cwe=cwe,
        severity=Severity.high,
        snippet=snippet,
    )


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


def test_true_hybrid_semgrep_finding_survives_empty_llm_response(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    records, output_dir = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding()]), llm=FakeLLM(FileAnalysis(findings=[]))).scan(
        source, output_dir=tmp_path / "out", mode="hybrid", save_raw=True
    )
    assert len(records) == 1
    assert records[0].agreement_status == "semgrep_only"
    assert records[0].user_classification == "LIKELY_VULNERABLE"
    raw = [json.loads(line) for line in (output_dir / "raw_findings.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [item["detector"] for item in raw] == ["semgrep"]


def test_true_hybrid_llm_finding_survives_zero_semgrep_results(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("danger()\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=1, line_end=1, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-089", sink_evidence="danger()", reasoning_summary="sink")
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")
    assert len(records) == 1
    assert records[0].agreement_status == "llm_only"
    assert records[0].detectors == ["llm"]


def test_true_hybrid_matching_semgrep_and_llm_findings_merge(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=2, line_end=2, verdict=Verdict.tp, confidence=0.95, normalized_cwe="CWE-078", sink_evidence="os.system(cmd)", reasoning_summary="command injection")
    records, output_dir = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding()]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(
        source, output_dir=tmp_path / "out", mode="hybrid", save_raw=True
    )
    assert len(records) == 1
    assert records[0].agreement_status == "detectors_agree"
    assert records[0].detectors == ["llm", "semgrep"]
    raw = [json.loads(line) for line in (output_dir / "raw_findings.jsonl").read_text(encoding="utf-8").splitlines()]
    assert sorted(item["detector"] for item in raw) == ["llm", "semgrep"]


def test_true_hybrid_different_findings_remain_separate(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system(cmd)\neval(user)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=3, line_end=3, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-094", sink_evidence="eval(user)", reasoning_summary="eval")
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding()]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")
    assert len(records) == 2


def test_true_hybrid_semgrep_survives_llm_schema_failure(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    records, output_dir = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding()]), llm=RawLLM("{bad json")).scan(
        source, output_dir=tmp_path / "out", mode="hybrid", save_raw=True
    )
    assert any(record.detectors == ["semgrep"] for record in records)
    assert any(record.status == FindingStatus.error for record in records)
    assert (output_dir / "raw" / "llm" / "app-py-full-file.txt").read_text(encoding="utf-8") == "{bad json"


def test_true_hybrid_llm_survives_semgrep_failure(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("danger()\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=1, line_end=1, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-089", sink_evidence="danger()", reasoning_summary="sink")
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FailingSemgrep(), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")
    assert any(record.detectors == ["llm"] for record in records)
    assert any(record.status == FindingStatus.error for record in records)


def test_true_hybrid_error_and_accepted_findings_remain_separate(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("danger()\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=1, line_end=1, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-089", sink_evidence="danger()", reasoning_summary="sink")
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FailingSemgrep(), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")
    assert len(records) == 2
    assert {record.status for record in records} == {FindingStatus.accepted, FindingStatus.error}


def test_true_hybrid_same_cwe_different_sinks_remain_separate(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system(cmd)\nsubprocess.call(user)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    findings = [
        semgrep_finding(line=2, snippet="os.system(cmd)"),
        semgrep_finding(rule_id="python.subprocess.shell", line=3, snippet="subprocess.call(user)"),
    ]
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep(findings), llm=FakeLLM(FileAnalysis(findings=[]))).scan(source, mode="hybrid")
    assert len(records) == 2


@pytest.mark.parametrize("mode", ["semgrep", "llm", "semgrep_gated", "hybrid"])
def test_scan_paths_are_portable_in_all_modes(tmp_path: Path, mode: str):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=2, line_end=2, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-078", sink_evidence="os.system(cmd)", reasoning_summary="sink")
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding()]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode=mode)
    assert all(record.relative_file == "app.py" for record in records)


def test_semgrep_absolute_container_path_becomes_repository_relative(tmp_path: Path):
    source = tmp_path / "examples" / "vulnerable_app" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    finding = semgrep_finding(relative_file="/work/examples/vulnerable_app/app.py")
    records, output_dir = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([finding]), llm=FakeLLM(FileAnalysis(findings=[]))).scan(
        source, output_dir=tmp_path / "out", mode="hybrid", save_raw=True
    )
    assert records[0].relative_file == "examples/vulnerable_app/app.py"
    raw = [json.loads(line) for line in (output_dir / "raw_findings.jsonl").read_text(encoding="utf-8").splitlines()]
    assert raw[0]["relative_file"] == "examples/vulnerable_app/app.py"
    assert "/work" not in (output_dir / "scan_report.md").read_text(encoding="utf-8")


def test_semgrep_absolute_windows_path_becomes_repository_relative(tmp_path: Path):
    source = tmp_path / "examples" / "vulnerable_app" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    finding = semgrep_finding(relative_file=str(source))
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([finding]), llm=FakeLLM(FileAnalysis(findings=[]))).scan(source, mode="hybrid")
    assert records[0].relative_file == "examples/vulnerable_app/app.py"
    assert ":" not in records[0].relative_file


def test_semgrep_already_relative_path_stays_stable(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    finding = semgrep_finding(relative_file="src/app.py")
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([finding]), llm=FakeLLM(FileAnalysis(findings=[]))).scan(source, mode="hybrid")
    assert records[0].relative_file == "src/app.py"


@pytest.mark.parametrize("mode", ["semgrep", "semgrep_gated", "hybrid"])
def test_semgrep_paths_are_portable_in_semgrep_modes(tmp_path: Path, mode: str):
    source = tmp_path / "examples" / "vulnerable_app" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    finding = semgrep_finding(relative_file=str(source))
    llm_finding = FileFinding(line_start=2, line_end=2, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-078", sink_evidence="os.system(cmd)", reasoning_summary="sink")
    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([finding]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode=mode)
    assert all(record.relative_file == "examples/vulnerable_app/app.py" for record in records)
    assert all(not record.relative_file.startswith(("/", "\\\\", "C:")) for record in records)


def test_semgrep_finding_ids_are_stable_across_absolute_roots(tmp_path: Path):
    source = tmp_path / "examples" / "vulnerable_app" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    windows_finding = semgrep_finding(relative_file=str(source))
    docker_finding = semgrep_finding(relative_file="/work/examples/vulnerable_app/app.py")
    first, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([windows_finding]), llm=FakeLLM(FileAnalysis(findings=[]))).scan(source, mode="hybrid")
    second, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([docker_finding]), llm=FakeLLM(FileAnalysis(findings=[]))).scan(source, mode="hybrid")
    assert first[0].underlying_finding_ids == second[0].underlying_finding_ids
    assert first[0].group_id == second[0].group_id


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
