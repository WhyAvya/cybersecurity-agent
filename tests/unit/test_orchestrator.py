from pathlib import Path

from vuln_agent.config import Settings
import json

import pytest

from vuln_agent.exceptions import ToolError
from vuln_agent.llm import LLMResult, RawModel
from vuln_agent.orchestrator import VulnerabilityOrchestrator, validate_plan_b_file_finding
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


def test_hybrid_merges_semgrep_sink_and_llm_source_line_same_flow(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\n\ndef run():\n    cmd = input('Command: ')\n    os.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(
        line_start=3,
        line_end=3,
        verdict=Verdict.tp,
        confidence=0.92,
        normalized_cwe="CWE-078",
        source_evidence="cmd = input('Command: ')",
        data_flow_evidence="cmd flows to os.system(cmd)",
        reasoning_summary="input reaches os.system",
    )

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(line=4, snippet="os.system(cmd)")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")

    assert len(records) == 1
    assert records[0].detectors == ["llm", "semgrep"]
    assert records[0].line_start == 4
    assert len(records[0].underlying_finding_ids) == 2
    assert records[0].underlying_rule_ids == ["llm.full-file", "python.lang.security.audit.dangerous-system-call"]
    assert {location["detector"] for location in records[0].detector_locations} == {"llm", "semgrep"}
    assert {location["line_start"] for location in records[0].detector_locations} == {4}
    assert {location["original_start_line"] for location in records[0].detector_locations} == {None, 3}


def test_hybrid_differing_detector_statuses_merge_but_require_review(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\ncmd = input('Command: ')\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=3, line_end=3, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-078", sink_evidence="os.system(cmd)", reasoning_summary="command injection")

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(line=3, snippet="os.system(cmd)")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")

    assert len(records) == 1
    assert records[0].agreement_status == "detector_disagreement"
    assert records[0].status == FindingStatus.needs_review
    assert records[0].needs_human_review is True
    assert records[0].user_classification == "UNCERTAIN"


def test_hybrid_merges_live_report_os_system_prose_and_rule_slug(tmp_path: Path):
    source = tmp_path / "example.py"
    source.write_text("import os\nuser_input = input('Command: ')\nos.system(user_input)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(
        line_start=3,
        line_end=3,
        verdict=Verdict.tp,
        confidence=0.9,
        normalized_cwe="CWE-078",
        reasoning_summary=(
            "The code directly uses user input in an os.system call without any validation "
            "or sanitization, making it vulnerable to command injection."
        ),
    )
    semgrep = semgrep_finding(
        rule_id="semgrep-rules.python.vuln-agent.python.command-injection.input-to-os-system",
        line=4,
        snippet="",
        relative_file="example.py",
    )

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")

    assert len(records) == 1
    assert records[0].line_start == 4
    assert records[0].detectors == ["llm", "semgrep"]
    assert records[0].agreement_status == "detector_disagreement"
    assert records[0].status == FindingStatus.needs_review
    assert records[0].underlying_rule_ids == ["llm.full-file", "semgrep-rules.python.vuln-agent.python.command-injection.input-to-os-system"]
    assert {location["detector"] for location in records[0].detector_locations} == {"llm", "semgrep"}
    assert {location["line_start"] for location in records[0].detector_locations} == {3, 4}
    assert any("os.system call" in location["reasoning_summary"] for location in records[0].detector_locations)
    assert any(location["rule_id"].endswith("input-to-os-system") for location in records[0].detector_locations)


def test_hybrid_distant_same_sink_flows_remain_separate(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\ncmd = input('one')\nos.system(cmd)\n\n\n\nother = input('two')\nos.system(other)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=8, line_end=8, verdict=Verdict.tp, confidence=0.91, normalized_cwe="CWE-078", sink_evidence="os.system(other)", reasoning_summary="second command injection")

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(line=3, snippet="os.system(cmd)")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")

    assert len(records) == 2


def test_hybrid_nearby_distinct_os_system_calls_remain_separate_when_distinguishable(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nfirst = input('one')\nsecond = input('two')\nos.system(first)\nos.system(second)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=5, line_end=5, verdict=Verdict.tp, confidence=0.91, normalized_cwe="CWE-078", sink_evidence="os.system(second)", reasoning_summary="second command injection")

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(line=4, snippet="os.system(first)")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")

    assert len(records) == 2


def test_hybrid_nearby_same_cwe_incompatible_sinks_remain_separate(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\ncmd = input('one')\nos.system(cmd)\neval(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=4, line_end=4, verdict=Verdict.tp, confidence=0.91, normalized_cwe="CWE-078", sink_evidence="eval(cmd)", reasoning_summary="eval of user input")

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(line=3, snippet="os.system(cmd)")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")

    assert len(records) == 2


def test_hybrid_different_files_and_cwes_remain_separate(tmp_path: Path):
    app = tmp_path / "app.py"
    helper = tmp_path / "helper.py"
    app.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    helper.write_text("eval(user)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=1, line_end=1, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-094", sink_evidence="eval(user)", reasoning_summary="code injection")

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(relative_file="app.py")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(helper, mode="hybrid")

    assert len(records) == 2
    assert {record.relative_file for record in records} == {"app.py", "helper.py"}
    assert {record.normalized_cwe for record in records} == {"CWE-078", "CWE-094"}


def test_hybrid_exact_sink_location_wins_over_approximate_source_location(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\ncmd = input('Command: ')\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(
        line_start=2,
        line_end=2,
        verdict=Verdict.tp,
        confidence=0.99,
        normalized_cwe="CWE-078",
        data_flow_evidence="cmd flows to os.system(cmd)",
        reasoning_summary="source reaches dangerous sink",
    )

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(line=3, snippet="os.system(cmd)")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")

    assert len(records) == 1
    assert records[0].line_start == 3
    assert records[0].location_is_approximate is True
    assert records[0].location_note
    assert any(location["location_is_approximate"] for location in records[0].detector_locations)
    assert any(location["sink_evidence"] == "os.system(cmd)" for location in records[0].detector_locations)


def test_hybrid_group_ids_and_order_are_stable(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\ncmd = input('Command: ')\nos.system(cmd)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=3, line_end=3, verdict=Verdict.tp, confidence=0.9, normalized_cwe="CWE-078", sink_evidence="os.system(cmd)", reasoning_summary="command injection")

    first, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(line=3, snippet="os.system(cmd)")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")
    second, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([semgrep_finding(line=3, snippet="os.system(cmd)")]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="hybrid")

    assert [record.group_id for record in first] == [record.group_id for record in second]
    assert [record.underlying_finding_ids for record in first] == [record.underlying_finding_ids for record in second]


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
    assert records[0].agreement_status == "detector_disagreement"
    assert records[0].status == FindingStatus.needs_review
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


def test_llm_location_validation_moves_uncertain_allowlist_finding_to_evidence_line(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text(
        "\n".join(
            [
                "import subprocess",
                "",
                "allowed_commands = {",
                '    "status": ["git", "status"],',
                '    "version": ["python", "--version"],',
                "}",
                "",
                'choice = input("Choose command: ")',
                "",
                "if choice in allowed_commands:",
                "    subprocess.run(",
                "        allowed_commands[choice],",
                "        check=True,",
                "        shell=False,",
                "    )",
                "",
            ]
        ),
        encoding="utf-8",
    )
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(
        line_start=6,
        line_end=6,
        verdict=Verdict.uncertain,
        confidence=0.5,
        normalized_cwe="CWE-078",
        sink_evidence="subprocess.run(",
        reasoning_summary="subprocess call needs review",
    )

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="llm")

    assert records[0].line_start == 11
    assert records[0].line_end == 11
    assert records[0].location_is_approximate is False
    assert records[0].original_start_line == 6


def test_llm_unverified_location_is_marked_approximate(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=1, line_end=1, verdict=Verdict.uncertain, confidence=0.2, normalized_cwe="CWE-078", reasoning_summary="ambiguous sink")

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="llm")

    assert records[0].line_start == 1
    assert records[0].location_is_approximate is True
    assert records[0].location_note


def test_llm_out_of_range_location_is_bounded_and_approximate(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nos.system(user_input)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(line_start=99, line_end=0, verdict=Verdict.uncertain, confidence=0.4, normalized_cwe="CWE-078", reasoning_summary="bad location")

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="llm")

    assert records[0].line_start == 1
    assert records[0].line_end == 2
    assert records[0].location_is_approximate is True
    assert records[0].original_start_line == 99
    assert records[0].original_end_line == 0


def test_llm_vulnerable_os_system_regression_remains_strong_cwe_078(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("import os\nuser_input = input('Command: ')\nos.system(user_input)\n", encoding="utf-8")
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(
        line_start=3,
        line_end=3,
        verdict=Verdict.tp,
        confidence=1.0,
        normalized_cwe="CWE-078",
        sink_evidence="os.system(user_input)",
        data_flow_evidence="user_input reaches os.system",
        reasoning_summary="user input reaches shell command execution",
    )

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="llm")

    assert records[0].normalized_cwe == "CWE-078"
    assert records[0].user_classification == "VULNERABLE"
    assert records[0].confidence == 1.0
    assert records[0].line_start == 3
    assert records[0].location_is_approximate is False


def test_llm_plan_b_sqli_location_prefers_execute_sink(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text(
        "param = request.form.get('case')\nbar = param\nsql = f\"SELECT * FROM users WHERE password = '{bar}'\"\ncur.execute(sql)\n",
        encoding="utf-8",
    )
    settings = Settings(allowed_scan_root=tmp_path, report_dir=tmp_path / "reports")
    llm_finding = FileFinding(
        line_start=1,
        line_end=1,
        verdict=Verdict.tp,
        confidence=1.0,
        normalized_cwe="CWE-089",
        source_evidence="param = request.form.get('case')",
        sink_evidence="sql = f\"SELECT * FROM users WHERE password = '{bar}'\"",
        data_flow_evidence="param -> bar -> sql -> cur.execute",
        reasoning_summary="SQL injection reaches execute",
    )

    records, _ = VulnerabilityOrchestrator(settings, semgrep=FakeSemgrep([]), llm=FakeLLM(FileAnalysis(findings=[llm_finding]))).scan(source, mode="llm")

    assert records[0].line_start == 4
    assert records[0].normalized_cwe == "CWE-089"
    assert records[0].location_is_approximate is False


def test_plan_b_validation_rejects_command_finding_without_command_sink():
    item = FileFinding(
        line_start=4,
        line_end=4,
        verdict=Verdict.tp,
        confidence=1.0,
        normalized_cwe="CWE-078",
        source_evidence="param = request.args.get('case')",
        sink_evidence="f.write(param)",
        data_flow_evidence="param -> f.write",
        reasoning_summary="file write is command injection",
    )

    checked = validate_plan_b_file_finding(item, "f.write(param)")

    assert checked.verdict == Verdict.fp
    assert checked.normalized_cwe == "NONE"
    assert "no command execution sink" in checked.reasoning_summary


def test_plan_b_validation_rejects_parameterized_sqli_claim():
    code = "sql = 'SELECT username FROM users WHERE password = ?'\ncur.execute(sql, (bar,))"
    item = FileFinding(
        line_start=2,
        line_end=2,
        verdict=Verdict.tp,
        confidence=1.0,
        normalized_cwe="CWE-089",
        source_evidence="bar = request.args.get('case')",
        sink_evidence="cur.execute(sql, (bar,))",
        data_flow_evidence="bar -> sql query parameter",
        reasoning_summary="SQL injection",
    )

    checked = validate_plan_b_file_finding(item, code)

    assert checked.verdict == Verdict.fp
    assert checked.normalized_cwe == "NONE"
    assert "separate parameters" in checked.reasoning_summary


def test_plan_b_validation_rejects_simple_constant_overwrite_before_sink():
    code = (
        'param = request.form.get("case")\n'
        'choices = {"user": param, "safe": "status"}\n'
        'bar = choices["user"]\n'
        'bar = choices["safe"]\n'
        'subprocess.run(f"echo {bar}", shell=True)\n'
    )
    item = FileFinding(
        line_start=5,
        line_end=5,
        verdict=Verdict.tp,
        confidence=1.0,
        normalized_cwe="CWE-078",
        source_evidence="param = request.form.get('case')",
        sink_evidence="subprocess.run(f'echo {bar}', shell=True)",
        data_flow_evidence="param -> choices['user'] -> bar -> subprocess.run",
        reasoning_summary="command injection",
    )

    checked = validate_plan_b_file_finding(item, code)

    assert checked.verdict == Verdict.fp
    assert "constant before the command sink" in checked.reasoning_summary


def test_plan_b_validation_allows_later_tainted_assignment_after_constant():
    code = (
        'param = request.form.get("case")\n'
        'bar = "safe"\n'
        'bar = param\n'
        'subprocess.run(f"echo {bar}", shell=True)\n'
    )
    item = FileFinding(
        line_start=4,
        line_end=4,
        verdict=Verdict.tp,
        confidence=1.0,
        normalized_cwe="CWE-078",
        source_evidence="param = request.form.get('case')",
        sink_evidence="subprocess.run(f'echo {bar}', shell=True)",
        data_flow_evidence="param -> bar -> subprocess.run",
        reasoning_summary="command injection",
    )

    checked = validate_plan_b_file_finding(item, code)

    assert checked.verdict == Verdict.tp
    assert checked.normalized_cwe == "CWE-078"


def test_file_finding_accepts_common_model_verdict_alias_and_list_evidence():
    item = FileFinding.model_validate(
        {
            "line_start": 1,
            "line_end": 1,
            "verdict": "VULNERABLE",
            "confidence": 0.9,
            "normalized_cwe": "CWE-089",
            "reasoning_summary": "SQL injection",
            "data_flow_evidence": [{"line_start": 1, "line_end": 2}],
            "sanitization_evidence": [],
        }
    )

    assert item.verdict == Verdict.tp
    assert "line_start" in item.data_flow_evidence
    assert item.sanitization_evidence == ""


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
