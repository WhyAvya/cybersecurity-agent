import json
import shutil
from pathlib import Path

from vuln_agent.agentic_v2.artifacts import AgenticArtifactManager
from vuln_agent.agentic_v2.models import ReasonerDecision
from vuln_agent.agentic_v2.orchestrator import (
    AgenticV2Orchestrator,
    extract_candidate_context,
    terminal_from_review,
    validate_reasoner_decision,
)
from vuln_agent.agentic_v2.models import ReviewerDecision, ReviewerVerdict, TerminalState, ValidatorDecision
from vuln_agent.schemas import ModelMetadata, SemgrepFinding, Severity, ToolMetadata


class RawResult:
    def __init__(self, raw_text: str) -> None:
        self.raw_text = raw_text
        self.parsed = None
        self.metadata = ModelMetadata(provider="fake", model="fake")
        self.latency_ms = 1


class FakeLLM:
    def __init__(self, responses: list[str]) -> None:
        self.responses = responses
        self.prompts: list[str] = []

    def healthcheck(self):
        raise AssertionError("healthcheck should not be called")

    def generate_raw(self, prompt: str):
        self.prompts.append(prompt)
        return RawResult(self.responses.pop(0))

    def generate_structured(self, prompt: str, schema):
        raise AssertionError("generate_raw should be used in tests")


class FakeSemgrep:
    def __init__(self, findings: list[SemgrepFinding]) -> None:
        self.findings = findings
        self.calls: list[Path] = []

    def scan(self, target_path):
        self.calls.append(Path(target_path))
        return self.findings, ToolMetadata(name="semgrep", version="fake")


def _finding(index: int, cwe: str = "CWE-078") -> SemgrepFinding:
    return SemgrepFinding(
        finding_id=f"finding-{index:02d}",
        relative_file="app.py",
        line_start=5 + index,
        line_end=5 + index,
        rule_id=f"rule-{index:02d}",
        normalized_cwe=cwe,
        severity=Severity.high,
        snippet="sink(user_input)",
    )


def _decision(candidate_id: str = "finding-00", cwe: str = "CWE-078") -> str:
    return json.dumps(
        {
            "candidate_id": candidate_id,
            "proposed_cwe": cwe,
            "source_supported": True,
            "propagation_supported": True,
            "sink_supported": True,
            "sanitization_summary": "",
            "confidence": 0.7,
            "missing_evidence": [],
            "rationale": "fixture",
        }
    )


def _review(candidate_id: str = "finding-00", decision: str = "accept", follow_up_action: str = "none") -> str:
    return json.dumps(
        {
            "candidate_id": candidate_id,
            "decision": decision,
            "follow_up_action": follow_up_action,
            "rationale": "review fixture",
        }
    )


def _repo(tmp_path: Path, source: str | None = None) -> Path:
    text = source or "import os\n\ndef handler():\n    user_input = input('x')\n    os.system(user_input)\n"
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    return tmp_path


def test_orchestrator_calls_existing_semgrep_and_inventory_drives_routing(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([_finding(0)])
    llm = FakeLLM([_decision(), _review()])

    result = AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078", "CWE-089"], auto_approve=True
    )

    assert semgrep.calls == [repo.resolve()]
    assert result.approved is True
    plan = json.loads((result.run_dir / "scan_plan.json").read_text(encoding="utf-8"))
    assert plan["active_cwes"] == ["CWE-078"]
    assert plan["skipped_cwes"] == {"CWE-089": "no SQL or database indicators found"}


def test_cli_approval_decision_is_recorded(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([])
    llm = FakeLLM([])

    result = AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078"], input_func=lambda _prompt: "n"
    )

    assert result.approved is False
    events = [json.loads(line) for line in (result.run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events[-1]["payload"] == {"approved": False, "auto_approve": False}
    assert semgrep.calls == []


def test_reasoner_receives_fresh_context_each_call(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([_finding(0), _finding(1)])
    llm = FakeLLM([_decision("finding-00"), _review("finding-00"), _decision("finding-01"), _review("finding-01")])

    AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078"], auto_approve=True
    )

    assert len(llm.prompts) == 4
    assert "finding-00" in llm.prompts[0]
    assert "finding-01" in llm.prompts[2]
    assert llm.prompts[0] != llm.prompts[2]


def test_reasoner_payload_excludes_benchmark_ground_truth_fields(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([_finding(0)])
    llm = FakeLLM([_decision(), _review()])

    AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078"], auto_approve=True
    )

    prompt = "\n".join(llm.prompts).lower()
    for prohibited in ("benchmarktest", "ground_truth", "expected_cwe", "expected_label", "benchmark target"):
        assert prohibited not in prompt


def test_malformed_json_gets_one_repair_attempt(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([_finding(0)])
    llm = FakeLLM(["not json", _decision(), _review()])

    result = AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078"], auto_approve=True
    )

    assert len(llm.prompts) == 3
    assert result.decisions[0].terminal_state is TerminalState.confirmed


def test_second_malformed_response_becomes_tool_error(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([_finding(0)])
    llm = FakeLLM(["not json", "still not json"])

    result = AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078"], auto_approve=True
    )

    assert result.decisions[0].terminal_state.value == "TOOL_ERROR"
    assert len(llm.prompts) == 2


def test_candidate_budget_is_enforced_and_event_written(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([_finding(i) for i in range(25)])
    responses = []
    for i in range(20):
        responses.extend([_decision(f"finding-{i:02d}"), _review(f"finding-{i:02d}")])
    llm = FakeLLM(responses)

    result = AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078"], auto_approve=True
    )

    assert len(result.candidates) == 20
    events = (result.run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "candidate-budget-truncated" in events


def test_context_extraction_uses_containing_function_and_imports(tmp_path: Path):
    repo = _repo(
        tmp_path,
        "import os\nimport sqlite3\n\n"
        "def first():\n    pass\n\n"
        "def handler():\n    user_input = input('x')\n    os.system(user_input)\n",
    )

    context = extract_candidate_context(repo.resolve(), "app.py", 9)

    assert context["imports"] == ["import os", "import sqlite3"]
    assert "def handler" in context["source"]
    assert "def first" not in context["source"]


def test_existing_validator_is_reused_for_safe_shell_rejection(tmp_path: Path):
    repo = _repo(
        tmp_path,
        "import subprocess\n\ndef handler():\n    subprocess.run(['git', 'status'], shell=False)\n",
    )
    candidate = _finding(0).model_dump()
    validator = validate_reasoner_decision(
        candidate=type("Candidate", (), {"candidate_id": "c1", "line_start": 4, "line_end": 4, "proposed_cwe": "CWE-078"})(),
        reasoner=ReasonerDecision(
            candidate_id="c1",
            proposed_cwe="CWE-078",
            source_supported=True,
            propagation_supported=True,
            sink_supported=True,
            confidence=0.9,
            rationale="source reaches subprocess",
        ),
        evidence={"source": (repo / "app.py").read_text(encoding="utf-8")},
    )
    assert validator.terminal_state is TerminalState.rejected
    assert "shell=False" in validator.reason or "command sink" in validator.reason


def test_reviewer_prompt_payload_differs_from_reasoner_and_has_no_hidden_history(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([_finding(0)])
    llm = FakeLLM([_decision(), _review()])
    AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078"], auto_approve=True
    )
    assert "security reasoner" in llm.prompts[0]
    assert "skeptical reviewer" in llm.prompts[1]
    assert "hidden" not in llm.prompts[1].lower()
    assert "ground_truth" not in llm.prompts[1].lower()


def test_two_pass_evidence_loop_and_no_third_pass(tmp_path: Path):
    repo = _repo(tmp_path)
    semgrep = FakeSemgrep([_finding(0)])
    llm = FakeLLM(
        [
            _decision(),
            _review(decision="needs_more_evidence", follow_up_action="assignment_history"),
            _decision(),
            _review(decision="human_review"),
        ]
    )
    result = AgenticV2Orchestrator(semgrep=semgrep, llm=llm, artifacts=AgenticArtifactManager(tmp_path / "runs")).run(
        repo, ["CWE-078"], auto_approve=True
    )
    assert len(llm.prompts) == 4
    assert "assignment_history" in llm.prompts[2]
    assert result.decisions[0].terminal_state is TerminalState.human_review_required


def test_llm_budget_stops_before_model_call(tmp_path: Path):
    repo = _repo(tmp_path)
    orchestrator = AgenticV2Orchestrator(
        semgrep=FakeSemgrep([_finding(0)]),
        llm=FakeLLM([]),
        artifacts=AgenticArtifactManager(tmp_path / "runs"),
    )
    orchestrator.max_llm_calls = 0
    result = orchestrator.run(repo, ["CWE-078"], auto_approve=True)
    assert result.decisions[0].terminal_state is TerminalState.tool_error


def test_terminal_mapping():
    candidate = type("Candidate", (), {"candidate_id": "c1"})()
    validator = ValidatorDecision(candidate_id="c1", terminal_state=TerminalState.confirmed)
    assert terminal_from_review(
        candidate, validator, ReviewerDecision(candidate_id="c1", decision=ReviewerVerdict.accept)
    ).terminal_state is TerminalState.confirmed
    assert terminal_from_review(
        candidate, validator, ReviewerDecision(candidate_id="c1", decision=ReviewerVerdict.reject)
    ).terminal_state is TerminalState.rejected


def _fixture_repo(name: str) -> Path:
    return Path(__file__).parents[1] / "fixtures" / "agentic_v2" / name


def test_phase5_fixture_expected_terminal_behaviors(tmp_path: Path):
    cases = [
        ("cwe078_vulnerable", "CWE-078", _finding(0, "CWE-078"), [_decision(), _review()], TerminalState.confirmed),
        ("cwe078_safe_overwrite", "CWE-078", _finding(0, "CWE-078"), [_decision(), _review()], TerminalState.rejected),
        (
            "cwe078_missing_helper",
            "CWE-078",
            _finding(0, "CWE-078"),
            [_decision(), _review(decision="needs_more_evidence", follow_up_action="more_context"), _decision(), _review(decision="human_review")],
            TerminalState.human_review_required,
        ),
        ("cwe089_vulnerable", "CWE-089", _finding(0, "CWE-089"), [_decision(cwe="CWE-089"), _review()], TerminalState.confirmed),
        ("cwe089_parameterized", "CWE-089", _finding(0, "CWE-089"), [_decision(cwe="CWE-089"), _review()], TerminalState.rejected),
    ]
    for name, cwe, finding, responses, expected in cases:
        finding.relative_file = "app.py"
        finding.line_start = 6
        finding.line_end = 6
        result = AgenticV2Orchestrator(
            semgrep=FakeSemgrep([finding]),
            llm=FakeLLM(responses),
            artifacts=AgenticArtifactManager(tmp_path / f"runs-{name}"),
        ).run(_fixture_repo(name), [cwe], auto_approve=True, auto_review_policy="keep")

        assert result.decisions[0].terminal_state is expected


def test_no_relevant_api_fixture_skips_during_routing(tmp_path: Path):
    result = AgenticV2Orchestrator(
        semgrep=FakeSemgrep([]),
        llm=FakeLLM([]),
        artifacts=AgenticArtifactManager(tmp_path / "runs"),
    ).run(_fixture_repo("no_relevant_apis"), ["CWE-078", "CWE-089"], auto_approve=True)

    plan = json.loads((result.run_dir / "scan_plan.json").read_text(encoding="utf-8"))
    assert plan["active_cwes"] == []
    assert plan["skipped_cwes"] == {
        "CWE-078": "no shell indicators found",
        "CWE-089": "no SQL or database indicators found",
    }


def test_human_review_auto_keep_is_recorded_in_events_and_report(tmp_path: Path):
    repo = _repo(tmp_path)
    llm = FakeLLM([_decision(), _review(decision="human_review")])

    result = AgenticV2Orchestrator(
        semgrep=FakeSemgrep([_finding(0)]),
        llm=llm,
        artifacts=AgenticArtifactManager(tmp_path / "runs"),
    ).run(repo, ["CWE-078"], auto_approve=True, auto_review_policy="keep")

    assert result.human_review_decisions == [
        {
            "candidate_id": "finding-00",
            "action": "keep",
            "terminal_state": "HUMAN_REVIEW_REQUIRED",
            "known_evidence": ["rule-00", "review fixture"],
            "missing_evidence": ["review fixture"],
        }
    ]
    report = json.loads((result.run_dir / "final_report.json").read_text(encoding="utf-8"))
    assert report["human_review_decisions"] == result.human_review_decisions
    events = (result.run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "human_review_decision" in events


def test_human_review_accept_reject_keep_and_stop_flow(tmp_path: Path):
    repo = _repo(tmp_path)
    findings = [_finding(0), _finding(1), _finding(2), _finding(3)]
    responses = []
    for index in range(4):
        responses.extend([_decision(f"finding-{index:02d}"), _review(f"finding-{index:02d}", decision="human_review")])
    review_inputs = iter(["a", "r", "u", "s"])
    result = AgenticV2Orchestrator(
        semgrep=FakeSemgrep(findings),
        llm=FakeLLM(responses),
        artifacts=AgenticArtifactManager(tmp_path / "runs"),
    ).run(repo, ["CWE-078"], auto_approve=True, auto_review_policy="manual", input_func=lambda _prompt: next(review_inputs))

    assert [item["action"] for item in result.human_review_decisions or []] == ["accept", "reject", "keep", "stop"]
    assert [decision.terminal_state for decision in result.decisions] == [
        TerminalState.confirmed,
        TerminalState.rejected,
        TerminalState.human_review_required,
        TerminalState.human_review_required,
    ]
    state = json.loads((result.run_dir / "state.json").read_text(encoding="utf-8"))
    assert state["human_review_stopped"] is True


def test_phase5_run_writes_required_six_artifacts_and_preserves_repository(tmp_path: Path):
    source_repo = _fixture_repo("cwe078_missing_helper")
    repo = tmp_path / "repo"
    shutil.copytree(source_repo, repo)
    before = {path.relative_to(repo): path.read_text(encoding="utf-8") for path in repo.rglob("*") if path.is_file()}
    llm = FakeLLM([_decision(), _review(decision="needs_more_evidence", follow_up_action="assignment_history"), _decision(), _review(decision="human_review")])

    result = AgenticV2Orchestrator(
        semgrep=FakeSemgrep([_finding(0)]),
        llm=llm,
        artifacts=AgenticArtifactManager(tmp_path / "runs"),
    ).run(repo, ["CWE-078", "CWE-089"], auto_approve=True, auto_review_policy="keep")

    assert sorted(path.name for path in result.run_dir.iterdir()) == [
        "events.jsonl",
        "final_report.json",
        "findings.json",
        "run_manifest.json",
        "scan_plan.json",
        "state.json",
    ]
    after = {path.relative_to(repo): path.read_text(encoding="utf-8") for path in repo.rglob("*") if path.is_file()}
    assert after == before
    assert len(llm.prompts) == 4
    assert "assignment_history" in llm.prompts[2]
    assert result.decisions[0].terminal_state is TerminalState.human_review_required


def test_step_budget_stops_before_model_call(tmp_path: Path):
    repo = _repo(tmp_path)
    orchestrator = AgenticV2Orchestrator(
        semgrep=FakeSemgrep([_finding(0)]),
        llm=FakeLLM([]),
        artifacts=AgenticArtifactManager(tmp_path / "runs"),
    )
    orchestrator.max_total_steps = 0
    result = orchestrator.run(repo, ["CWE-078"], auto_approve=True)
    assert result.decisions[0].terminal_state is TerminalState.tool_error
