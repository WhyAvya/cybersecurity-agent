import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vuln_agent.agentic_v2.artifacts import AgenticArtifactManager, REQUIRED_ARTIFACTS
from vuln_agent.agentic_v2.models import (
    AgentEvent,
    AgentState,
    CandidateFinding,
    FollowUpAction,
    ReasonerDecision,
    ReviewerDecision,
    ReviewerVerdict,
    ScanGoal,
    TerminalState,
    ValidatorDecision,
)
from vuln_agent.agentic_v2.prompts import REASONER_SYSTEM_PROMPT, REVIEWER_SYSTEM_PROMPT


def test_valid_models_are_json_serializable():
    goal = ScanGoal(target_path="repo", supported_cwes=["CWE-078"])
    candidate = CandidateFinding(
        candidate_id="candidate-1",
        relative_file="app.py",
        line_start=4,
        line_end=4,
        proposed_cwe="CWE-078",
    )
    decision = ReasonerDecision(candidate_id=candidate.candidate_id, proposed_cwe="CWE-078", confidence=0.7)
    payload = json.loads(goal.model_dump_json()) | json.loads(candidate.model_dump_json()) | json.loads(decision.model_dump_json())
    assert payload["target_path"] == "repo"
    assert payload["candidate_id"] == "candidate-1"


def test_invalid_terminal_state_is_rejected():
    with pytest.raises(ValidationError):
        ValidatorDecision(candidate_id="candidate-1", terminal_state="MAYBE")


def test_invalid_reviewer_decision_is_rejected():
    with pytest.raises(ValidationError):
        ReviewerDecision(candidate_id="candidate-1", decision="approve")


def test_invalid_follow_up_action_is_rejected():
    with pytest.raises(ValidationError):
        ReviewerDecision(candidate_id="candidate-1", decision=ReviewerVerdict.accept, follow_up_action="rerun_llm")


def test_negative_budget_and_counter_rejection():
    with pytest.raises(ValidationError):
        ScanGoal(target_path="repo", max_candidates=-1)
    with pytest.raises(ValidationError):
        AgentState(run_id="run-1", llm_calls_used=-1)


def test_safety_policy_defaults_are_read_only():
    policy = Path("config/agentic_v2.yaml").read_text(encoding="utf-8")
    assert "read_only: true" in policy
    assert "execute_target_code: false" in policy
    assert "modify_target_files: false" in policy
    assert "allow_cloud_models: false" in policy


def test_artifact_manager_creates_exact_required_artifacts(tmp_path: Path):
    manager = AgenticArtifactManager(tmp_path)
    run_dir = manager.create_run("run-001")
    assert sorted(path.name for path in run_dir.iterdir()) == sorted(REQUIRED_ARTIFACTS)


def test_artifact_manager_atomically_replaces_json(tmp_path: Path):
    manager = AgenticArtifactManager(tmp_path)
    manager.create_run("run-001")
    path = manager.write_json("run-001", "state.json", {"value": 1})
    manager.write_json("run-001", "state.json", {"value": 2})
    assert json.loads(path.read_text(encoding="utf-8")) == {"value": 2}
    assert not list(path.parent.glob("*.tmp"))


def test_artifact_manager_appends_jsonl_events(tmp_path: Path):
    manager = AgenticArtifactManager(tmp_path)
    manager.create_run("run-001")
    event = AgentEvent(event_id="event-1", event_type="created", message="ok")
    path = manager.append_event("run-001", event)
    manager.append_event("run-001", {"event_id": "event-2", "event_type": "updated"})
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [row["event_id"] for row in rows] == ["event-1", "event-2"]


@pytest.mark.parametrize("run_id", ["../escape", "nested/run", "", ".hidden"])
def test_artifact_manager_rejects_unsafe_run_ids(tmp_path: Path, run_id: str):
    with pytest.raises(ValueError):
        AgenticArtifactManager(tmp_path).create_run(run_id)


def test_reasoner_and_reviewer_prompts_are_distinct_and_clean():
    assert REASONER_SYSTEM_PROMPT != REVIEWER_SYSTEM_PROMPT
    joined = f"{REASONER_SYSTEM_PROMPT}\n{REVIEWER_SYSTEM_PROMPT}".lower()
    prohibited = ["benchmarktest", "realvuln", "expected label", "expected answer", "ground truth"]
    assert not any(term in joined for term in prohibited)


def test_detector_facing_models_do_not_expose_expected_or_ground_truth_fields():
    models = [ScanGoal, CandidateFinding, ReasonerDecision, ValidatorDecision, ReviewerDecision]
    prohibited = {"expected_cwe", "expected_label", "ground_truth", "benchmark_answer", "expected_answer"}
    for model in models:
        assert prohibited.isdisjoint(set(model.model_fields))


def test_reviewer_defaults_to_no_follow_up():
    decision = ReviewerDecision(candidate_id="candidate-1", decision=ReviewerVerdict.reject)
    assert decision.follow_up_action is FollowUpAction.none


def test_terminal_states_are_exact_values():
    assert {state.value for state in TerminalState} == {
        "CONFIRMED",
        "REJECTED",
        "HUMAN_REVIEW_REQUIRED",
        "TOOL_ERROR",
        "OUT_OF_SCOPE",
    }
