from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class TerminalState(str, Enum):
    confirmed = "CONFIRMED"
    rejected = "REJECTED"
    human_review_required = "HUMAN_REVIEW_REQUIRED"
    tool_error = "TOOL_ERROR"
    out_of_scope = "OUT_OF_SCOPE"


class ReviewerVerdict(str, Enum):
    accept = "accept"
    reject = "reject"
    needs_more_evidence = "needs_more_evidence"
    human_review = "human_review"


class FollowUpAction(str, Enum):
    more_context = "more_context"
    assignment_history = "assignment_history"
    none = "none"


class ScanGoal(BaseModel):
    target_path: str
    supported_cwes: list[str] = Field(default_factory=lambda: ["CWE-078", "CWE-089"])
    max_candidates: int = Field(default=20, ge=0)
    max_total_steps: int = Field(default=100, ge=0)


class RepositoryInventory(BaseModel):
    root_path: str
    files_considered: int = Field(default=0, ge=0)
    python_files: list[str] = Field(default_factory=list)
    skipped_files: list[str] = Field(default_factory=list)


class PlanStep(BaseModel):
    step_id: str
    role: str
    action: str
    target: str = ""
    status: str = "pending"


class ScanPlan(BaseModel):
    goal: ScanGoal
    steps: list[PlanStep] = Field(default_factory=list)
    max_passes_per_candidate: int = Field(default=2, ge=0)
    max_reviewer_cycles: int = Field(default=1, ge=0)
    max_llm_calls: int = Field(default=50, ge=0)


class CandidateFinding(BaseModel):
    candidate_id: str
    relative_file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    proposed_cwe: str
    summary: str = ""
    detector_input_ref: str | None = None

    @field_validator("line_end")
    @classmethod
    def _line_end_after_start(cls, value: int, info: Any) -> int:
        start = info.data.get("line_start")
        if start is not None and value < start:
            raise ValueError("line_end must be >= line_start")
        return value


class EvidenceRecord(BaseModel):
    evidence_id: str
    candidate_id: str
    source: str = ""
    propagation: str = ""
    sink: str = ""
    sanitization: str = ""
    missing_evidence: list[str] = Field(default_factory=list)


class ReasonerDecision(BaseModel):
    candidate_id: str
    proposed_cwe: str
    source_supported: bool = False
    propagation_supported: bool = False
    sink_supported: bool = False
    sanitization_summary: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    missing_evidence: list[str] = Field(default_factory=list)
    rationale: str = ""


class ValidatorDecision(BaseModel):
    candidate_id: str
    terminal_state: TerminalState
    reason: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ReviewerDecision(BaseModel):
    candidate_id: str
    decision: ReviewerVerdict
    follow_up_action: FollowUpAction = FollowUpAction.none
    rationale: str = ""


class AgentEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    message: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


class AgentState(BaseModel):
    run_id: str
    terminal_state: TerminalState | None = None
    candidates_seen: int = Field(default=0, ge=0)
    llm_calls_used: int = Field(default=0, ge=0)
    reviewer_cycles_used: int = Field(default=0, ge=0)
    events_written: int = Field(default=0, ge=0)


class FinalFinding(BaseModel):
    finding_id: str
    candidate_id: str
    terminal_state: TerminalState
    relative_file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    proposed_cwe: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = ""
