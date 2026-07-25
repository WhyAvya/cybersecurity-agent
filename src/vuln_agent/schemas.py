"""Canonical Pydantic schemas for scans, findings, and evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


SCHEMA_VERSION = "1.0"


class Severity(str, Enum):
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"
    info = "INFO"
    unknown = "UNKNOWN"


class Priority(str, Enum):
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"


class Verdict(str, Enum):
    tp = "TP"
    fp = "FP"
    uncertain = "UNCERTAIN"
    error = "ERROR"


class FindingStatus(str, Enum):
    accepted = "ACCEPTED"
    rejected = "REJECTED"
    needs_review = "NEEDS_REVIEW"
    error = "ERROR"


class CweSource(str, Enum):
    semgrep = "SEMGREP"
    analyzer = "ANALYZER"
    rule_inference = "RULE_INFERENCE"
    unknown = "UNKNOWN"


class SourceLocation(BaseModel):
    relative_file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    column_start: int | None = Field(default=None, ge=1)
    column_end: int | None = Field(default=None, ge=1)


class ToolMetadata(BaseModel):
    name: str
    version: str | None = None
    config: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)
    stderr_excerpt: str = ""


class ModelMetadata(BaseModel):
    provider: str = "ollama"
    model: str
    endpoint: str | None = None
    digest: str | None = None
    prompt_name: str | None = None
    prompt_version: str | None = None
    prompt_checksum: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)


class SemgrepFinding(BaseModel):
    finding_id: str
    relative_file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    column_start: int | None = Field(default=None, ge=1)
    column_end: int | None = Field(default=None, ge=1)
    rule_id: str
    raw_semgrep_cwes: list[str] = Field(default_factory=list)
    normalized_cwe: str = "NONE"
    severity: Severity = Severity.medium
    snippet: str = ""

    @property
    def file(self) -> str:
        return self.relative_file

    @property
    def line(self) -> int:
        return self.line_start

    @property
    def cwe_tag(self) -> str:
        return self.normalized_cwe


class SecurityEvidence(BaseModel):
    source: str = ""
    sink: str = ""
    data_flow: str = ""
    sanitization: str = ""
    context: str = ""


class AgentAnalysis(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    normalized_cwe: str = "NONE"
    reasoning_summary: str
    remediation: str = ""
    source_evidence: str = ""
    sink_evidence: str = ""
    data_flow_evidence: str = ""
    sanitization_evidence: str = ""
    needs_more_context: bool = False

    @field_validator(
        "reasoning_summary",
        "remediation",
        "source_evidence",
        "sink_evidence",
        "data_flow_evidence",
        "sanitization_evidence",
        mode="before",
    )
    @classmethod
    def _coerce_evidence_string(cls, value: Any) -> Any:
        return coerce_evidence_string(value)


class FileFinding(BaseModel):
    line_start: int
    line_end: int
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    normalized_cwe: str = "NONE"
    reasoning_summary: str
    remediation: str = ""
    source_evidence: str = ""
    sink_evidence: str = ""
    data_flow_evidence: str = ""
    sanitization_evidence: str = ""
    needs_more_context: bool = False

    @field_validator(
        "reasoning_summary",
        "remediation",
        "source_evidence",
        "sink_evidence",
        "data_flow_evidence",
        "sanitization_evidence",
        mode="before",
    )
    @classmethod
    def _empty_string_for_null_evidence(cls, value: Any) -> Any:
        return coerce_evidence_string(value)

    @field_validator("verdict", mode="before")
    @classmethod
    def _coerce_verdict_aliases(cls, value: Any) -> Any:
        return coerce_verdict_alias(value)


def coerce_verdict_alias(value: Any) -> Any:
    if isinstance(value, str):
        normalized = value.strip().upper()
        aliases = {
            "VULNERABLE": Verdict.tp.value,
            "UNSAFE": Verdict.tp.value,
            "SAFE": Verdict.fp.value,
            "NOT_VULNERABLE": Verdict.fp.value,
            "NON_VULNERABLE": Verdict.fp.value,
        }
        return aliases.get(normalized, value)
    return value


def coerce_evidence_string(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return value


class FileAnalysis(BaseModel):
    findings: list[FileFinding] = Field(default_factory=list)


class FinalFinding(BaseModel):
    run_id: str
    finding_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    relative_file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    location_is_approximate: bool = False
    location_note: str | None = None
    original_start_line: int | None = None
    original_end_line: int | None = None
    rule_id: str
    raw_semgrep_cwes: list[str] = Field(default_factory=list)
    normalized_cwe: str
    cwe_source: CweSource
    cwe_mismatch: bool
    severity: Severity
    priority: Priority
    status: FindingStatus
    analyzer_verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    source_evidence: str = ""
    sink_evidence: str = ""
    data_flow_evidence: str = ""
    sanitization_evidence: str = ""
    reasoning_summary: str = ""
    remediation: str = ""
    needs_human_review: bool = False
    review_reason: str = ""
    schema_version: str = SCHEMA_VERSION
    tool_metadata: ToolMetadata
    model_metadata: ModelMetadata
    duration_ms: int = Field(ge=0)
    user_classification: str = ""
    model_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    detector: str = ""
    detectors: list[str] = Field(default_factory=list)
    agreement_status: str = ""
    semgrep_cwe: str = "NONE"
    llm_cwe: str = "NONE"
    detector_errors: list[str] = Field(default_factory=list)
    group_id: str | None = None
    underlying_finding_ids: list[str] = Field(default_factory=list)
    underlying_rule_ids: list[str] = Field(default_factory=list)
    duplicate_count: int = 0
    detector_locations: list[dict[str, Any]] = Field(default_factory=list)


class ScanSummary(BaseModel):
    run_id: str
    target_path: str
    raw_findings: int
    accepted: int
    rejected: int
    needs_review: int
    errors: int = 0


class ScanRun(BaseModel):
    run_id: str
    started_at: datetime
    ended_at: datetime | None = None
    configuration: dict[str, Any]
    tool_metadata: list[ToolMetadata] = Field(default_factory=list)
    model_metadata: list[ModelMetadata] = Field(default_factory=list)
    summary: ScanSummary | None = None


class EvaluationPrediction(BaseModel):
    test_id: str
    expected_vulnerable: bool
    predicted_vulnerable: bool
    expected_cwe: str = "NONE"
    predicted_cwe: str = "NONE"
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    latency_ms: int | None = Field(default=None, ge=0)
    schema_valid: bool = True
    raw_response: str | None = None
    source_file: str | None = None
    semgrep_finding_count: int | None = None
    semgrep_rule_ids: list[str] = Field(default_factory=list)
    llm_called: bool = False
    decision_source: str = ""
    source_code_supplied: bool = False
    semgrep_gate_triggered: bool = False
    raw_response_path: str | None = None
    semgrep_raw_path: str | None = None
    analyzer_verdict: str | None = None
    status: str | None = None
    error: str | None = None


class EvaluationMetrics(BaseModel):
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positive_rate: float = 0.0
    specificity: float = 0.0
    accuracy: float = 0.0
    balanced_accuracy: float = 0.0
    completion_rate: float = 0.0
    error_rate: float = 0.0
    uncertain_rate: float = 0.0
    uncertain_count: int = 0
    review_required_count: int = 0
    attempted_count: int = 0
    completed_count: int = 0


class FailureRecord(BaseModel):
    test_id: str | None = None
    finding_id: str | None = None
    category: str
    automated: bool = True
    detail: str
