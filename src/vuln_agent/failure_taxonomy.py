"""Failure taxonomy labels for automated and manual review."""

from __future__ import annotations

from enum import Enum


class FailureCategory(str, Enum):
    tool_coverage_gap = "TOOL_COVERAGE_GAP"
    model_hallucination = "MODEL_HALLUCINATION"
    prompt_injection_suspected = "PROMPT_INJECTION_SUSPECTED"
    cwe_mismatch = "CWE_MISMATCH"
    sanitization_misunderstanding = "SANITIZATION_MISUNDERSTANDING"
    data_flow_misunderstanding = "DATA_FLOW_MISUNDERSTANDING"
    source_misidentification = "SOURCE_MISIDENTIFICATION"
    sink_misidentification = "SINK_MISIDENTIFICATION"
    schema_failure = "SCHEMA_FAILURE"
    model_failure = "MODEL_FAILURE"
    tool_failure = "TOOL_FAILURE"
    uncertainty_error = "UNCERTAINTY_ERROR"
    policy_error = "POLICY_ERROR"
    duplicate_finding = "DUPLICATE_FINDING"


def automated_failure_category(error: str | None, cwe_mismatch: bool = False, duplicate: bool = False) -> FailureCategory | None:
    if duplicate:
        return FailureCategory.duplicate_finding
    if cwe_mismatch:
        return FailureCategory.cwe_mismatch
    if not error:
        return None
    text = error.lower()
    if "schema" in text or "json" in text or "validation" in text:
        return FailureCategory.schema_failure
    if "ollama" in text or "model" in text or "llm" in text:
        return FailureCategory.model_failure
    if "semgrep" in text or "tool" in text:
        return FailureCategory.tool_failure
    return FailureCategory.uncertainty_error
