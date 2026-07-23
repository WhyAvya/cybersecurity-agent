"""Report writing and policy decisions."""

from __future__ import annotations

import json
from pathlib import Path

from .schemas import FinalFinding, FindingStatus, Priority, Severity, Verdict


def classify_status(verdict: Verdict, confidence: float, accept_threshold: float) -> FindingStatus:
    if verdict == Verdict.tp and confidence >= accept_threshold:
        return FindingStatus.accepted
    if verdict == Verdict.fp:
        return FindingStatus.rejected
    if verdict == Verdict.error:
        return FindingStatus.error
    return FindingStatus.needs_review


def calculate_priority(status: FindingStatus, severity: Severity, confidence: float, high_threshold: float) -> Priority:
    if status == FindingStatus.error:
        return Priority.low
    if status == FindingStatus.needs_review:
        return Priority.medium
    if status == FindingStatus.rejected:
        return Priority.low
    if severity in (Severity.critical, Severity.high) and confidence >= high_threshold:
        return Priority.high
    if confidence >= 0.60:
        return Priority.medium
    return Priority.low


def write_jsonl(records: list[FinalFinding], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(record.model_dump_json() + "\n")


def write_markdown(records: list[FinalFinding], output_path: Path, target_path: str, mode: str = "hybrid", underlying_count: int | None = None) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    accepted = sum(1 for item in records if item.status == FindingStatus.accepted)
    rejected = sum(1 for item in records if item.status == FindingStatus.rejected)
    review = sum(1 for item in records if item.status == FindingStatus.needs_review)
    lines = [
        "# Vulnerability Scan Report",
        "",
        f"Target path: `{target_path}`",
        f"Scan mode: `{mode}`",
        "",
        "## Summary",
        "",
        f"- Grouped findings: {len(records)}",
        f"- Underlying matches: {underlying_count if underlying_count is not None else len(records)}",
        f"- Accepted: {accepted}",
        f"- Rejected: {rejected}",
        f"- Needs review: {review}",
        "",
        "## Findings",
        "",
    ]
    for index, record in enumerate(records, 1):
        lines.extend(
            [
                f"### {index}. {record.user_classification or record.status.value}",
                "",
                f"- File: `{record.relative_file}`",
                f"- Line: {record.line_start}{' (approximate)' if record.location_is_approximate else ''}",
                *([f"- Location note: {record.location_note}"] if record.location_note else []),
                f"- Rule: `{record.rule_id}`",
                f"- CWE: `{record.normalized_cwe}`",
                f"- Detectors: `{', '.join(record.detectors) or record.detector}`",
                f"- Agreement: `{record.agreement_status or 'n/a'}`",
                f"- User classification: `{record.user_classification or record.status.value}`",
                f"- Internal verdict: `{record.analyzer_verdict.value}`",
                f"- Model confidence: {record.confidence:.2f}",
                f"- Priority: `{record.priority.value}`",
                f"- Group ID: `{record.group_id or record.finding_id}`",
                f"- Underlying rule IDs: `{', '.join(record.underlying_rule_ids)}`",
                "",
                record.reasoning_summary or "No reasoning summary provided.",
                "",
            ]
        )
    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_manifest(data: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    temporary.replace(output_path)
