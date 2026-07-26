from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from vuln_agent.config import Settings
from vuln_agent.exceptions import SchemaParseError, ToolError
from vuln_agent.llm import LLMClient, OllamaClient
from vuln_agent.orchestrator import validate_plan_b_file_finding
from vuln_agent.schemas import FileFinding, Verdict
from vuln_agent.semgrep import SemgrepAdapter
from vuln_agent.utils import parse_model_json

from .artifacts import AgenticArtifactManager
from .inventory import RouteDecision, inspect_repository
from .models import (
    AgentEvent,
    CandidateFinding,
    FollowUpAction,
    ReasonerDecision,
    ReviewerDecision,
    ReviewerVerdict,
    TerminalState,
    ValidatorDecision,
)
from .prompts import REASONER_SYSTEM_PROMPT, REVIEWER_SYSTEM_PROMPT


@dataclass(frozen=True)
class AgenticRunResult:
    run_id: str
    run_dir: Path
    approved: bool
    candidates: list[CandidateFinding]
    decisions: list[ReasonerDecision | ValidatorDecision]
    human_review_decisions: list[dict[str, Any]] | None = None


class AgenticV2Orchestrator:
    def __init__(
        self,
        settings: Settings | None = None,
        semgrep: SemgrepAdapter | None = None,
        llm: LLMClient | None = None,
        artifacts: AgenticArtifactManager | None = None,
    ) -> None:
        self.settings = settings or Settings()
        agentic_semgrep_settings = self.settings.model_copy(update={"semgrep_no_git_ignore": True})
        self.semgrep = semgrep or SemgrepAdapter(agentic_semgrep_settings, use_target_as_project_root=True)
        self.llm = llm or OllamaClient(self.settings)
        self.artifacts = artifacts or AgenticArtifactManager(self.settings.artifact_root / "agentic-runs")
        self.max_candidates = 20
        self.max_passes_per_candidate = 2
        self.max_reviewer_cycles = 1
        self.max_llm_calls = 50
        self.max_total_steps = 100

    def run(
        self,
        repository: str | Path,
        cwes: list[str],
        *,
        auto_approve: bool = False,
        auto_review_policy: str = "keep",
        input_func=input,
    ) -> AgenticRunResult:
        root = _safe_repository_root(repository)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-agentic-v2")
        run_dir = self.artifacts.create_run(run_id)
        self.artifacts.write_json(
            run_id,
            "run_manifest.json",
            {
                "run_id": run_id,
                "repository": str(root),
                "requested_cwes": cwes,
                "auto_review_policy": auto_review_policy,
                "started_at_utc": datetime.now(timezone.utc).isoformat(),
            },
        )

        route = inspect_repository(root)
        active_cwes = [cwe for cwe in route.active_cwes if cwe in cwes]
        route_payload = _route_payload(route, active_cwes)
        self.artifacts.write_json(run_id, "scan_plan.json", route_payload)
        self.artifacts.append_event(run_id, AgentEvent(event_id="inventory-complete", event_type="inventory", payload=route_payload))

        approved = auto_approve or _prompt_for_approval(route_payload, input_func)
        self.artifacts.append_event(
            run_id,
            AgentEvent(
                event_id="approval-decision",
                event_type="human_checkpoint",
                payload={"approved": approved, "auto_approve": auto_approve},
            ),
        )
        if not approved:
            self.artifacts.write_json(run_id, "state.json", {"approved": False, "terminal_state": "HUMAN_REVIEW_REQUIRED"})
            return AgenticRunResult(run_id, run_dir, False, [], [])

        findings, metadata = self.semgrep.scan(root)
        semgrep_event = {"finding_count": len(findings), "metadata": metadata.model_dump(mode="json")}
        self.artifacts.append_event(run_id, AgentEvent(event_id="semgrep-complete", event_type="semgrep", payload=semgrep_event))

        candidates = _normalize_candidates(findings, active_cwes, self.max_candidates)
        if len([f for f in findings if f.normalized_cwe in active_cwes]) > len(candidates):
            self.artifacts.append_event(
                run_id,
                AgentEvent(
                    event_id="candidate-budget-truncated",
                    event_type="budget",
                    payload={"max_candidates": self.max_candidates},
                ),
            )

        decisions: list[ReasonerDecision | ValidatorDecision] = []
        llm_calls_used = 0
        steps_used = 0
        for candidate in candidates:
            terminal, used_calls, used_steps = self._investigate_candidate(run_id, root, candidate, active_cwes, llm_calls_used, steps_used)
            llm_calls_used += used_calls
            steps_used += used_steps
            decisions.append(terminal)

        human_review_decisions = self._human_review_checkpoint(
            run_id,
            candidates,
            decisions,
            auto_review_policy=auto_review_policy,
            input_func=input_func,
        )
        self.artifacts.write_json(run_id, "findings.json", {"candidates": [c.model_dump(mode="json") for c in candidates]})
        self.artifacts.write_json(
            run_id,
            "state.json",
            {
                "approved": True,
                "candidate_count": len(candidates),
                "llm_calls_used": llm_calls_used,
                "steps_used": steps_used,
                "human_review_decision_count": len(human_review_decisions),
                "human_review_stopped": any(decision["action"] == "stop" for decision in human_review_decisions),
            },
        )
        self.artifacts.write_json(
            run_id,
            "final_report.json",
            {
                "decisions": [_model_dump(decision) for decision in decisions],
                "human_review_decisions": human_review_decisions,
            },
        )
        return AgenticRunResult(run_id, run_dir, True, candidates, decisions, human_review_decisions)

    def _human_review_checkpoint(
        self,
        run_id: str,
        candidates: list[CandidateFinding],
        decisions: list[ReasonerDecision | ValidatorDecision],
        *,
        auto_review_policy: str,
        input_func,
    ) -> list[dict[str, Any]]:
        decisions_by_id = {decision.candidate_id: decision for decision in decisions}
        review_decisions: list[dict[str, Any]] = []
        for candidate in candidates:
            decision = decisions_by_id.get(candidate.candidate_id)
            if not isinstance(decision, ValidatorDecision):
                continue
            if decision.terminal_state is not TerminalState.human_review_required:
                continue
            action = "keep" if auto_review_policy == "keep" else _prompt_for_human_review(candidate, decision, input_func)
            final_state = {
                "accept": TerminalState.confirmed,
                "reject": TerminalState.rejected,
                "keep": TerminalState.human_review_required,
                "stop": TerminalState.human_review_required,
            }[action]
            if action in {"accept", "reject"}:
                decision.terminal_state = final_state
                decision.reason = f"human checkpoint 2 {action}: {decision.reason}"
            record = {
                "candidate_id": candidate.candidate_id,
                "action": action,
                "terminal_state": final_state.value,
                "known_evidence": _known_evidence(candidate, decision),
                "missing_evidence": _missing_evidence(decision),
            }
            review_decisions.append(record)
            self.artifacts.append_event(
                run_id,
                AgentEvent(
                    event_id=f"human-review-{candidate.candidate_id}-{len(review_decisions)}",
                    event_type="human_review_decision",
                    payload=record,
                ),
            )
            if action == "stop":
                break
        return review_decisions

    def _investigate_candidate(
        self,
        run_id: str,
        root: Path,
        candidate: CandidateFinding,
        active_cwes: list[str],
        prior_llm_calls: int,
        prior_steps: int,
    ) -> tuple[ValidatorDecision, int, int]:
        llm_calls = 0
        steps = 0
        follow_up = FollowUpAction.none
        validator = ValidatorDecision(candidate_id=candidate.candidate_id, terminal_state=TerminalState.tool_error)
        reviewer = ReviewerDecision(candidate_id=candidate.candidate_id, decision=ReviewerVerdict.human_review)
        for pass_number in range(1, self.max_passes_per_candidate + 1):
            if prior_steps + steps >= self.max_total_steps or prior_llm_calls + llm_calls >= self.max_llm_calls:
                validator = ValidatorDecision(
                    candidate_id=candidate.candidate_id,
                    terminal_state=TerminalState.tool_error,
                    reason="Agentic v2 budget exhausted.",
                )
                return validator, llm_calls, steps
            evidence = collect_evidence(root, candidate, follow_up)
            reasoner_payload = _reasoner_payload(candidate, evidence, active_cwes, pass_number)
            self.artifacts.append_event(
                run_id,
                AgentEvent(
                    event_id=f"reasoner-start-{candidate.candidate_id}-pass-{pass_number}",
                    event_type="reasoner_start",
                    payload=reasoner_payload,
                ),
            )
            reasoner = self._reason(candidate, reasoner_payload)
            llm_calls += 1 if isinstance(reasoner, ReasonerDecision) else 2
            steps += 1
            if isinstance(reasoner, ValidatorDecision):
                return reasoner, llm_calls, steps
            validator = validate_reasoner_decision(candidate, reasoner, evidence)
            self.artifacts.append_event(
                run_id,
                AgentEvent(
                    event_id=f"validator-{candidate.candidate_id}-pass-{pass_number}",
                    event_type="validator",
                    payload=validator.model_dump(mode="json"),
                ),
            )
            reviewer_payload = _reviewer_payload(candidate, reasoner, validator, evidence, pass_number)
            self.artifacts.append_event(
                run_id,
                AgentEvent(
                    event_id=f"reviewer-start-{candidate.candidate_id}-pass-{pass_number}",
                    event_type="reviewer_start",
                    payload=reviewer_payload,
                ),
            )
            reviewer = self._review(candidate, reviewer_payload)
            llm_calls += 1 if isinstance(reviewer, ReviewerDecision) else 2
            steps += 1
            if isinstance(reviewer, ValidatorDecision):
                return reviewer, llm_calls, steps
            terminal = terminal_from_review(candidate, validator, reviewer)
            self.artifacts.append_event(
                run_id,
                AgentEvent(
                    event_id=f"terminal-{candidate.candidate_id}-pass-{pass_number}",
                    event_type="terminal_decision",
                    payload=terminal.model_dump(mode="json"),
                ),
            )
            if terminal.terminal_state != TerminalState.human_review_required:
                return terminal, llm_calls, steps
            if pass_number == self.max_passes_per_candidate or reviewer.follow_up_action is FollowUpAction.none:
                return terminal, llm_calls, steps
            follow_up = reviewer.follow_up_action
            self.artifacts.append_event(
                run_id,
                AgentEvent(
                    event_id=f"evidence-request-{candidate.candidate_id}-pass-{pass_number}",
                    event_type="evidence_request",
                    payload={"follow_up_action": follow_up.value, "next_pass": pass_number + 1},
                ),
            )
        return terminal_from_review(candidate, validator, reviewer), llm_calls, steps

    def _reason(self, candidate: CandidateFinding, payload: dict[str, Any]) -> ReasonerDecision | ValidatorDecision:
        prompt = _build_reasoner_prompt(payload)
        reasoner, raw_response, validation_error = _try_generate_reasoner(self.llm, prompt)
        if reasoner is not None:
            return reasoner
        repair_prompt = _build_reasoner_repair_prompt(candidate, raw_response, validation_error)
        repaired, _repair_raw, _repair_error = _try_generate_reasoner(self.llm, repair_prompt)
        if repaired is not None:
            return repaired
        return ValidatorDecision(
            candidate_id=candidate.candidate_id,
            terminal_state=TerminalState.tool_error,
            reason="Reasoner returned malformed JSON after one repair attempt.",
        )

    def _review(self, candidate: CandidateFinding, payload: dict[str, Any]) -> ReviewerDecision | ValidatorDecision:
        prompt = _build_reviewer_prompt(payload)
        reviewer, raw_response, validation_error = _try_generate_reviewer(self.llm, prompt)
        if reviewer is not None:
            return reviewer
        repair_prompt = _build_reviewer_repair_prompt(candidate, raw_response, validation_error)
        repaired, _repair_raw, _repair_error = _try_generate_reviewer(self.llm, repair_prompt)
        if repaired is not None:
            return repaired
        return ValidatorDecision(
            candidate_id=candidate.candidate_id,
            terminal_state=TerminalState.tool_error,
            reason="Reviewer returned malformed JSON after one repair attempt.",
        )


def run_from_args(args: argparse.Namespace) -> int:
    result = AgenticV2Orchestrator().run(
        args.repository,
        args.cwes,
        auto_approve=args.auto_approve,
        auto_review_policy=args.auto_review_policy,
    )
    return 0 if result.approved else 2


def _normalize_candidates(findings: list[Any], active_cwes: list[str], max_candidates: int) -> list[CandidateFinding]:
    selected = [
        finding
        for finding in sorted(findings, key=lambda item: (item.relative_file, item.line_start, item.finding_id))
        if finding.normalized_cwe in active_cwes
    ]
    candidates = []
    for finding in selected[:max_candidates]:
        candidates.append(
            CandidateFinding(
                candidate_id=finding.finding_id,
                relative_file=finding.relative_file,
                line_start=finding.line_start,
                line_end=finding.line_end,
                proposed_cwe=finding.normalized_cwe,
                summary=finding.rule_id,
                detector_input_ref=finding.finding_id,
            )
        )
    return candidates


def collect_evidence(root: Path, candidate: CandidateFinding, follow_up: FollowUpAction = FollowUpAction.none) -> dict[str, Any]:
    context = extract_candidate_context(root, candidate.relative_file, candidate.line_start)
    if follow_up is FollowUpAction.more_context:
        context["additional_context"] = extract_candidate_context(root, candidate.relative_file, candidate.line_start, radius=25)["source"]
    elif follow_up is FollowUpAction.assignment_history:
        context["assignment_history"] = assignment_history(root, candidate.relative_file)
    return context


def extract_candidate_context(root: Path, relative_file: str, line: int, radius: int = 10) -> dict[str, Any]:
    path = _resolve_inside(root, root / relative_file)
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    imports = _import_lines(text)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {"relative_file": relative_file, "imports": imports, "source": _window(lines, line, radius=radius)}
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= line <= end:
                best = (node.lineno, end)
                break
    if best:
        start, end = best
        source = "\n".join(lines[start - 1 : end])
    else:
        source = _window(lines, line, radius=radius)
    return {"relative_file": relative_file, "imports": imports, "source": source}


def assignment_history(root: Path, relative_file: str) -> list[str]:
    path = _resolve_inside(root, root / relative_file)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    rows = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = []
            for target in node.targets:
                if isinstance(target, ast.Name):
                    targets.append(target.id)
            if targets:
                rows.append(f"line {node.lineno}: {', '.join(sorted(targets))}")
    return rows


def _import_lines(text: str) -> list[str]:
    imports = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            imports.append(line)
    return imports


def _window(lines: list[str], line: int, radius: int = 10) -> str:
    start = max(line - radius - 1, 0)
    end = min(line + radius, len(lines))
    return "\n".join(lines[start:end])


def _reasoner_payload(candidate: CandidateFinding, context: dict[str, Any], active_cwes: list[str], pass_number: int = 1) -> dict[str, Any]:
    return {
        "candidate": {
            "candidate_id": candidate.candidate_id,
            "file": candidate.relative_file,
            "line": candidate.line_start,
            "rule_id": candidate.summary,
            "candidate_cwe": candidate.proposed_cwe,
            "sink_expression": "",
            "raw_result_reference": candidate.detector_input_ref,
        },
        "context": context,
        "semgrep_evidence": {"rule_id": candidate.summary, "line": candidate.line_start},
        "active_cwe_scope": active_cwes,
        "pass_number": pass_number,
    }


def _reviewer_payload(
    candidate: CandidateFinding,
    reasoner: ReasonerDecision,
    validator: ValidatorDecision,
    evidence: dict[str, Any],
    pass_number: int,
) -> dict[str, Any]:
    return {
        "candidate": {
            "candidate_id": candidate.candidate_id,
            "file": candidate.relative_file,
            "line": candidate.line_start,
            "candidate_cwe": candidate.proposed_cwe,
        },
        "reasoner_output": reasoner.model_dump(mode="json"),
        "validator_result": validator.model_dump(mode="json"),
        "collected_evidence": evidence,
        "pass_number": pass_number,
    }


def _build_reasoner_prompt(payload: dict[str, Any]) -> str:
    return (
        REASONER_SYSTEM_PROMPT
        + "\n"
        + _reasoner_output_contract(payload["candidate"]["candidate_id"], payload["candidate"]["candidate_cwe"])
        + "\nInput payload:\n"
        + json.dumps(payload, indent=2, sort_keys=True)
    )


def _build_reasoner_repair_prompt(candidate: CandidateFinding, raw_response: str, validation_error: str) -> str:
    return (
        REASONER_SYSTEM_PROMPT
        + "\nRepair the original response into valid ReasonerDecision JSON only.\n"
        + _reasoner_output_contract(candidate.candidate_id, candidate.proposed_cwe)
        + "\nValidation error:\n"
        + validation_error
        + "\nOriginal raw response:\n"
        + raw_response
    )


def _reasoner_output_contract(candidate_id: str, proposed_cwe: str) -> str:
    template = {
        "candidate_id": candidate_id,
        "proposed_cwe": proposed_cwe,
        "source_supported": False,
        "propagation_supported": False,
        "sink_supported": False,
        "sanitization_summary": "",
        "confidence": 0.0,
        "missing_evidence": [],
        "rationale": "",
    }
    return (
        "Return exactly one JSON object. Do not include Markdown fences or prose. "
        "Copy candidate_id and proposed_cwe unchanged from this template. "
        "Use booleans for supported fields, a number from 0.0 to 1.0 for confidence, "
        "and missing_evidence as list[str]. Use only supplied evidence; do not invent evidence. "
        "Required ReasonerDecision template:\n"
        + json.dumps(template, indent=2, sort_keys=True)
    )


def _build_reviewer_prompt(payload: dict[str, Any]) -> str:
    return (
        REVIEWER_SYSTEM_PROMPT
        + "\n"
        + _reviewer_output_contract(payload["candidate"]["candidate_id"])
        + "\nInput payload:\n"
        + json.dumps(payload, indent=2, sort_keys=True)
    )


def _build_reviewer_repair_prompt(candidate: CandidateFinding, raw_response: str, validation_error: str) -> str:
    return (
        REVIEWER_SYSTEM_PROMPT
        + "\nRepair the original response into valid ReviewerDecision JSON only.\n"
        + _reviewer_output_contract(candidate.candidate_id)
        + "\nValidation error:\n"
        + validation_error
        + "\nOriginal raw response:\n"
        + raw_response
    )


def _reviewer_output_contract(candidate_id: str) -> str:
    template = {
        "candidate_id": candidate_id,
        "decision": "human_review",
        "follow_up_action": "none",
        "rationale": "",
    }
    return (
        "Return exactly one JSON object. Do not include Markdown fences or prose. "
        "Copy candidate_id unchanged from this template. "
        "decision must be one of: accept, reject, needs_more_evidence, human_review. "
        "follow_up_action must be one of: more_context, assignment_history, none. "
        "Use only supplied evidence; do not invent evidence or force a verdict. "
        "Required ReviewerDecision template:\n"
        + json.dumps(template, indent=2, sort_keys=True)
    )


def _generate_reasoner(llm: LLMClient, prompt: str) -> ReasonerDecision:
    if hasattr(llm, "generate_raw"):
        result = llm.generate_raw(prompt)  # type: ignore[attr-defined]
        return ReasonerDecision.model_validate(parse_model_json(result.raw_text, ReasonerDecision).model_dump())
    result = llm.generate_structured(prompt, ReasonerDecision)
    return ReasonerDecision.model_validate(result.parsed.model_dump())


def _try_generate_reasoner(llm: LLMClient, prompt: str) -> tuple[ReasonerDecision | None, str, str]:
    if hasattr(llm, "generate_raw"):
        result = llm.generate_raw(prompt)  # type: ignore[attr-defined]
        try:
            return ReasonerDecision.model_validate(parse_model_json(result.raw_text, ReasonerDecision).model_dump()), result.raw_text, ""
        except SchemaParseError as exc:
            return None, result.raw_text, str(exc)
    try:
        result = llm.generate_structured(prompt, ReasonerDecision)
        return ReasonerDecision.model_validate(result.parsed.model_dump()), result.raw_text, ""
    except SchemaParseError as exc:
        return None, "", str(exc)


def _generate_reviewer(llm: LLMClient, prompt: str) -> ReviewerDecision:
    if hasattr(llm, "generate_raw"):
        result = llm.generate_raw(prompt)  # type: ignore[attr-defined]
        return ReviewerDecision.model_validate(parse_model_json(result.raw_text, ReviewerDecision).model_dump())
    result = llm.generate_structured(prompt, ReviewerDecision)
    return ReviewerDecision.model_validate(result.parsed.model_dump())


def _try_generate_reviewer(llm: LLMClient, prompt: str) -> tuple[ReviewerDecision | None, str, str]:
    if hasattr(llm, "generate_raw"):
        result = llm.generate_raw(prompt)  # type: ignore[attr-defined]
        try:
            return ReviewerDecision.model_validate(parse_model_json(result.raw_text, ReviewerDecision).model_dump()), result.raw_text, ""
        except SchemaParseError as exc:
            return None, result.raw_text, str(exc)
    try:
        result = llm.generate_structured(prompt, ReviewerDecision)
        return ReviewerDecision.model_validate(result.parsed.model_dump()), result.raw_text, ""
    except SchemaParseError as exc:
        return None, "", str(exc)


def validate_reasoner_decision(
    candidate: CandidateFinding,
    reasoner: ReasonerDecision,
    evidence: dict[str, Any],
) -> ValidatorDecision:
    if candidate.proposed_cwe not in {"CWE-078", "CWE-089"}:
        return ValidatorDecision(
            candidate_id=candidate.candidate_id,
            terminal_state=TerminalState.out_of_scope,
            reason="Candidate CWE is outside the active Plan B v2 scope.",
        )
    verdict = Verdict.tp if reasoner.source_supported and reasoner.propagation_supported and reasoner.sink_supported else Verdict.uncertain
    file_finding = FileFinding(
        line_start=candidate.line_start,
        line_end=candidate.line_end,
        verdict=verdict,
        confidence=reasoner.confidence,
        normalized_cwe=candidate.proposed_cwe,
        reasoning_summary=reasoner.rationale or "agentic v2 reasoner decision",
        source_evidence="source evidence" if reasoner.source_supported else "",
        sink_evidence=evidence.get("source", ""),
        data_flow_evidence="source reaches sink" if reasoner.propagation_supported else "",
        sanitization_evidence=reasoner.sanitization_summary,
    )
    checked = validate_plan_b_file_finding(file_finding, evidence.get("source", ""))
    passed = checked.verdict == Verdict.tp
    return ValidatorDecision(
        candidate_id=candidate.candidate_id,
        terminal_state=TerminalState.confirmed if passed else TerminalState.rejected,
        reason="deterministic validation passed" if passed else checked.reasoning_summary,
        confidence=checked.confidence,
    )


def terminal_from_review(
    candidate: CandidateFinding,
    validator: ValidatorDecision,
    reviewer: ReviewerDecision,
) -> ValidatorDecision:
    if validator.terminal_state is TerminalState.out_of_scope:
        return validator
    if validator.terminal_state is TerminalState.confirmed and reviewer.decision is ReviewerVerdict.accept:
        return ValidatorDecision(
            candidate_id=candidate.candidate_id,
            terminal_state=TerminalState.confirmed,
            reason="reviewer accepted and validator passed",
            confidence=validator.confidence,
        )
    if reviewer.decision is ReviewerVerdict.reject:
        if validator.terminal_state is TerminalState.confirmed and not _reviewer_reject_has_contradictory_evidence(reviewer.rationale):
            return ValidatorDecision(
                candidate_id=candidate.candidate_id,
                terminal_state=TerminalState.confirmed,
                reason="reviewer rejection did not provide contradictory safety evidence; deterministic validation remains confirmed",
                confidence=validator.confidence,
            )
        return ValidatorDecision(
            candidate_id=candidate.candidate_id,
            terminal_state=TerminalState.rejected,
            reason=reviewer.rationale,
            confidence=validator.confidence if validator.terminal_state is TerminalState.confirmed else reviewer_confidence_floor(validator),
        )
    if reviewer.decision is ReviewerVerdict.human_review:
        return ValidatorDecision(candidate_id=candidate.candidate_id, terminal_state=TerminalState.human_review_required, reason=reviewer.rationale)
    if reviewer.decision is ReviewerVerdict.needs_more_evidence:
        return ValidatorDecision(candidate_id=candidate.candidate_id, terminal_state=TerminalState.human_review_required, reason=reviewer.rationale)
    return ValidatorDecision(candidate_id=candidate.candidate_id, terminal_state=TerminalState.rejected, reason=validator.reason)


def reviewer_confidence_floor(validator: ValidatorDecision) -> float:
    return validator.confidence if validator.confidence else 0.0


def _reviewer_reject_has_contradictory_evidence(rationale: str) -> bool:
    text = rationale.lower()
    contradiction_terms = (
        "parameterized",
        "bound parameter",
        "placeholder",
        "prepared statement",
        "sanitized",
        "escaped",
        "validated",
        "constant overwrite",
        "overwritten",
        "no user-controlled",
        "not user-controlled",
        "no source",
        "no propagation",
        "no flow",
        "no sink",
        "safe",
        "allowlist",
        "shell=false",
    )
    vulnerability_terms = ("without sanitization", "no sanitization", "directly executes", "sql injection", "vulnerab")
    return any(term in text for term in contradiction_terms) and not any(term in text for term in vulnerability_terms)


def _prompt_for_approval(route_payload: dict[str, Any], input_func) -> bool:
    print(f"Repository path: {route_payload['repository_path']}")
    print(f"Python file count: {route_payload['python_file_count']}")
    print(f"Framework indicators: {route_payload['framework_indicators']}")
    print(f"Active CWEs: {route_payload['active_cwes']}")
    print(f"Skipped CWEs: {route_payload['skipped_cwes']}")
    print("Candidate budget: 20")
    print("Safety policy: read_only=True execute_target_code=False modify_target_files=False allow_cloud_models=False")
    return input_func("Approve scan plan? [y/n] ").strip().lower() == "y"


def _prompt_for_human_review(candidate: CandidateFinding, decision: ValidatorDecision, input_func) -> str:
    print(f"Finding: {candidate.candidate_id} {candidate.relative_file}:{candidate.line_start}")
    print(f"CWE: {candidate.proposed_cwe}")
    print(f"Known evidence: {_known_evidence(candidate, decision)}")
    print(f"Missing evidence: {_missing_evidence(decision)}")
    choices = {"a": "accept", "r": "reject", "u": "keep", "s": "stop"}
    while True:
        response = input_func("Review finding? [A=accept/R=reject/U=keep human review/S=stop] ").strip().lower()
        if response in choices:
            return choices[response]


def _known_evidence(candidate: CandidateFinding, decision: ValidatorDecision) -> list[str]:
    evidence = [candidate.summary]
    if decision.reason:
        evidence.append(decision.reason)
    return evidence


def _missing_evidence(decision: ValidatorDecision) -> list[str]:
    if decision.terminal_state is TerminalState.human_review_required:
        return [decision.reason or "additional evidence needed"]
    return []


def _route_payload(route: RouteDecision, active_cwes: list[str]) -> dict[str, Any]:
    skipped = dict(route.skipped_cwes)
    for cwe in route.active_cwes:
        if cwe not in active_cwes:
            skipped[cwe] = "not requested"
    return {
        "repository_path": route.inventory.root_path,
        "python_file_count": len(route.inventory.python_files),
        "framework_indicators": route.framework_indicators,
        "active_cwes": active_cwes,
        "skipped_cwes": skipped,
        "candidate_budget": 20,
        "safety_policy": {
            "read_only": True,
            "execute_target_code": False,
            "modify_target_files": False,
            "allow_cloud_models": False,
        },
        "planning_steps": [step.model_dump(mode="json") for step in route.planning_steps if step.target in active_cwes],
    }


def _safe_repository_root(repository: str | Path) -> Path:
    raw = Path(repository)
    if any(part == ".." for part in raw.parts):
        raise ValueError("repository path traversal is not allowed")
    root = raw.resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("repository must be an existing local directory")
    return root


def _resolve_inside(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("path escapes repository root")
    return resolved


def _model_dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")
