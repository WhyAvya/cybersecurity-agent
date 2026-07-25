from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from vuln_agent.config import Settings
from vuln_agent.exceptions import SchemaParseError, ToolError
from vuln_agent.llm import LLMClient, OllamaClient
from vuln_agent.semgrep import SemgrepAdapter
from vuln_agent.utils import parse_model_json

from .artifacts import AgenticArtifactManager
from .inventory import RouteDecision, inspect_repository
from .models import AgentEvent, CandidateFinding, ReasonerDecision, TerminalState, ValidatorDecision
from .prompts import REASONER_SYSTEM_PROMPT


@dataclass(frozen=True)
class AgenticRunResult:
    run_id: str
    run_dir: Path
    approved: bool
    candidates: list[CandidateFinding]
    decisions: list[ReasonerDecision | ValidatorDecision]


class AgenticV2Orchestrator:
    def __init__(
        self,
        settings: Settings | None = None,
        semgrep: SemgrepAdapter | None = None,
        llm: LLMClient | None = None,
        artifacts: AgenticArtifactManager | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self.semgrep = semgrep or SemgrepAdapter(self.settings)
        self.llm = llm or OllamaClient(self.settings)
        self.artifacts = artifacts or AgenticArtifactManager(self.settings.artifact_root / "agentic-runs")

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

        candidates = _normalize_candidates(findings, active_cwes, self.settings.max_agent_iterations * 0 + 20)
        if len([f for f in findings if f.normalized_cwe in active_cwes]) > len(candidates):
            self.artifacts.append_event(
                run_id,
                AgentEvent(
                    event_id="candidate-budget-truncated",
                    event_type="budget",
                    payload={"max_candidates": 20},
                ),
            )

        decisions: list[ReasonerDecision | ValidatorDecision] = []
        for candidate in candidates:
            context = extract_candidate_context(root, candidate.relative_file, candidate.line_start)
            payload = _reasoner_payload(candidate, context, active_cwes)
            self.artifacts.append_event(
                run_id,
                AgentEvent(event_id=f"reasoner-start-{candidate.candidate_id}", event_type="reasoner_start", payload=payload),
            )
            decisions.append(self._reason(candidate, payload))

        self.artifacts.write_json(run_id, "findings.json", {"candidates": [c.model_dump(mode="json") for c in candidates]})
        self.artifacts.write_json(run_id, "state.json", {"approved": True, "candidate_count": len(candidates)})
        self.artifacts.write_json(
            run_id,
            "final_report.json",
            {"decisions": [_model_dump(decision) for decision in decisions]},
        )
        return AgenticRunResult(run_id, run_dir, True, candidates, decisions)

    def _reason(self, candidate: CandidateFinding, payload: dict[str, Any]) -> ReasonerDecision | ValidatorDecision:
        prompt = _build_reasoner_prompt(payload)
        try:
            return _generate_reasoner(self.llm, prompt)
        except SchemaParseError:
            repair_prompt = f"{REASONER_SYSTEM_PROMPT}\nRepair this response into valid ReasonerDecision JSON only."
            try:
                return _generate_reasoner(self.llm, repair_prompt)
            except SchemaParseError:
                return ValidatorDecision(
                    candidate_id=candidate.candidate_id,
                    terminal_state=TerminalState.tool_error,
                    reason="Reasoner returned malformed JSON after one repair attempt.",
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


def extract_candidate_context(root: Path, relative_file: str, line: int) -> dict[str, Any]:
    path = _resolve_inside(root, root / relative_file)
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    imports = _import_lines(text)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {"relative_file": relative_file, "imports": imports, "source": _window(lines, line)}
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
        source = _window(lines, line)
    return {"relative_file": relative_file, "imports": imports, "source": source}


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


def _reasoner_payload(candidate: CandidateFinding, context: dict[str, Any], active_cwes: list[str]) -> dict[str, Any]:
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
    }


def _build_reasoner_prompt(payload: dict[str, Any]) -> str:
    return REASONER_SYSTEM_PROMPT + "\n" + json.dumps(payload, indent=2, sort_keys=True)


def _generate_reasoner(llm: LLMClient, prompt: str) -> ReasonerDecision:
    if hasattr(llm, "generate_raw"):
        result = llm.generate_raw(prompt)  # type: ignore[attr-defined]
        return ReasonerDecision.model_validate(parse_model_json(result.raw_text, ReasonerDecision).model_dump())
    result = llm.generate_structured(prompt, ReasonerDecision)
    return ReasonerDecision.model_validate(result.parsed.model_dump())


def _prompt_for_approval(route_payload: dict[str, Any], input_func) -> bool:
    print(f"Repository path: {route_payload['repository_path']}")
    print(f"Python file count: {route_payload['python_file_count']}")
    print(f"Framework indicators: {route_payload['framework_indicators']}")
    print(f"Active CWEs: {route_payload['active_cwes']}")
    print(f"Skipped CWEs: {route_payload['skipped_cwes']}")
    print("Candidate budget: 20")
    print("Safety policy: read_only=True execute_target_code=False modify_target_files=False allow_cloud_models=False")
    return input_func("Approve scan plan? [y/n] ").strip().lower() == "y"


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
