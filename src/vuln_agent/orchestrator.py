"""Bounded scanner/analyzer/reporter orchestration."""

from __future__ import annotations

import platform
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings
from .exceptions import LLMError, SchemaParseError, SecurityPolicyError, ToolError
from .llm import LLMClient, OllamaClient
from .prompts import build_analyzer_prompt
from .reporting import calculate_priority, classify_status, write_jsonl, write_manifest, write_markdown
from .schemas import (
    AgentAnalysis,
    CweSource,
    FinalFinding,
    FindingStatus,
    ModelMetadata,
    SemgrepFinding,
    Severity,
    ToolMetadata,
    Verdict,
)
from .semgrep import SemgrepAdapter
from .source import fetch_context, resolve_scan_path
from .utils import normalize_cwe


def current_git_metadata(root: Path) -> dict[str, object]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        )
        return {"commit": commit or None, "dirty": dirty}
    except Exception:
        return {"commit": None, "dirty": None}


class VulnerabilityOrchestrator:
    def __init__(
        self,
        settings: Settings,
        semgrep: SemgrepAdapter | None = None,
        llm: LLMClient | None = None,
    ) -> None:
        self.settings = settings
        self.semgrep = semgrep or SemgrepAdapter(settings)
        self.llm = llm or OllamaClient(settings)

    def scan(self, target: str | Path, output_dir: Path | None = None, offline: bool = False) -> tuple[list[FinalFinding], Path]:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        target_path = resolve_scan_path(target, self.settings)
        out_dir = output_dir or self.settings.report_dir / run_id
        manifest_path = out_dir / "manifest.json"
        manifest: dict[str, object] = {
            "run_id": run_id,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "python": sys.version,
            "platform": platform.platform(),
            "configuration": self.settings.model_dump(mode="json"),
            "git": current_git_metadata(Path.cwd()),
            "target_path": str(target_path),
        }
        write_manifest(manifest, manifest_path)

        findings: list[SemgrepFinding]
        tool_metadata: ToolMetadata
        if offline:
            findings, tool_metadata = self._offline_findings(target_path)
        else:
            findings, tool_metadata = self.semgrep.scan(target_path)

        final_findings = [self._process_finding(run_id, target_path, finding, tool_metadata, offline) for finding in findings]
        write_jsonl(final_findings, out_dir / "scan_report.jsonl")
        write_markdown(final_findings, out_dir / "scan_report.md", str(target_path))
        manifest["end_time"] = datetime.now(timezone.utc).isoformat()
        manifest["finding_count"] = len(final_findings)
        write_manifest(manifest, manifest_path)
        return final_findings, out_dir

    def _process_finding(
        self,
        run_id: str,
        target_path: Path,
        finding: SemgrepFinding,
        tool_metadata: ToolMetadata,
        offline: bool,
    ) -> FinalFinding:
        started = time.perf_counter()
        model_metadata = ModelMetadata(model=self.settings.ollama_model, endpoint=self.settings.ollama_base_url)
        try:
            source_file = target_path / finding.relative_file if target_path.is_dir() else target_path
            context = fetch_context(source_file, finding.line_start, self.settings)
            if offline:
                analysis = AgentAnalysis(
                    verdict=Verdict.tp,
                    confidence=0.75,
                    normalized_cwe=finding.normalized_cwe,
                    reasoning_summary="Offline demo mode preserves pipeline shape without calling an LLM.",
                    remediation="Review the flagged sink and apply input validation or parameterized APIs as appropriate.",
                    sink_evidence=finding.snippet,
                )
            else:
                prompt = build_analyzer_prompt(finding, context)
                result = self.llm.generate_structured(prompt.text, AgentAnalysis)
                analysis = AgentAnalysis.model_validate(result.parsed.model_dump())
                model_metadata = result.metadata.model_copy(
                    update={
                        "prompt_name": prompt.name,
                        "prompt_version": prompt.version,
                        "prompt_checksum": prompt.checksum,
                    }
                )
        except (SecurityPolicyError, LLMError, SchemaParseError, ToolError) as exc:
            analysis = AgentAnalysis(
                verdict=Verdict.error,
                confidence=0.0,
                normalized_cwe=finding.normalized_cwe,
                reasoning_summary=f"Analysis failed: {exc}",
                needs_more_context=False,
            )

        semgrep_cwe = normalize_cwe(finding.raw_semgrep_cwes)
        analyzer_cwe = normalize_cwe(analysis.normalized_cwe)
        normalized = analyzer_cwe if analyzer_cwe != "NONE" else semgrep_cwe
        cwe_source = CweSource.analyzer if analyzer_cwe != "NONE" else CweSource.semgrep
        cwe_mismatch = semgrep_cwe != "NONE" and analyzer_cwe != "NONE" and semgrep_cwe != analyzer_cwe
        status = classify_status(analysis.verdict, analysis.confidence, self.settings.hybrid_accept_confidence)
        review_reason = ""
        if cwe_mismatch:
            status = FindingStatus.needs_review
            review_reason = "Analyzer CWE differs from Semgrep CWE."
        if analysis.needs_more_context:
            status = FindingStatus.needs_review
            review_reason = "Analyzer requested more context."
        return FinalFinding(
            run_id=run_id,
            finding_id=finding.finding_id,
            relative_file=finding.relative_file,
            line_start=finding.line_start,
            line_end=finding.line_end,
            rule_id=finding.rule_id,
            raw_semgrep_cwes=finding.raw_semgrep_cwes,
            normalized_cwe=normalized,
            cwe_source=cwe_source,
            cwe_mismatch=cwe_mismatch,
            severity=finding.severity,
            priority=calculate_priority(status, finding.severity, analysis.confidence, self.settings.high_priority_confidence),
            status=status,
            analyzer_verdict=analysis.verdict,
            confidence=analysis.confidence,
            source_evidence=analysis.source_evidence,
            sink_evidence=analysis.sink_evidence,
            data_flow_evidence=analysis.data_flow_evidence,
            sanitization_evidence=analysis.sanitization_evidence,
            reasoning_summary=analysis.reasoning_summary,
            remediation=analysis.remediation,
            needs_human_review=status == FindingStatus.needs_review,
            review_reason=review_reason,
            tool_metadata=tool_metadata,
            model_metadata=model_metadata,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _offline_findings(self, target_path: Path) -> tuple[list[SemgrepFinding], ToolMetadata]:
        files = [target_path] if target_path.is_file() else list(target_path.rglob("*.py"))
        findings: list[SemgrepFinding] = []
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for index, line in enumerate(text, 1):
                lowered = line.lower()
                if "os.system" in lowered or "subprocess" in lowered:
                    findings.append(
                        SemgrepFinding(
                            finding_id=f"offline-{uuid.uuid5(uuid.NAMESPACE_URL, str(path) + str(index)).hex[:16]}",
                            relative_file=str(path.relative_to(target_path if target_path.is_dir() else target_path.parent)).replace("\\", "/"),
                            line_start=index,
                            line_end=index,
                            rule_id="offline.demo.command-injection",
                            raw_semgrep_cwes=["CWE-078"],
                            normalized_cwe="CWE-078",
                            severity=Severity.high,
                            snippet=line.strip(),
                        )
                    )
        return findings, ToolMetadata(name="offline-semgrep-demo", version="0", config="offline")
