"""Bounded scanner/analyzer/reporter orchestration."""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings
from .exceptions import LLMError, SchemaParseError, SecurityPolicyError, ToolError
from .llm import LLMClient, LLMResult, OllamaClient, RawModel
from .prompts import build_analyzer_prompt, build_file_analysis_prompt
from .reporting import calculate_priority, classify_status, write_jsonl, write_manifest, write_markdown
from .schemas import (
    AgentAnalysis,
    CweSource,
    FileAnalysis,
    FileFinding,
    FinalFinding,
    FindingStatus,
    ModelMetadata,
    SemgrepFinding,
    Severity,
    ToolMetadata,
    Verdict,
)
from .semgrep import SemgrepAdapter
from .source import fetch_context, resolve_scan_path, select_source_files
from .utils import infer_cwe_from_rule, normalize_cwe, parse_model_json, stable_finding_id


SCAN_MODES = ("semgrep", "llm", "semgrep_gated", "hybrid")


def current_git_metadata(root: Path) -> dict[str, object]:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=5).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, timeout=5).stdout.strip())
        return {"commit": commit or None, "dirty": dirty}
    except Exception:
        return {"commit": None, "dirty": None}


def portable_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return path.name


def portable_id(text: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in text.replace("\\", "/")).strip("-") or "target"


def user_classification(status: FindingStatus, verdict: Verdict, confidence: float) -> str:
    if status == FindingStatus.error or verdict == Verdict.error:
        return "ERROR"
    if status == FindingStatus.rejected:
        return "REJECTED"
    if status == FindingStatus.needs_review and verdict == Verdict.tp:
        return "LIKELY_VULNERABLE"
    if verdict == Verdict.uncertain or status == FindingStatus.needs_review:
        return "UNCERTAIN"
    if confidence >= 0.8:
        return "VULNERABLE"
    return "LIKELY_VULNERABLE"


class VulnerabilityOrchestrator:
    def __init__(self, settings: Settings, semgrep: SemgrepAdapter | None = None, llm: LLMClient | None = None) -> None:
        self.settings = settings
        self.semgrep = semgrep or SemgrepAdapter(settings)
        self.llm = llm or OllamaClient(settings)

    def scan(
        self,
        target: str | Path,
        output_dir: Path | None = None,
        offline: bool = False,
        mode: str = "hybrid",
        save_raw: bool = False,
    ) -> tuple[list[FinalFinding], Path]:
        if mode not in SCAN_MODES:
            raise ValueError(f"Unsupported scan mode: {mode}")
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        target_path = resolve_scan_path(target, self.settings)
        selection = select_source_files(target_path, self.settings)
        out_dir = output_dir or self.settings.report_dir / run_id
        raw_dir = out_dir / "raw" if save_raw else None
        manifest_path = out_dir / "manifest.json"
        manifest: dict[str, Any] = {
            "run_id": run_id,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "python": sys.version,
            "platform": platform.platform(),
            "scan_mode": mode,
            "raw_output_enabled": save_raw,
            "configuration": self.settings.model_dump(mode="json"),
            "git": current_git_metadata(Path.cwd()),
            "target_path": portable_path(target_path, self.settings.allowed_scan_root),
            "source_selection": selection.__dict__,
            "raw_paths": [],
            "failures": [],
        }
        write_manifest(manifest, manifest_path)

        if offline:
            candidates, tool_metadata = self._offline_findings(target_path)
            grouped = self._group_findings(run_id, candidates, tool_metadata)
        else:
            candidates, grouped, manifest = self._live_scan(run_id, selection.files, mode, save_raw, raw_dir, manifest)

        write_jsonl(candidates, out_dir / "raw_findings.jsonl")
        write_jsonl(grouped, out_dir / "scan_report.jsonl")
        write_markdown(grouped, out_dir / "scan_report.md", manifest["target_path"], mode=mode, underlying_count=len(candidates))
        manifest["end_time"] = datetime.now(timezone.utc).isoformat()
        manifest["finding_count"] = len(grouped)
        manifest["underlying_match_count"] = len(candidates)
        if save_raw and raw_dir:
            manifest["missing_raw_files"] = [path for path in manifest["raw_paths"] if not (out_dir / path).exists()]
        write_manifest(manifest, manifest_path)
        return grouped, out_dir

    def _live_scan(
        self,
        run_id: str,
        files: list[Path],
        mode: str,
        save_raw: bool,
        raw_dir: Path | None,
        manifest: dict[str, Any],
    ) -> tuple[list[FinalFinding], list[FinalFinding], dict[str, Any]]:
        semgrep_by_file: dict[Path, list[SemgrepFinding]] = {}
        candidates: list[FinalFinding] = []
        tool_metadata = ToolMetadata(name="semgrep", config=self.settings.semgrep_config)
        if mode in {"semgrep", "semgrep_gated", "hybrid"}:
            for file_path in files:
                try:
                    findings, metadata, raw_paths = self._scan_semgrep(file_path, raw_dir)
                    tool_metadata = metadata
                    semgrep_by_file[file_path] = findings
                    manifest["raw_paths"].extend(raw_paths)
                    if mode in {"semgrep", "hybrid"}:
                        candidates.extend(self._semgrep_findings(run_id, findings, metadata, review_recommended=mode == "hybrid"))
                except ToolError as exc:
                    error = self._detector_error(run_id, file_path, "semgrep", str(exc), tool_metadata)
                    candidates.append(error)
                    manifest["failures"].append({"detector": "semgrep", "file": error.relative_file, "error": str(exc)})
        if mode == "semgrep":
            return candidates, self._group_findings(run_id, candidates, tool_metadata), manifest

        for file_path in files:
            semgrep_findings = semgrep_by_file.get(file_path, [])
            if mode == "semgrep_gated" and not semgrep_findings:
                continue
            if mode == "semgrep_gated":
                for index, finding in enumerate(semgrep_findings, 1):
                    candidate, raw_path = self._triage_candidate(run_id, file_path, finding, tool_metadata, save_raw, raw_dir, index)
                    if raw_path:
                        manifest["raw_paths"].append(raw_path)
                    candidates.append(candidate)
                continue
            if mode == "llm":
                semgrep_findings = []
            file_candidates, raw_path = self._analyze_full_file(run_id, file_path, tool_metadata, save_raw, raw_dir)
            if raw_path:
                manifest["raw_paths"].append(raw_path)
            candidates.extend(file_candidates)
        return candidates, self._group_findings(run_id, candidates, tool_metadata), manifest

    def _scan_semgrep(self, file_path: Path, raw_dir: Path | None) -> tuple[list[SemgrepFinding], ToolMetadata, list[str]]:
        if not isinstance(self.semgrep, SemgrepAdapter):
            findings, metadata = self.semgrep.scan(file_path)  # type: ignore[attr-defined]
            findings = self._normalize_semgrep_findings(file_path, findings)
            raw_paths: list[str] = []
            if raw_dir is not None:
                semgrep_dir = raw_dir / "semgrep"
                semgrep_dir.mkdir(parents=True, exist_ok=True)
                name = portable_id(portable_path(file_path, self.settings.allowed_scan_root))
                path = semgrep_dir / f"{name}.json"
                path.write_text(json.dumps({"results": [finding.model_dump() for finding in findings]}), encoding="utf-8")
                raw_paths.append(str(path.relative_to(raw_dir.parent)).replace("\\", "/"))
            return findings, metadata, raw_paths
        captured: dict[str, str] = {"stdout": "", "stderr": ""}

        def runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            result = subprocess.run(command, **kwargs)
            captured["stdout"] = result.stdout or ""
            captured["stderr"] = result.stderr or ""
            return result

        adapter = SemgrepAdapter(self.settings, runner=runner)
        findings, metadata = adapter.scan(file_path)
        findings = self._normalize_semgrep_findings(file_path, findings)
        raw_paths: list[str] = []
        if raw_dir is not None:
            semgrep_dir = raw_dir / "semgrep"
            semgrep_dir.mkdir(parents=True, exist_ok=True)
            name = portable_id(portable_path(file_path, self.settings.allowed_scan_root))
            stdout_path = semgrep_dir / f"{name}.json"
            stderr_path = semgrep_dir / f"{name}.stderr.txt"
            stdout_path.write_text(captured["stdout"], encoding="utf-8")
            stderr_path.write_text(captured["stderr"], encoding="utf-8")
            raw_paths.extend([str(stdout_path.relative_to(raw_dir.parent)).replace("\\", "/"), str(stderr_path.relative_to(raw_dir.parent)).replace("\\", "/")])
        return findings, metadata, raw_paths

    def _normalize_semgrep_findings(self, file_path: Path, findings: list[SemgrepFinding]) -> list[SemgrepFinding]:
        normalized = []
        selected_relative = portable_path(file_path, self.settings.allowed_scan_root)
        root = self.settings.allowed_scan_root.resolve()
        for finding in findings:
            relative = self._normalize_semgrep_path(finding.relative_file, root, selected_relative)
            updated = finding.model_copy(update={"relative_file": relative})
            updated.finding_id = stable_finding_id(relative, updated.line_start, updated.column_start, updated.rule_id, updated.snippet)
            normalized.append(updated)
        return normalized

    def _normalize_semgrep_path(self, reported_path: str, root: Path, selected_relative: str) -> str:
        path_text = reported_path.replace("\\", "/")
        absolute_like = Path(reported_path).is_absolute() or path_text.startswith("/") or re.match(r"^[A-Za-z]:/", path_text) is not None
        if path_text and not absolute_like and not path_text.startswith("../") and "/.." not in path_text:
            return path_text
        try:
            return str(Path(reported_path).resolve().relative_to(root)).replace("\\", "/")
        except (OSError, ValueError):
            return selected_relative

    def _semgrep_findings(self, run_id: str, findings: list[SemgrepFinding], metadata: ToolMetadata, review_recommended: bool = False) -> list[FinalFinding]:
        records = []
        for finding in findings:
            analysis = AgentAnalysis(
                verdict=Verdict.tp,
                confidence=0.75 if review_recommended else 1.0,
                normalized_cwe=finding.normalized_cwe,
                reasoning_summary="Semgrep reported this issue. Human review is recommended for detector-only findings." if review_recommended else "Semgrep reported this issue. No LLM validation was requested in semgrep mode.",
                sink_evidence=finding.snippet,
                needs_more_context=review_recommended,
            )
            records.append(self._final_from_analysis(run_id, finding, analysis, metadata, ModelMetadata(model="none", provider="none"), "semgrep"))
        return records

    def _triage_candidate(
        self,
        run_id: str,
        file_path: Path,
        finding: SemgrepFinding,
        metadata: ToolMetadata,
        save_raw: bool,
        raw_dir: Path | None,
        index: int,
    ) -> tuple[FinalFinding, str | None]:
        started = time.perf_counter()
        raw_path = None
        try:
            context = fetch_context(file_path, finding.line_start, self.settings)
            prompt = build_analyzer_prompt(finding, context)
            result = self._generate_raw(prompt.text, AgentAnalysis)
            if save_raw and raw_dir:
                raw_path = self._write_llm_raw(raw_dir, file_path, f"candidate-{index}", result.raw_text)
            if isinstance(result.parsed, RawModel):
                parsed = parse_model_json(result.raw_text, AgentAnalysis)
                result = LLMResult(parsed=parsed, raw_text=result.raw_text, metadata=result.metadata, latency_ms=result.latency_ms)
            analysis = AgentAnalysis.model_validate(result.parsed.model_dump())
            model_metadata = result.metadata.model_copy(update={"prompt_name": prompt.name, "prompt_version": prompt.version, "prompt_checksum": prompt.checksum})
        except (SecurityPolicyError, LLMError, SchemaParseError, ToolError) as exc:
            analysis = AgentAnalysis(verdict=Verdict.error, confidence=0.0, normalized_cwe=finding.normalized_cwe, reasoning_summary=f"Analysis failed: {exc}")
            model_metadata = ModelMetadata(model=self.settings.ollama_model, endpoint=self.settings.ollama_base_url)
        record = self._final_from_analysis(run_id, finding, analysis, metadata, model_metadata, "semgrep_gated")
        record.duration_ms = int((time.perf_counter() - started) * 1000)
        return record, raw_path

    def _analyze_full_file(
        self,
        run_id: str,
        file_path: Path,
        tool_metadata: ToolMetadata,
        save_raw: bool,
        raw_dir: Path | None,
    ) -> tuple[list[FinalFinding], str | None]:
        relative = portable_path(file_path, self.settings.allowed_scan_root)
        code = file_path.read_text(encoding="utf-8", errors="replace")
        prompt = build_file_analysis_prompt(relative, code)
        started = time.perf_counter()
        raw_path = None
        try:
            result = self._generate_raw(prompt.text, FileAnalysis)
            if save_raw and raw_dir:
                raw_path = self._write_llm_raw(raw_dir, file_path, "full-file", result.raw_text)
            if isinstance(result.parsed, RawModel):
                parsed = parse_model_json(result.raw_text, FileAnalysis)
                result = LLMResult(parsed=parsed, raw_text=result.raw_text, metadata=result.metadata, latency_ms=result.latency_ms)
            analysis = FileAnalysis.model_validate(result.parsed.model_dump())
            records = []
            for item in analysis.findings:
                finding = self._finding_from_file_item(relative, item)
                model_metadata = result.metadata.model_copy(update={"prompt_name": prompt.name, "prompt_version": prompt.version, "prompt_checksum": prompt.checksum})
                record = self._final_from_file_finding(run_id, finding, item, tool_metadata, model_metadata, "llm_full_file")
                record.duration_ms = int((time.perf_counter() - started) * 1000)
                records.append(record)
            return records, raw_path
        except (LLMError, SchemaParseError, ValueError) as exc:
            error_finding = SemgrepFinding(
                finding_id=stable_finding_id(relative, 1, 0, "llm.full-file.error", str(exc)),
                relative_file=relative,
                line_start=1,
                line_end=1,
                rule_id="llm.full-file.error",
                normalized_cwe="NONE",
                severity=Severity.unknown,
                snippet="",
            )
            item = FileFinding(line_start=1, line_end=1, verdict=Verdict.error, confidence=0.0, normalized_cwe="NONE", reasoning_summary=f"Full-file analysis failed: {exc}")
            record = self._final_from_file_finding(run_id, error_finding, item, tool_metadata, ModelMetadata(model=self.settings.ollama_model, endpoint=self.settings.ollama_base_url), "llm_full_file")
            record.duration_ms = int((time.perf_counter() - started) * 1000)
            return [record], raw_path

    def _generate_raw(self, prompt: str, schema: type[Any]) -> Any:
        if hasattr(self.llm, "generate_raw"):
            return self.llm.generate_raw(prompt)  # type: ignore[attr-defined]
        return self.llm.generate_structured(prompt, schema)

    def _write_llm_raw(self, raw_dir: Path, file_path: Path, suffix: str, text: str) -> str:
        llm_dir = raw_dir / "llm"
        llm_dir.mkdir(parents=True, exist_ok=True)
        path = llm_dir / f"{portable_id(portable_path(file_path, self.settings.allowed_scan_root))}-{suffix}.txt"
        path.write_text(text, encoding="utf-8")
        return str(path.relative_to(raw_dir.parent)).replace("\\", "/")

    def _finding_from_file_item(self, relative: str, item: FileFinding) -> SemgrepFinding:
        if item.line_end < item.line_start:
            raise ValueError("line_end must be >= line_start")
        rule = "llm.full-file"
        return SemgrepFinding(
            finding_id=stable_finding_id(relative, item.line_start, 0, rule, item.sink_evidence or item.reasoning_summary),
            relative_file=relative,
            line_start=item.line_start,
            line_end=item.line_end,
            rule_id=rule,
            raw_semgrep_cwes=[],
            normalized_cwe=normalize_cwe(item.normalized_cwe),
            severity=Severity.medium,
            snippet=item.sink_evidence,
        )

    def _final_from_file_finding(self, run_id: str, finding: SemgrepFinding, item: FileFinding, tool_metadata: ToolMetadata, model_metadata: ModelMetadata, decision_source: str) -> FinalFinding:
        analysis = AgentAnalysis(
            verdict=item.verdict,
            confidence=item.confidence,
            normalized_cwe=item.normalized_cwe,
            reasoning_summary=item.reasoning_summary,
            remediation=item.remediation,
            source_evidence=item.source_evidence,
            sink_evidence=item.sink_evidence,
            data_flow_evidence=item.data_flow_evidence,
            sanitization_evidence=item.sanitization_evidence,
            needs_more_context=item.needs_more_context,
        )
        return self._final_from_analysis(run_id, finding, analysis, tool_metadata, model_metadata, decision_source)

    def _final_from_analysis(self, run_id: str, finding: SemgrepFinding, analysis: AgentAnalysis, tool_metadata: ToolMetadata, model_metadata: ModelMetadata, decision_source: str) -> FinalFinding:
        semgrep_cwe = normalize_cwe(finding.raw_semgrep_cwes)
        analyzer_cwe = normalize_cwe(analysis.normalized_cwe)
        inferred_cwe, inferred_source = infer_cwe_from_rule(finding.rule_id, semgrep_cwe)
        normalized = analyzer_cwe if analyzer_cwe != "NONE" else inferred_cwe
        cwe_source = CweSource.analyzer if analyzer_cwe != "NONE" else CweSource.rule_inference if inferred_source == "rule_inference" else CweSource.semgrep
        cwe_mismatch = semgrep_cwe != "NONE" and analyzer_cwe != "NONE" and semgrep_cwe != analyzer_cwe
        status = classify_status(analysis.verdict, analysis.confidence, self.settings.hybrid_accept_confidence)
        review_reason = ""
        if cwe_mismatch:
            status = FindingStatus.needs_review
            review_reason = "Analyzer CWE differs from Semgrep CWE."
        if analysis.needs_more_context:
            status = FindingStatus.needs_review
            review_reason = "Analyzer requested more context."
        classification = user_classification(status, analysis.verdict, analysis.confidence)
        detector = "llm" if decision_source in {"llm_full_file", "hybrid_full_file", "semgrep_gated"} else decision_source
        llm_cwe = analyzer_cwe if detector == "llm" else "NONE"
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
            model_confidence=analysis.confidence,
            user_classification=classification,
            source_evidence=analysis.source_evidence,
            sink_evidence=analysis.sink_evidence,
            data_flow_evidence=analysis.data_flow_evidence,
            sanitization_evidence=analysis.sanitization_evidence,
            reasoning_summary=f"[{decision_source}] {analysis.reasoning_summary}",
            remediation=analysis.remediation,
            needs_human_review=status == FindingStatus.needs_review,
            review_reason=review_reason,
            tool_metadata=tool_metadata,
            model_metadata=model_metadata,
            duration_ms=0,
            detector=detector,
            detectors=[detector],
            agreement_status="single_detector",
            semgrep_cwe=semgrep_cwe if detector == "semgrep" else "NONE",
            llm_cwe=llm_cwe,
            detector_errors=[analysis.reasoning_summary] if status == FindingStatus.error else [],
        )

    def _group_findings(self, run_id: str, records: list[FinalFinding], metadata: ToolMetadata) -> list[FinalFinding]:
        groups: dict[tuple[str, str, int, str, str], list[FinalFinding]] = {}
        for record in records:
            if record.status in {FindingStatus.rejected, FindingStatus.error}:
                key_status = record.status.value
            else:
                key_status = "active"
            sink = self._sink_signature(record)
            bucket = (record.relative_file, record.normalized_cwe, self._line_bucket(record), key_status, sink)
            groups.setdefault(bucket, []).append(record)
        grouped = []
        for key, items in sorted(groups.items()):
            primary = sorted(items, key=lambda item: (item.status.value, -item.confidence, item.line_start))[0].model_copy(deep=True)
            canonical = "|".join(map(str, key))
            primary.group_id = "group-" + uuid.uuid5(uuid.NAMESPACE_URL, canonical).hex[:16]
            primary.underlying_finding_ids = sorted(item.finding_id for item in items)
            primary.underlying_rule_ids = sorted({item.rule_id for item in items})
            primary.duplicate_count = max(0, len(items) - 1)
            primary.detectors = sorted({detector for item in items for detector in item.detectors})
            primary.detector = "+".join(primary.detectors)
            primary.semgrep_cwe = normalize_cwe([item.semgrep_cwe for item in items if item.semgrep_cwe != "NONE"])
            primary.llm_cwe = normalize_cwe([item.llm_cwe for item in items if item.llm_cwe != "NONE"])
            primary.detector_errors = [error for item in items for error in item.detector_errors]
            primary.agreement_status = self._agreement_status(items)
            if primary.agreement_status == "detector_disagreement":
                primary.status = FindingStatus.needs_review
                primary.analyzer_verdict = Verdict.uncertain
                primary.user_classification = "UNCERTAIN"
                primary.needs_human_review = True
                primary.review_reason = "Detector disagreement requires human review."
            primary.finding_id = primary.group_id
            primary.line_start = min(item.line_start for item in items)
            primary.line_end = max(item.line_end for item in items)
            grouped.append(primary)
        return grouped

    def _line_bucket(self, record: FinalFinding) -> int:
        return max(1, (record.line_start - 1) // 5)

    def _sink_signature(self, record: FinalFinding) -> str:
        evidence = (record.sink_evidence or record.source_evidence or record.reasoning_summary or record.rule_id).lower()
        return " ".join(evidence.replace('"', "'").split())[:120]

    def _agreement_status(self, items: list[FinalFinding]) -> str:
        detectors = {detector for item in items for detector in item.detectors}
        if any(item.status == FindingStatus.error for item in items):
            return "detector_error"
        if detectors == {"semgrep", "llm"}:
            statuses = {item.status for item in items}
            verdicts = {item.analyzer_verdict for item in items}
            if FindingStatus.rejected in statuses or Verdict.uncertain in verdicts:
                return "detector_disagreement"
            return "detectors_agree"
        if detectors == {"semgrep"}:
            return "semgrep_only"
        if detectors == {"llm"}:
            return "llm_only"
        return "single_detector"

    def _detector_error(self, run_id: str, file_path: Path, detector: str, error: str, metadata: ToolMetadata) -> FinalFinding:
        relative = portable_path(file_path, self.settings.allowed_scan_root)
        finding = SemgrepFinding(
            finding_id=stable_finding_id(relative, 1, 0, f"{detector}.error", error),
            relative_file=relative,
            line_start=1,
            line_end=1,
            rule_id=f"{detector}.error",
            normalized_cwe="NONE",
            severity=Severity.unknown,
            snippet="",
        )
        analysis = AgentAnalysis(verdict=Verdict.error, confidence=0.0, normalized_cwe="NONE", reasoning_summary=f"{detector} failed: {error}")
        return self._final_from_analysis(run_id, finding, analysis, metadata.model_copy(update={"error": error}), ModelMetadata(model="none", provider=detector), detector)

    def _offline_findings(self, target_path: Path) -> tuple[list[FinalFinding], ToolMetadata]:
        files = [target_path] if target_path.is_file() else list(target_path.rglob("*.py"))
        metadata = ToolMetadata(name="offline-semgrep-demo", version="0", config="offline")
        findings: list[FinalFinding] = []
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for index, line in enumerate(text, 1):
                lowered = line.lower()
                if "os.system" in lowered or "subprocess" in lowered:
                    relative = str(path.relative_to(target_path if target_path.is_dir() else target_path.parent)).replace("\\", "/")
                    semgrep_finding = SemgrepFinding(
                        finding_id=f"offline-{uuid.uuid5(uuid.NAMESPACE_URL, str(path) + str(index)).hex[:16]}",
                        relative_file=relative,
                        line_start=index,
                        line_end=index,
                        rule_id="offline.demo.command-injection",
                        raw_semgrep_cwes=["CWE-078"],
                        normalized_cwe="CWE-078",
                        severity=Severity.high,
                        snippet=line.strip(),
                    )
                    analysis = AgentAnalysis(verdict=Verdict.tp, confidence=0.75, normalized_cwe="CWE-078", reasoning_summary="Offline demo mode preserves pipeline shape without calling an LLM.", remediation="Review shell command construction.", sink_evidence=line.strip())
                    findings.append(self._final_from_analysis("offline", semgrep_finding, analysis, metadata, ModelMetadata(model="offline-demo", provider="static"), "offline"))
        return findings, metadata
