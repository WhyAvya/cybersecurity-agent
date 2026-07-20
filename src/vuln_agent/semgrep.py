"""Robust Semgrep adapter with structured errors and stable finding IDs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

from .config import Settings
from .exceptions import ToolError
from .schemas import SemgrepFinding, Severity, ToolMetadata
from .utils import normalize_cwe, normalize_cwe_list, stable_finding_id


CompletedProcessFactory = Callable[..., subprocess.CompletedProcess[str]]


class SemgrepAdapter:
    def __init__(self, settings: Settings, runner: CompletedProcessFactory | None = None) -> None:
        self.settings = settings
        self.runner = runner or subprocess.run

    def executable_path(self) -> str | None:
        found = shutil.which(self.settings.semgrep_binary)
        if found:
            return found
        scripts_candidate = Path(sys.executable).parent / self.settings.semgrep_binary
        if scripts_candidate.exists():
            return str(scripts_candidate)
        exe_candidate = scripts_candidate.with_suffix(".exe")
        if exe_candidate.exists():
            return str(exe_candidate)
        return None

    def version(self) -> str | None:
        executable = self.executable_path()
        if executable is None:
            return None
        try:
            result = self.runner(
                [executable, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=10,
            )
        except Exception:
            return None
        return (result.stdout or result.stderr).strip() or None

    def scan(self, target_path: str | Path, config: str | None = None) -> tuple[list[SemgrepFinding], ToolMetadata]:
        executable = self.executable_path()
        if executable is None:
            raise ToolError(f"Semgrep binary not found: {self.settings.semgrep_binary}")

        command = [
            executable,
            "--json",
            "--metrics",
            "off",
            "--disable-version-check",
            "--config",
            config or self.settings.semgrep_config,
            str(target_path),
        ]
        if self.settings.semgrep_no_git_ignore:
            command.insert(2, "--no-git-ignore")

        started = time.perf_counter()
        try:
            result = self.runner(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=self.settings.semgrep_timeout_seconds,
                env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"Semgrep timed out after {self.settings.semgrep_timeout_seconds}s") from exc
        except OSError as exc:
            raise ToolError(f"Semgrep failed to start: {exc}") from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        stderr = (result.stderr or "").strip()[:2000]
        stdout = result.stdout or ""
        if not stdout.strip():
            raise ToolError(f"Semgrep exited with {result.returncode} and no JSON output: {stderr}")

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ToolError(f"Semgrep exited with {result.returncode} and returned malformed JSON: {exc}: {stderr}") from exc

        if result.returncode not in (0, 1):
            raise ToolError(f"Semgrep exited with {result.returncode}: {stderr}")

        findings = self._parse_results(raw.get("results", []))
        metadata = ToolMetadata(
            name="semgrep",
            version=None,
            config=config or self.settings.semgrep_config,
            duration_ms=duration_ms,
            error=stderr or None,
        )
        return findings, metadata

    def _parse_results(self, results: list[dict]) -> list[SemgrepFinding]:
        deduped: dict[str, SemgrepFinding] = {}
        for record in results:
            extra = record.get("extra", {})
            metadata = extra.get("metadata", {})
            start = record.get("start", {})
            end = record.get("end", start)
            snippet = extra.get("lines", "")
            raw_cwes = normalize_cwe_list(metadata.get("cwe"))
            relative_file = str(record.get("path", "")).replace("\\", "/")
            rule_id = str(record.get("check_id", "UNKNOWN_RULE"))
            line = int(start.get("line", 1))
            column = start.get("col")
            finding_id = stable_finding_id(relative_file, line, column, rule_id, snippet)
            severity_text = str(extra.get("severity", "MEDIUM")).upper()
            severity = Severity.__members__.get(severity_text.lower(), Severity.medium)
            finding = SemgrepFinding(
                finding_id=finding_id,
                relative_file=relative_file,
                line_start=line,
                line_end=int(end.get("line", line)),
                column_start=column,
                column_end=end.get("col"),
                rule_id=rule_id,
                raw_semgrep_cwes=raw_cwes,
                normalized_cwe=normalize_cwe(raw_cwes),
                severity=severity,
                snippet=snippet,
            )
            deduped[finding_id] = finding
        return list(deduped.values())
