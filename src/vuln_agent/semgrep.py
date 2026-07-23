"""Robust Semgrep adapter with structured errors and stable finding IDs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import re
from pathlib import Path
from typing import Callable

from .config import Settings
from .exceptions import ToolError
from .schemas import SemgrepFinding, Severity, ToolMetadata
from .utils import infer_cwe_from_rule, normalize_cwe, normalize_cwe_list, stable_finding_id


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
        status = self.version_status()
        return status.get("version")

    def version_status(self) -> dict[str, str | None]:
        executable = self.executable_path()
        if executable is None:
            return {"status": "unavailable", "version": None, "error": "Semgrep binary not found"}
        try:
            result = self.runner(
                [executable, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=self.settings.semgrep_version_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "version": None, "error": f"Semgrep version check timed out after {self.settings.semgrep_version_timeout_seconds}s"}
        except OSError as exc:
            return {"status": "unavailable", "version": None, "error": f"Semgrep failed to start: {exc}"}
        version = (result.stdout or result.stderr).strip() or None
        if result.returncode != 0:
            return {"status": "unavailable", "version": version, "error": f"Semgrep version exited with {result.returncode}"}
        return {"status": "ok" if version else "unavailable", "version": version, "error": None if version else "Semgrep version output was empty"}

    def scan(self, target_path: str | Path, config: str | None = None) -> tuple[list[SemgrepFinding], ToolMetadata]:
        executable = self.executable_path()
        if executable is None:
            raise ToolError(f"Semgrep binary not found: {self.settings.semgrep_binary}")
        resolved_config = self._resolve_config(config or self.settings.semgrep_config)

        command = [
            executable,
            "--json",
            "--metrics",
            "off",
            "--disable-version-check",
            "--config",
            resolved_config,
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
        stderr_full = strip_console_noise(result.stderr or "")
        stderr = stderr_full.strip()[:2000]
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
            config=resolved_config,
            duration_ms=duration_ms,
            error=None,
            warnings=[stderr] if stderr else [],
            stderr_excerpt=stderr,
        )
        return findings, metadata

    def _resolve_config(self, config: str) -> str:
        config_path = Path(config)
        if config_path.is_absolute() or _looks_like_registry_config(config):
            return config
        candidates = [
            Path.cwd() / config_path,
            Path(__file__).resolve().parents[2] / config_path,
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return config

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
            normalized_cwe, _source = infer_cwe_from_rule(rule_id, normalize_cwe(raw_cwes))
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
                normalized_cwe=normalized_cwe,
                severity=severity,
                snippet=snippet,
            )
            deduped[finding_id] = finding
        return list(deduped.values())


def strip_console_noise(text: str) -> str:
    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    cleaned = ansi.sub("", text.replace("\ufffd", ""))
    return "".join(ch for ch in cleaned if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def _looks_like_registry_config(config: str) -> bool:
    return config.startswith(("p/", "r/", "https://", "http://"))
